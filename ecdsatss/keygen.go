package ecdsatss

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	cmts "github.com/KarpelesLab/tss-lib/v2/crypto/commitments"
	"github.com/KarpelesLab/tss-lib/v2/crypto/dlnproof"
	"github.com/KarpelesLab/tss-lib/v2/crypto/facproof"
	"github.com/KarpelesLab/tss-lib/v2/crypto/modproof"
	"github.com/KarpelesLab/tss-lib/v2/crypto/paillier"
	"github.com/KarpelesLab/tss-lib/v2/crypto/vss"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

var zero = big.NewInt(0)

// Keygen is an object used to track a key currently being generated
type Keygen struct {
	ctx           context.Context
	params        *tss.Parameters // contains curve, parties, etc
	KGCs          []cmts.HashCommitment
	vs            vss.Vs
	ssid          []byte // ssid for current round/values
	ssidNonce     *big.Int
	shares        vss.Shares
	deCommitPolyG cmts.HashDeCommitment
	data          *Key // key data currently being generated
	round         int  // current round

	ui        *big.Int // keep around for potential use (ECDSA does clear it though)
	r2pending int32    // atomic counter for dual-message round 2

	r2msg1From []*tss.PartyID
	r2msg1     []*keygenRound2msg1
	r2msg2From []*tss.PartyID
	r2msg2     []*keygenRound2msg2

	Done chan *Key
	Err  chan error

	Receiver tss.MessageReceiver
}

// NewKeygen creates a new Keygen instance and executes round 1 of the key generation protocol.
func NewKeygen(ctx context.Context, params *tss.Parameters, optionalPreParams ...LocalPreParams) (*Keygen, error) {
	partyCount := params.PartyCount()
	res := &Keygen{
		ctx:    ctx,
		params: params,
		KGCs:   make([]cmts.HashCommitment, partyCount),
		data:   NewKey(partyCount),
		round:  1,
		Done:   make(chan *Key, 1),
		Err:    make(chan error, 1),
	}
	if len(optionalPreParams) > 0 {
		res.data.LocalPreParams = optionalPreParams[0]
	}
	err := res.round1()
	if err != nil {
		return nil, err
	}

	return res, nil
}

// getSSID returns ssid from local params
func (kg *Keygen) getSSID(roundNum int) ([]byte, error) {
	ssidList := []*big.Int{kg.params.EC().Params().P, kg.params.EC().Params().N, kg.params.EC().Params().Gx, kg.params.EC().Params().Gy} // ec curve
	ssidList = append(ssidList, kg.params.Parties().IDs().Keys()...)
	ssidList = append(ssidList, big.NewInt(int64(roundNum))) // round number
	ssidList = append(ssidList, kg.ssidNonce)
	ssid := common.SHA512_256i(ssidList...).Bytes()

	return ssid, nil
}

func (kg *Keygen) round1() error {
	Pi := kg.params.PartyID()
	i := Pi.Index
	// 1. calculate "partial" key share ui
	ui := common.GetRandomPositiveInt(kg.params.PartialKeyRand(), kg.params.EC().Params().N)

	// 2. compute the vss shares
	ids := kg.params.Parties().IDs().Keys()
	vs, shares, err := vss.Create(kg.params.EC(), kg.params.Threshold(), ui, ids, kg.params.Rand())
	if err != nil {
		return err
	}
	kg.data.Ks = ids

	// security: the original u_i may be discarded
	ui = zero // clears the secret data from memory
	_ = ui    // silences a linter warning

	// make commitment -> (C, D)
	pGFlat, err := crypto.FlattenECPoints(vs)
	if err != nil {
		return err
	}
	cmt := cmts.NewHashCommitment(kg.params.Rand(), pGFlat...)

	// 4. generate Paillier public key E_i, private key and proof
	// 5-7. generate safe primes for ZKPs used later on
	// 9-11. compute ntilde, h1, h2 (uses safe primes)
	var preParams *LocalPreParams
	if kg.data.LocalPreParams.Validate() && !kg.data.LocalPreParams.ValidateWithProof() {
		return errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib")
	} else if kg.data.LocalPreParams.ValidateWithProof() {
		preParams = &kg.data.LocalPreParams
	} else {
		ctx, cancel := context.WithTimeout(kg.ctx, kg.params.SafePrimeGenTimeout())
		defer cancel()
		preParams, err = (&LocalPreGenerator{Context: ctx, Rand: kg.params.Rand(), Concurrency: kg.params.Concurrency()}).Generate()
		if err != nil {
			return errors.New("pre-params generation failed")
		}
	}
	kg.data.LocalPreParams = *preParams
	kg.data.NTildej[i] = preParams.NTildei
	kg.data.H1j[i], kg.data.H2j[i] = preParams.H1i, preParams.H2i

	// generate the dlnproofs for keygen
	h1i, h2i, alpha, beta, p, q, NTildei := preParams.H1i, preParams.H2i, preParams.Alpha, preParams.Beta, preParams.P, preParams.Q, preParams.NTildei
	dlnProof1 := dlnproof.NewDLNProof(h1i, h2i, alpha, p, q, NTildei, kg.params.Rand())
	dlnProof2 := dlnproof.NewDLNProof(h2i, h1i, beta, p, q, NTildei, kg.params.Rand())

	// for this P: SAVE
	// - shareID
	// and keep in temporary storage:
	// - VSS Vs
	// - our set of Shamir shares
	kg.ssidNonce = new(big.Int).SetUint64(0)
	kg.data.ShareID = ids[i]
	kg.vs = vs
	ssid, err := kg.getSSID(kg.round) // for round 1
	if err != nil {
		return errors.New("failed to generate ssid")
	}
	kg.ssid = ssid
	kg.shares = shares

	// for this P: SAVE de-commitments, paillier keys for round 2
	kg.data.PaillierSK = preParams.PaillierSK
	kg.data.PaillierPKs[i] = &preParams.PaillierSK.PublicKey
	kg.deCommitPolyG = cmt.D

	// send commitments, paillier pk + proof; round 1 message
	dlnProof1Bz, err := dlnProof1.Serialize()
	if err != nil {
		return err
	}
	dlnProof2Bz, err := dlnProof2.Serialize()
	if err != nil {
		return err
	}
	msg := &keygenRound1msg{
		Commitment: cmt.C.Bytes(),
		PaillierN:  preParams.PaillierSK.PublicKey.N.Bytes(),
		NTilde:     preParams.NTildei.Bytes(),
		H1:         preParams.H1i.Bytes(),
		H2:         preParams.H2i.Bytes(),
		Dlnproof_1: dlnProof1Bz,
		Dlnproof_2: dlnProof2Bz,
	}

	var otherIds []*tss.PartyID
	for n, p := range kg.params.Parties().IDs() {
		if n == i {
			// do not send to self
			continue
		}
		otherIds = append(otherIds, p)
		m := tss.JsonWrap("ecdsa:keygen:round1", msg, Pi, p)
		kg.params.Broker().Receive(m)
	}

	kg.Receiver = tss.NewJsonExpect[keygenRound1msg]("ecdsa:keygen:round1", otherIds, kg.round2)
	kg.params.Broker().Connect("ecdsa:keygen:round1", kg.Receiver)

	return nil
}

// round2 processes round 1 messages from other parties and executes round 2.
func (kg *Keygen) round2(otherIds []*tss.PartyID, r1msgs []*keygenRound1msg) {
	if kg.ctx.Err() != nil {
		kg.Err <- kg.ctx.Err()
		return
	}
	kg.round = 2

	Pi := kg.params.PartyID()
	i := Pi.Index
	ec := kg.params.EC()
	allParties := kg.params.Parties().IDs()

	// Build index mapping: otherIds position -> allParties index
	partyIdxMap := make([]int, len(otherIds))
	for k, oid := range otherIds {
		for n, pid := range allParties {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				partyIdxMap[k] = n
				break
			}
		}
	}

	// Verify DLN proofs concurrently
	dlnProof1Fail := make([]bool, len(otherIds))
	dlnProof2Fail := make([]bool, len(otherIds))
	wg := new(sync.WaitGroup)

	for k, r1msg := range r1msgs {
		jIdx := partyIdxMap[k]
		_ = jIdx

		paillierPK := &paillier.PublicKey{N: new(big.Int).SetBytes(r1msg.PaillierN)}
		if paillierPK.N.BitLen() < 2048 {
			kg.Err <- fmt.Errorf("party %s: paillier modulus bit length %d < 2048", otherIds[k], paillierPK.N.BitLen())
			return
		}

		NTildej := new(big.Int).SetBytes(r1msg.NTilde)
		if NTildej.BitLen() < 2048 {
			kg.Err <- fmt.Errorf("party %s: NTilde bit length %d < 2048", otherIds[k], NTildej.BitLen())
			return
		}

		H1j := new(big.Int).SetBytes(r1msg.H1)
		H2j := new(big.Int).SetBytes(r1msg.H2)
		if H1j.Cmp(H2j) == 0 {
			kg.Err <- fmt.Errorf("party %s: H1j == H2j", otherIds[k])
			return
		}

		wg.Add(2)
		kk := k
		go func() {
			defer wg.Done()
			dlnPf1, err := dlnproof.UnmarshalDLNProof(r1msgs[kk].Dlnproof_1)
			if err != nil || !dlnPf1.Verify(H1j, H2j, NTildej) {
				dlnProof1Fail[kk] = true
			}
		}()
		go func() {
			defer wg.Done()
			dlnPf2, err := dlnproof.UnmarshalDLNProof(r1msgs[kk].Dlnproof_2)
			if err != nil || !dlnPf2.Verify(H2j, H1j, NTildej) {
				dlnProof2Fail[kk] = true
			}
		}()
	}
	wg.Wait()

	for k := range otherIds {
		if dlnProof1Fail[k] || dlnProof2Fail[k] {
			kg.Err <- fmt.Errorf("party %s: DLN proof verification failed", otherIds[k])
			return
		}
	}

	// Store verified values from R1 messages
	for k, r1msg := range r1msgs {
		jIdx := partyIdxMap[k]

		paillierPK := &paillier.PublicKey{N: new(big.Int).SetBytes(r1msg.PaillierN)}
		NTildej := new(big.Int).SetBytes(r1msg.NTilde)
		H1j := new(big.Int).SetBytes(r1msg.H1)
		H2j := new(big.Int).SetBytes(r1msg.H2)

		kg.data.PaillierPKs[jIdx] = paillierPK
		kg.data.NTildej[jIdx] = NTildej
		kg.data.H1j[jIdx] = H1j
		kg.data.H2j[jIdx] = H2j
		kg.KGCs[jIdx] = cmts.HashCommitment(new(big.Int).SetBytes(r1msg.Commitment))
	}

	// Generate ContextI for proofs
	ContextI := append(kg.ssid, big.NewInt(int64(i)).Bytes()...)

	// Generate FacProof for each other party and send P2P round2-1 messages
	for k, oid := range otherIds {
		jIdx := partyIdxMap[k]

		var facProofBzs [][]byte
		if !kg.params.NoProofFac() {
			fp, err := facproof.NewProof(ContextI, ec, kg.data.PaillierSK.N,
				kg.data.NTildej[jIdx], kg.data.H1j[jIdx], kg.data.H2j[jIdx],
				kg.data.PaillierSK.P, kg.data.PaillierSK.Q, kg.params.Rand())
			if err != nil {
				kg.Err <- fmt.Errorf("failed to generate fac proof for party %s: %w", oid, err)
				return
			}
			bzArr := fp.Bytes()
			facProofBzs = bzArr[:]
		}

		// Find the share for this party: shares are indexed by position in
		// allParties, so the share at jIdx corresponds to party allParties[jIdx].
		shareBytes := kg.shares[jIdx].Share.Bytes()

		r2m1 := &keygenRound2msg1{
			Share:    shareBytes,
			FacProof: facProofBzs,
		}
		m := tss.JsonWrap("ecdsa:keygen:round2-1", r2m1, Pi, oid)
		kg.params.Broker().Receive(m)
	}

	// Generate ModProof and broadcast round2-2 message
	var modProofBzs [][]byte
	if !kg.params.NoProofMod() {
		mp, err := modproof.NewProof(ContextI, kg.data.PaillierSK.N,
			kg.data.PaillierSK.P, kg.data.PaillierSK.Q, kg.params.Rand())
		if err != nil {
			kg.Err <- fmt.Errorf("failed to generate mod proof: %w", err)
			return
		}
		bzArr := mp.Bytes()
		modProofBzs = bzArr[:]
	}

	r2m2 := &keygenRound2msg2{
		DeCommitment: common.BigIntsToBytes(kg.deCommitPolyG),
		ModProof:     modProofBzs,
	}
	for _, oid := range otherIds {
		m := tss.JsonWrap("ecdsa:keygen:round2-2", r2m2, Pi, oid)
		kg.params.Broker().Receive(m)
	}

	// Set pending counter for two incoming message types
	atomic.StoreInt32(&kg.r2pending, 2)

	// Register receivers for round 2 messages from other parties
	rcv1 := tss.NewJsonExpect[keygenRound2msg1]("ecdsa:keygen:round2-1", otherIds, kg.onR2msg1)
	kg.params.Broker().Connect("ecdsa:keygen:round2-1", rcv1)

	rcv2 := tss.NewJsonExpect[keygenRound2msg2]("ecdsa:keygen:round2-2", otherIds, kg.onR2msg2)
	kg.params.Broker().Connect("ecdsa:keygen:round2-2", rcv2)
}

func (kg *Keygen) onR2msg1(from []*tss.PartyID, msgs []*keygenRound2msg1) {
	kg.r2msg1From = from
	kg.r2msg1 = msgs
	if atomic.AddInt32(&kg.r2pending, -1) == 0 {
		kg.processRound3()
	}
}

func (kg *Keygen) onR2msg2(from []*tss.PartyID, msgs []*keygenRound2msg2) {
	kg.r2msg2From = from
	kg.r2msg2 = msgs
	if atomic.AddInt32(&kg.r2pending, -1) == 0 {
		kg.processRound3()
	}
}

// processRound3 verifies round 2 messages and executes round 3.
func (kg *Keygen) processRound3() {
	if kg.ctx.Err() != nil {
		kg.Err <- kg.ctx.Err()
		return
	}
	kg.round = 3

	Pi := kg.params.PartyID()
	i := Pi.Index
	ec := kg.params.EC()
	allParties := kg.params.Parties().IDs()
	threshold := kg.params.Threshold()

	// Build index mapping for r2msg1From (should be same set as r2msg2From)
	partyIdxMap := make(map[int]int) // position in r2msg1From -> index in allParties
	for k, oid := range kg.r2msg1From {
		for n, pid := range allParties {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				partyIdxMap[k] = n
				break
			}
		}
	}

	// Also build map for r2msg2From
	r2msg2IdxMap := make(map[int]int) // position in r2msg2From -> index in allParties
	for k, oid := range kg.r2msg2From {
		for n, pid := range allParties {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				r2msg2IdxMap[k] = n
				break
			}
		}
	}

	// Build a lookup from allParties index -> r2msg2 position
	r2msg2ByPartyIdx := make(map[int]int)
	for k, jIdx := range r2msg2IdxMap {
		r2msg2ByPartyIdx[jIdx] = k
	}

	// Verify and process each other party's messages concurrently
	type verifyResult struct {
		err  error
		pjVs vss.Vs
	}
	chs := make([]chan verifyResult, len(kg.r2msg1From))

	for k := range kg.r2msg1From {
		chs[k] = make(chan verifyResult, 1)
		jIdx := partyIdxMap[k]
		m2Pos := r2msg2ByPartyIdx[jIdx]

		go func(k, jIdx, m2Pos int) {
			r2m1 := kg.r2msg1[k]
			r2m2 := kg.r2msg2[m2Pos]

			ContextJ := common.AppendBigIntToBytesSlice(kg.ssid, big.NewInt(int64(jIdx)))

			// Verify decommitment
			KGCj := kg.KGCs[jIdx]
			KGDj := cmts.NewHashDeCommitmentFromBytes(r2m2.DeCommitment)
			cmtDeCmt := cmts.HashCommitDecommit{C: KGCj, D: KGDj}
			ok, flatPolyGs := cmtDeCmt.DeCommit()
			if !ok || flatPolyGs == nil {
				chs[k] <- verifyResult{err: fmt.Errorf("party %s: decommitment verification failed", allParties[jIdx])}
				return
			}

			PjVs, err := crypto.UnFlattenECPoints(ec, flatPolyGs)
			if err != nil {
				chs[k] <- verifyResult{err: fmt.Errorf("party %s: unflatten EC points failed: %w", allParties[jIdx], err)}
				return
			}

			// Verify ModProof
			if !kg.params.NoProofMod() {
				if len(r2m2.ModProof) == 0 {
					chs[k] <- verifyResult{err: fmt.Errorf("party %s: mod proof missing", allParties[jIdx])}
					return
				}
				mp, err := modproof.NewProofFromBytes(r2m2.ModProof)
				if err != nil {
					chs[k] <- verifyResult{err: fmt.Errorf("party %s: mod proof deserialization failed: %w", allParties[jIdx], err)}
					return
				}
				if ok := mp.Verify(ContextJ, kg.data.PaillierPKs[jIdx].N); !ok {
					chs[k] <- verifyResult{err: fmt.Errorf("party %s: mod proof verification failed", allParties[jIdx])}
					return
				}
			}

			// Verify VSS share
			share := vss.Share{
				Threshold: threshold,
				ID:        Pi.KeyInt(),
				Share:     new(big.Int).SetBytes(r2m1.Share),
			}
			if ok := share.Verify(ec, threshold, PjVs); !ok {
				chs[k] <- verifyResult{err: fmt.Errorf("party %s: VSS share verification failed", allParties[jIdx])}
				return
			}

			// Verify FacProof
			if !kg.params.NoProofFac() {
				if len(r2m1.FacProof) == 0 {
					chs[k] <- verifyResult{err: fmt.Errorf("party %s: fac proof missing", allParties[jIdx])}
					return
				}
				fp, err := facproof.NewProofFromBytes(r2m1.FacProof)
				if err != nil {
					chs[k] <- verifyResult{err: fmt.Errorf("party %s: fac proof deserialization failed: %w", allParties[jIdx], err)}
					return
				}
				if ok := fp.Verify(ContextJ, ec, kg.data.PaillierPKs[jIdx].N,
					kg.data.NTildei, kg.data.H1i, kg.data.H2i); !ok {
					chs[k] <- verifyResult{err: fmt.Errorf("party %s: fac proof verification failed", allParties[jIdx])}
					return
				}
			}

			chs[k] <- verifyResult{pjVs: PjVs}
		}(k, jIdx, m2Pos)
	}

	// Collect results
	pjVsMap := make(map[int]vss.Vs) // allParties index -> PjVs
	for k := range chs {
		result := <-chs[k]
		if result.err != nil {
			kg.Err <- result.err
			return
		}
		jIdx := partyIdxMap[k]
		pjVsMap[jIdx] = result.pjVs
	}

	// Compute xi = own share + sum(received shares) mod N
	xi := new(big.Int).Set(kg.shares[i].Share)
	for k := range kg.r2msg1 {
		share := new(big.Int).SetBytes(kg.r2msg1[k].Share)
		xi = new(big.Int).Add(xi, share)
	}
	kg.data.Xi = new(big.Int).Mod(xi, ec.Params().N)

	// Aggregate Vc: start with our own vs
	Vc := make(vss.Vs, threshold+1)
	for c := range Vc {
		Vc[c] = kg.vs[c]
	}
	for jIdx, PjVs := range pjVsMap {
		_ = jIdx
		for c := 0; c <= threshold; c++ {
			var err error
			Vc[c], err = Vc[c].Add(PjVs[c])
			if err != nil {
				kg.Err <- fmt.Errorf("failed to add PjVs[%d] to Vc[%d]: %w", c, c, err)
				return
			}
		}
	}

	// Compute BigXj for each party
	modQ := common.ModInt(ec.Params().N)
	ks := kg.data.Ks
	for j := 0; j < kg.params.PartyCount(); j++ {
		kj := ks[j]
		BigXj := Vc[0]
		z := new(big.Int).SetInt64(1)
		for c := 1; c <= threshold; c++ {
			z = modQ.Mul(z, kj)
			var err error
			BigXj, err = BigXj.Add(Vc[c].ScalarMult(z))
			if err != nil {
				kg.Err <- fmt.Errorf("failed computing BigXj for party %d: %w", j, err)
				return
			}
		}
		kg.data.BigXj[j] = BigXj
	}

	// ECDSAPub = Vc[0]
	ecdsaPubKey, err := crypto.NewECPoint(ec, Vc[0].X(), Vc[0].Y())
	if err != nil {
		kg.Err <- fmt.Errorf("public key is not on the curve: %w", err)
		return
	}
	kg.data.ECDSAPub = ecdsaPubKey

	// Generate Paillier proof
	ki := Pi.KeyInt()
	proof, err := kg.data.PaillierSK.Proof(ki, ecdsaPubKey)
	if err != nil {
		kg.Err <- fmt.Errorf("failed to generate Paillier proof: %w", err)
		return
	}

	// Serialize proof
	proofBzs := make([][]byte, paillier.ProofIters)
	for idx := 0; idx < paillier.ProofIters; idx++ {
		if proof[idx] != nil {
			proofBzs[idx] = proof[idx].Bytes()
		}
	}

	r3msg := &keygenRound3msg{
		PaillierProof: proofBzs,
	}

	// Broadcast round 3 message
	var otherIds []*tss.PartyID
	for n, p := range allParties {
		if n == i {
			continue
		}
		otherIds = append(otherIds, p)
		m := tss.JsonWrap("ecdsa:keygen:round3", r3msg, Pi, p)
		kg.params.Broker().Receive(m)
	}

	// Register receiver for round 3 -> round 4
	rcv := tss.NewJsonExpect[keygenRound3msg]("ecdsa:keygen:round3", otherIds, kg.round4)
	kg.params.Broker().Connect("ecdsa:keygen:round3", rcv)
}

// round4 verifies Paillier proofs from all other parties and completes keygen.
func (kg *Keygen) round4(otherIds []*tss.PartyID, r3msgs []*keygenRound3msg) {
	if kg.ctx.Err() != nil {
		kg.Err <- kg.ctx.Err()
		return
	}
	kg.round = 4

	allParties := kg.params.Parties().IDs()
	allKeys := allParties.Keys()
	ecdsaPub := kg.data.ECDSAPub

	// Build index mapping
	partyIdxMap := make([]int, len(otherIds))
	for k, oid := range otherIds {
		for n, pid := range allParties {
			if pid.KeyInt().Cmp(oid.KeyInt()) == 0 {
				partyIdxMap[k] = n
				break
			}
		}
	}

	// Verify Paillier proofs concurrently
	chs := make([]chan bool, len(otherIds))
	for k := range chs {
		chs[k] = make(chan bool, 1)
	}

	for k, r3msg := range r3msgs {
		jIdx := partyIdxMap[k]
		go func(k, jIdx int, r3msg *keygenRound3msg) {
			// Deserialize Paillier proof
			var proof paillier.Proof
			for idx := 0; idx < paillier.ProofIters; idx++ {
				if idx < len(r3msg.PaillierProof) && len(r3msg.PaillierProof[idx]) > 0 {
					proof[idx] = new(big.Int).SetBytes(r3msg.PaillierProof[idx])
				} else {
					proof[idx] = big.NewInt(0)
				}
			}

			ppk := kg.data.PaillierPKs[jIdx]
			ok, err := proof.Verify(ppk.N, allKeys[jIdx], ecdsaPub)
			if err != nil {
				chs[k] <- false
				return
			}
			chs[k] <- ok
		}(k, jIdx, r3msg)
	}

	// Collect results
	var culprits []string
	for k := range chs {
		if !<-chs[k] {
			jIdx := partyIdxMap[k]
			culprits = append(culprits, allParties[jIdx].String())
		}
	}

	if len(culprits) > 0 {
		kg.Err <- fmt.Errorf("paillier proof verification failed for parties: %v", culprits)
		return
	}

	kg.Done <- kg.data
}
