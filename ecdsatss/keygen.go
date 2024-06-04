package ecdsatss

import (
	"context"
	"errors"
	"math/big"

	"github.com/ModChain/tss-lib/v2/common"
	"github.com/ModChain/tss-lib/v2/crypto"
	cmts "github.com/ModChain/tss-lib/v2/crypto/commitments"
	"github.com/ModChain/tss-lib/v2/crypto/dlnproof"
	"github.com/ModChain/tss-lib/v2/crypto/vss"
	"github.com/ModChain/tss-lib/v2/tss"
)

var zero = big.NewInt(0)

// Keygen is an object used to track a key currently being generated
type Keygen struct {
	params        *tss.Parameters // contains curve, parties, etc
	KGCs          []cmts.HashCommitment
	vs            vss.Vs
	ssid          []byte // ssid for current round/values
	ssidNonce     *big.Int
	shares        vss.Shares
	deCommitPolyG cmts.HashDeCommitment
	data          *Key // key data currently being generated
	round         int  // current round

	Receiver tss.JsonExpect
}

func NewKeygen(params *tss.Parameters) (*Keygen, error) {
	partyCount := params.PartyCount()
	res := &Keygen{
		params: params,
		KGCs:   make([]cmts.HashCommitment, partyCount),
		data:   &Key{},
		round:  1,
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
		ctx, cancel := context.WithTimeout(context.Background(), kg.params.SafePrimeGenTimeout())
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
	// round.PartyID(), cmt.C, &preParams.PaillierSK.PublicKey, preParams.NTildei, preParams.H1i, preParams.H2i, dlnProof1, dlnProof2
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
		_ = m
	}

	kg.Receiver = tss.NewJsonExpect[keygenRound2msg1]("ecdsa:keygen:round2-1", otherIds, kg.round2)

	return nil
}

func (kg *Keygen) round2(otherIds []*tss.PartyID, r2msg1 []*keygenRound2msg1) {
}
