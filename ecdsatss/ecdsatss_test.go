package ecdsatss

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/KarpelesLab/secp256k1/ecckd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/crypto/ckd"
	"github.com/KarpelesLab/tss-lib/v2/crypto/paillier"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

func newTestPaillierSK() *paillier.PrivateKey {
	P := big.NewInt(107)
	Q := big.NewInt(113)
	N := new(big.Int).Mul(P, Q)
	PMinus1 := new(big.Int).Sub(P, big.NewInt(1))
	QMinus1 := new(big.Int).Sub(Q, big.NewInt(1))
	PhiN := new(big.Int).Mul(PMinus1, QMinus1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	LambdaN := new(big.Int).Div(PhiN, gcd)

	return &paillier.PrivateKey{
		PublicKey: paillier.PublicKey{N: N},
		LambdaN:   LambdaN,
		PhiN:      PhiN,
		P:         P,
		Q:         Q,
	}
}

func TestLocalPreParamsValidate(t *testing.T) {
	sk := newTestPaillierSK()

	pp := LocalPreParams{
		PaillierSK: sk,
		NTildei:    big.NewInt(100),
		H1i:        big.NewInt(200),
		H2i:        big.NewInt(300),
	}
	assert.True(t, pp.Validate())

	pp2 := LocalPreParams{PaillierSK: sk}
	assert.False(t, pp2.Validate())

	pp3 := LocalPreParams{PaillierSK: sk, NTildei: big.NewInt(1)}
	assert.False(t, pp3.Validate())

	pp4 := LocalPreParams{PaillierSK: sk, NTildei: big.NewInt(1), H1i: big.NewInt(2)}
	assert.False(t, pp4.Validate())

	pp5 := LocalPreParams{NTildei: big.NewInt(1), H1i: big.NewInt(2), H2i: big.NewInt(3)}
	assert.False(t, pp5.Validate())
}

func TestLocalPreParamsValidateWithProof(t *testing.T) {
	sk := newTestPaillierSK()

	pp := LocalPreParams{
		PaillierSK: sk,
		NTildei:    big.NewInt(100),
		H1i:        big.NewInt(200),
		H2i:        big.NewInt(300),
		Alpha:      big.NewInt(400),
		Beta:       big.NewInt(500),
		P:          big.NewInt(600),
		Q:          big.NewInt(700),
	}
	assert.True(t, pp.ValidateWithProof())

	pp2 := LocalPreParams{
		PaillierSK: sk,
		NTildei:    big.NewInt(100),
		H1i:        big.NewInt(200),
		H2i:        big.NewInt(300),
	}
	assert.False(t, pp2.ValidateWithProof())

	pp3 := LocalPreParams{
		PaillierSK: sk,
		NTildei:    big.NewInt(100),
		H1i:        big.NewInt(200),
		H2i:        big.NewInt(300),
		Alpha:      big.NewInt(400),
		Beta:       big.NewInt(500),
	}
	assert.False(t, pp3.ValidateWithProof())
}

// --- Hub broker for integration tests ---

type hubBroker struct {
	partyIdx int
	hub      *testHub
	handlers map[string]tss.MessageReceiver
	pending  map[string][]*tss.JsonMessage
	mu       sync.Mutex
}

type testHub struct {
	brokers []*hubBroker
}

func newTestHub(n int) *testHub {
	h := &testHub{
		brokers: make([]*hubBroker, n),
	}
	for i := 0; i < n; i++ {
		h.brokers[i] = &hubBroker{
			partyIdx: i,
			hub:      h,
			handlers: make(map[string]tss.MessageReceiver),
			pending:  make(map[string][]*tss.JsonMessage),
		}
	}
	return h
}

func (b *hubBroker) Connect(typ string, dest tss.MessageReceiver) {
	b.mu.Lock()
	b.handlers[typ] = dest
	queued := b.pending[typ]
	delete(b.pending, typ)
	b.mu.Unlock()

	for _, msg := range queued {
		if err := dest.Receive(msg); err != nil {
			fmt.Printf("hubBroker: error delivering queued message type %s to party %d: %v\n", typ, b.partyIdx, err)
		}
	}
}

func (b *hubBroker) Receive(msg *tss.JsonMessage) error {
	if msg.From.Index == b.partyIdx {
		if msg.To != nil {
			return b.hub.brokers[msg.To.Index].Receive(msg)
		}
		for j, broker := range b.hub.brokers {
			if j == b.partyIdx {
				continue
			}
			if err := broker.Receive(msg); err != nil {
				return err
			}
		}
		return nil
	}

	b.mu.Lock()
	handler, ok := b.handlers[msg.Type]
	if !ok {
		b.pending[msg.Type] = append(b.pending[msg.Type], msg)
		b.mu.Unlock()
		return nil
	}
	b.mu.Unlock()
	return handler.Receive(msg)
}

// --- ECDSA Keygen Integration Test ---

func TestKeygenFull(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)

	// Pre-generate params for all parties (this is the expensive part)
	t.Log("Generating pre-parameters for all parties...")
	preParams := make([]LocalPreParams, partyCount)
	for i := 0; i < partyCount; i++ {
		pp, err := GeneratePreParams(5*time.Minute, 4)
		require.NoError(t, err, "GeneratePreParams should not fail for party %d", i)
		preParams[i] = *pp
		t.Logf("Party %d pre-params generated", i)
	}

	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		params.SetNoProofMod()
		params.SetNoProofFac()

		kg, err := NewKeygen(context.Background(), params, preParams[i])
		require.NoError(t, err, "NewKeygen should not fail for party %d", i)
		keygens[i] = kg
	}

	keys := make([]*Key, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			keys[i] = k
			t.Logf("Party %d completed keygen", i)
		case err := <-keygens[i].Err:
			t.Fatalf("Party %d keygen error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("Party %d keygen timed out", i)
		}
	}

	// verify all parties got the same public key
	for i := 1; i < partyCount; i++ {
		assert.True(t, keys[0].ECDSAPub.Equals(keys[i].ECDSAPub),
			"party 0 and party %d should have the same public key", i)
	}

	t.Log("All parties completed ECDSA keygen with matching public keys")
}

func TestKeygenAndSign(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)

	// Pre-generate params for all parties
	t.Log("Generating pre-parameters for all parties...")
	preParams := make([]LocalPreParams, partyCount)
	for i := 0; i < partyCount; i++ {
		pp, err := GeneratePreParams(5*time.Minute, 4)
		require.NoError(t, err, "GeneratePreParams should not fail for party %d", i)
		preParams[i] = *pp
		t.Logf("Party %d pre-params generated", i)
	}

	// --- Phase 1: Keygen ---
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		params.SetNoProofMod()
		params.SetNoProofFac()

		kg, err := NewKeygen(context.Background(), params, preParams[i])
		require.NoError(t, err, "NewKeygen should not fail for party %d", i)
		keygens[i] = kg
	}

	keys := make([]*Key, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			keys[i] = k
			t.Logf("Party %d completed keygen", i)
		case err := <-keygens[i].Err:
			t.Fatalf("Party %d keygen error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("Party %d keygen timed out", i)
		}
	}

	// Verify all parties got the same public key
	for i := 1; i < partyCount; i++ {
		require.True(t, keys[0].ECDSAPub.Equals(keys[i].ECDSAPub),
			"party 0 and party %d should have the same public key", i)
	}
	t.Log("Keygen completed successfully")

	// --- Phase 2: Signing ---
	// Create a message to sign (hash of "hello world")
	msgHash := sha256.Sum256([]byte("hello world"))
	msg := new(big.Int).SetBytes(msgHash[:])

	// Create a new hub for signing (fresh broker state)
	signHub := newTestHub(partyCount)

	signings := make([]*Signing, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(signHub.brokers[i])

		sig, err := keys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err, "NewSigning should not fail for party %d", i)
		signings[i] = sig
	}

	// Collect signature data from all parties
	sigDatas := make([]*SignatureData, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case sd := <-signings[i].Done:
			sigDatas[i] = sd
			t.Logf("Party %d completed signing", i)
		case err := <-signings[i].Err:
			t.Fatalf("Party %d signing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("Party %d signing timed out", i)
		}
	}

	// Verify all parties produced the same signature
	for i := 1; i < partyCount; i++ {
		assert.Equal(t, sigDatas[0].R, sigDatas[i].R, "party 0 and party %d should have the same R", i)
		assert.Equal(t, sigDatas[0].S, sigDatas[i].S, "party 0 and party %d should have the same S", i)
	}

	// Verify the signature using crypto/ecdsa
	r := new(big.Int).SetBytes(sigDatas[0].R)
	sVal := new(big.Int).SetBytes(sigDatas[0].S)
	pk := ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}

	ok := ecdsa.Verify(&pk, msgHash[:], r, sVal)
	assert.True(t, ok, "ECDSA signature verification should succeed")

	t.Log("All parties completed ECDSA signing with valid signature")
}

func TestKeygenAndSignWithKDD(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)

	// --- Phase 1: Pre-params + keygen (same shape as TestKeygenAndSign) ---
	t.Log("Generating pre-parameters for all parties...")
	preParams := make([]LocalPreParams, partyCount)
	for i := 0; i < partyCount; i++ {
		pp, err := GeneratePreParams(5*time.Minute, 4)
		require.NoError(t, err, "GeneratePreParams should not fail for party %d", i)
		preParams[i] = *pp
		t.Logf("Party %d pre-params generated", i)
	}

	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		params.SetNoProofMod()
		params.SetNoProofFac()

		kg, err := NewKeygen(context.Background(), params, preParams[i])
		require.NoError(t, err, "NewKeygen should not fail for party %d", i)
		keygens[i] = kg
	}

	keys := make([]*Key, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			keys[i] = k
			t.Logf("Party %d completed keygen", i)
		case err := <-keygens[i].Err:
			t.Fatalf("Party %d keygen error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("Party %d keygen timed out", i)
		}
	}

	for i := 1; i < partyCount; i++ {
		require.True(t, keys[0].ECDSAPub.Equals(keys[i].ECDSAPub),
			"party 0 and party %d should have the same public key", i)
	}
	t.Log("Keygen completed successfully")

	// --- Phase 2: Derive child key via BIP32 path ---
	chainCode := make([]byte, 32)
	_, err := rand.Read(chainCode)
	require.NoError(t, err, "chain code rand should succeed")

	parentExt := &ckd.ExtendedKey{
		PublicKey: ecdsa.PublicKey{
			Curve: tss.S256(),
			X:     keys[0].ECDSAPub.X(),
			Y:     keys[0].ECDSAPub.Y(),
		},
		Depth:      0,
		ChildIndex: 0,
		ChainCode:  chainCode,
		ParentFP:   []byte{0, 0, 0, 0},
		Version:    ecckd.BitcoinMainnetPrivate,
	}

	delta, childExt, err := ckd.DeriveChildKeyFromHierarchy(
		[]uint32{12, 209, 3},
		parentExt,
		tss.S256().Params().N,
		tss.S256(),
	)
	require.NoError(t, err, "child key derivation should succeed")
	require.NotNil(t, delta)
	require.NotNil(t, childExt)

	// Snapshot the master pubkey so we can assert it was not mutated.
	masterX := new(big.Int).Set(keys[0].ECDSAPub.X())
	masterY := new(big.Int).Set(keys[0].ECDSAPub.Y())
	masterXi := new(big.Int).Set(keys[0].Xi)

	// --- Phase 3: Signing under the derived child key ---
	msgHash := sha256.Sum256([]byte("hello hd world"))
	msg := new(big.Int).SetBytes(msgHash[:])

	signHub := newTestHub(partyCount)

	signings := make([]*Signing, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(signHub.brokers[i])

		sig, err := keys[i].NewSigningWithKDD(context.Background(), msg, params, delta)
		require.NoError(t, err, "NewSigningWithKDD should not fail for party %d", i)
		signings[i] = sig
	}

	sigDatas := make([]*SignatureData, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case sd := <-signings[i].Done:
			sigDatas[i] = sd
			t.Logf("Party %d completed signing", i)
		case err := <-signings[i].Err:
			t.Fatalf("Party %d signing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("Party %d signing timed out", i)
		}
	}

	for i := 1; i < partyCount; i++ {
		assert.Equal(t, sigDatas[0].R, sigDatas[i].R, "party 0 and party %d should have the same R", i)
		assert.Equal(t, sigDatas[0].S, sigDatas[i].S, "party 0 and party %d should have the same S", i)
	}

	// --- Phase 4: Verify against the derived child pubkey, not the master ---
	r := new(big.Int).SetBytes(sigDatas[0].R)
	sVal := new(big.Int).SetBytes(sigDatas[0].S)

	childPk := ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     childExt.PublicKey.X,
		Y:     childExt.PublicKey.Y,
	}
	okChild := ecdsa.Verify(&childPk, msgHash[:], r, sVal)
	assert.True(t, okChild, "signature must verify under the derived child pubkey")

	// Signing should NOT verify under the master pubkey (sanity check that the delta was applied).
	masterPk := ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     masterX,
		Y:     masterY,
	}
	okMaster := ecdsa.Verify(&masterPk, msgHash[:], r, sVal)
	assert.False(t, okMaster, "signature must NOT verify under the master pubkey")

	// Assert the master Key was not mutated by NewSigningWithKDD.
	assert.Equal(t, 0, keys[0].ECDSAPub.X().Cmp(masterX), "master ECDSAPub.X must be untouched")
	assert.Equal(t, 0, keys[0].ECDSAPub.Y().Cmp(masterY), "master ECDSAPub.Y must be untouched")
	assert.Equal(t, 0, keys[0].Xi.Cmp(masterXi), "master Xi must be untouched")

	t.Log("ECDSA KDD signing test done.")

	// --- Phase 5: Nil-delta passthrough guard ---
	nilHub := newTestHub(partyCount)
	params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], partyCount, threshold)
	params.SetBroker(nilHub.brokers[0])
	nilSig, err := keys[0].NewSigningWithKDD(context.Background(), msg, params, nil)
	require.NoError(t, err, "NewSigningWithKDD(nil) must fall through to NewSigning without error")
	require.NotNil(t, nilSig, "NewSigningWithKDD(nil) must return a non-nil *Signing")
}

// TestKeygenAndSignStrictSubset exercises the bug where the signing committee is a strict,
// non-contiguous subset of the keygen parties. With 4 keygen parties and threshold=1 (t+1=2),
// picking parties {0, 2} forces the new party P2 to move from keygen index 2 to signing
// index 1 — the signing code must reindex Ks/NTildej/H1j/H2j/BigXj/PaillierPKs via
// SubsetForParties, or Lagrange interpolation and MTA lookups will use wrong slots.
func TestKeygenAndSignStrictSubset(t *testing.T) {
	const (
		partyCount = 4
		threshold  = 1 // t+1 = 2 signers
	)

	// --- Phase 1: Full 4-party keygen ---
	t.Log("Generating pre-parameters for all parties...")
	preParams := make([]LocalPreParams, partyCount)
	for i := 0; i < partyCount; i++ {
		pp, err := GeneratePreParams(5*time.Minute, 4)
		require.NoError(t, err, "GeneratePreParams should not fail for party %d", i)
		preParams[i] = *pp
		t.Logf("Party %d pre-params generated", i)
	}

	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])
		params.SetNoProofMod()
		params.SetNoProofFac()

		kg, err := NewKeygen(context.Background(), params, preParams[i])
		require.NoError(t, err, "NewKeygen should not fail for party %d", i)
		keygens[i] = kg
	}

	keys := make([]*Key, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			keys[i] = k
		case err := <-keygens[i].Err:
			t.Fatalf("Party %d keygen error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("Party %d keygen timed out", i)
		}
	}
	for i := 1; i < partyCount; i++ {
		require.True(t, keys[0].ECDSAPub.Equals(keys[i].ECDSAPub),
			"party 0 and party %d should have the same public key", i)
	}
	t.Log("Keygen completed for all 4 parties")

	// --- Phase 2: Build a strict 2-party signing subset from parties {0, 2} ---
	// Clone the PartyIDs via tss.NewPartyID so that SortPartyIDs below only assigns
	// indices on the clones; the original keygen pIDs stay intact.
	selectedKeygenIdx := []int{0, 2}
	var subsetUnsorted tss.UnSortedPartyIDs
	for _, k := range selectedKeygenIdx {
		orig := pIDs[k]
		clone := tss.NewPartyID(orig.Id, orig.Moniker, orig.KeyInt())
		subsetUnsorted = append(subsetUnsorted, clone)
	}
	subsetSorted := tss.SortPartyIDs(subsetUnsorted)
	require.Equal(t, 2, len(subsetSorted))
	require.Equal(t, 0, subsetSorted[0].Index, "subset party 0 should be at index 0")
	require.Equal(t, 1, subsetSorted[1].Index, "subset party 1 should be at index 1")

	// Safety: the originals must still report their keygen indices.
	for i, orig := range pIDs {
		require.Equal(t, i, orig.Index, "original keygen pID %d must not have been mutated", i)
	}

	subsetP2pCtx := tss.NewPeerContext(subsetSorted)

	// Map each subset position to its corresponding keygen Key by matching Key bytes.
	subsetKeys := make([]*Key, len(subsetSorted))
	for i, subsetPID := range subsetSorted {
		for k, origPID := range pIDs {
			if bytes.Equal(origPID.Key, subsetPID.Key) {
				subsetKeys[i] = keys[k]
				break
			}
		}
		require.NotNil(t, subsetKeys[i], "no keygen key found for subset party at index %d", i)
	}

	// --- Phase 3: Sign with the 2-party subset ---
	msgHash := sha256.Sum256([]byte("strict subset signing"))
	msg := new(big.Int).SetBytes(msgHash[:])

	signHub := newTestHub(len(subsetSorted))

	signings := make([]*Signing, len(subsetSorted))
	for i := 0; i < len(subsetSorted); i++ {
		params := tss.NewParameters(tss.S256(), subsetP2pCtx, subsetSorted[i], len(subsetSorted), threshold)
		params.SetBroker(signHub.brokers[i])

		sig, err := subsetKeys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err, "NewSigning should not fail for subset party %d", i)
		signings[i] = sig
	}

	sigDatas := make([]*SignatureData, len(subsetSorted))
	for i := 0; i < len(subsetSorted); i++ {
		select {
		case sd := <-signings[i].Done:
			sigDatas[i] = sd
			t.Logf("Subset party %d completed signing", i)
		case err := <-signings[i].Err:
			t.Fatalf("Subset party %d signing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("Subset party %d signing timed out", i)
		}
	}

	for i := 1; i < len(subsetSorted); i++ {
		assert.Equal(t, sigDatas[0].R, sigDatas[i].R, "R mismatch between subset parties")
		assert.Equal(t, sigDatas[0].S, sigDatas[i].S, "S mismatch between subset parties")
	}

	// --- Phase 4: Verify under the original master pubkey ---
	r := new(big.Int).SetBytes(sigDatas[0].R)
	sVal := new(big.Int).SetBytes(sigDatas[0].S)
	pk := ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     keys[0].ECDSAPub.X(),
		Y:     keys[0].ECDSAPub.Y(),
	}
	ok := ecdsa.Verify(&pk, msgHash[:], r, sVal)
	assert.True(t, ok, "subset signature must verify under the master keygen pubkey")
	t.Log("Strict subset signature verified under master pubkey")
}

// --- Resharing Hub broker ---
// Unlike the keygen hub, the resharing hub routes messages by PartyID KeyInt
// because old and new committees have separate index spaces.

type resharingBroker struct {
	keyInt   *big.Int // KeyInt of the party this broker belongs to
	hub      *resharingHub
	handlers map[string]tss.MessageReceiver
	pending  map[string][]*tss.JsonMessage
	mu       sync.Mutex
}

type resharingHub struct {
	brokers map[string]*resharingBroker // keyed by hex(KeyInt)
}

func newResharingHub(allPartyIDs []*tss.PartyID) *resharingHub {
	h := &resharingHub{
		brokers: make(map[string]*resharingBroker, len(allPartyIDs)),
	}
	for _, pid := range allPartyIDs {
		key := pid.KeyInt().Text(16)
		h.brokers[key] = &resharingBroker{
			keyInt:   pid.KeyInt(),
			hub:      h,
			handlers: make(map[string]tss.MessageReceiver),
			pending:  make(map[string][]*tss.JsonMessage),
		}
	}
	return h
}

func (h *resharingHub) brokerFor(pid *tss.PartyID) *resharingBroker {
	return h.brokers[pid.KeyInt().Text(16)]
}

func (rb *resharingBroker) Connect(typ string, dest tss.MessageReceiver) {
	rb.mu.Lock()
	rb.handlers[typ] = dest
	queued := rb.pending[typ]
	delete(rb.pending, typ)
	rb.mu.Unlock()

	for _, msg := range queued {
		if err := dest.Receive(msg); err != nil {
			fmt.Printf("resharingBroker: error delivering queued message type %s: %v\n", typ, err)
		}
	}
}

func (rb *resharingBroker) Receive(msg *tss.JsonMessage) error {
	// If from self, route to destination
	if msg.From.KeyInt().Cmp(rb.keyInt) == 0 {
		if msg.To != nil {
			target := rb.hub.brokerFor(msg.To)
			if target == nil {
				return fmt.Errorf("resharingBroker: no broker for party %s", msg.To)
			}
			return target.Receive(msg)
		}
		// broadcast: send to all others
		for _, broker := range rb.hub.brokers {
			if broker.keyInt.Cmp(rb.keyInt) == 0 {
				continue
			}
			if err := broker.Receive(msg); err != nil {
				return err
			}
		}
		return nil
	}

	// Incoming message: deliver to handler
	rb.mu.Lock()
	handler, ok := rb.handlers[msg.Type]
	if !ok {
		rb.pending[msg.Type] = append(rb.pending[msg.Type], msg)
		rb.mu.Unlock()
		return nil
	}
	rb.mu.Unlock()
	return handler.Receive(msg)
}

// --- ECDSA Resharing Integration Test ---

func TestResharing(t *testing.T) {
	const (
		oldPartyCount = 3
		oldThreshold  = 1
		newPartyCount = 4
		newThreshold  = 2
	)

	// Phase 1: Generate pre-params for old parties and run keygen
	t.Log("Generating pre-parameters for old committee...")
	oldPreParams := make([]LocalPreParams, oldPartyCount)
	for i := 0; i < oldPartyCount; i++ {
		pp, err := GeneratePreParams(5*time.Minute, 4)
		require.NoError(t, err, "GeneratePreParams should not fail for old party %d", i)
		oldPreParams[i] = *pp
		t.Logf("Old party %d pre-params generated", i)
	}

	oldPIDs := tss.GenerateTestPartyIDs(oldPartyCount)
	oldHub := newTestHub(oldPartyCount)
	oldP2pCtx := tss.NewPeerContext(oldPIDs)

	keygens := make([]*Keygen, oldPartyCount)
	for i := 0; i < oldPartyCount; i++ {
		params := tss.NewParameters(tss.S256(), oldP2pCtx, oldPIDs[i], oldPartyCount, oldThreshold)
		params.SetBroker(oldHub.brokers[i])
		params.SetNoProofMod()
		params.SetNoProofFac()

		kg, err := NewKeygen(context.Background(), params, oldPreParams[i])
		require.NoError(t, err, "NewKeygen should not fail for old party %d", i)
		keygens[i] = kg
	}

	oldKeys := make([]*Key, oldPartyCount)
	for i := 0; i < oldPartyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			oldKeys[i] = k
			t.Logf("Old party %d completed keygen", i)
		case err := <-keygens[i].Err:
			t.Fatalf("Old party %d keygen error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("Old party %d keygen timed out", i)
		}
	}

	// Verify all old parties got the same public key
	for i := 1; i < oldPartyCount; i++ {
		require.True(t, oldKeys[0].ECDSAPub.Equals(oldKeys[i].ECDSAPub),
			"old party 0 and old party %d should have the same public key", i)
	}
	origECDSAPub := oldKeys[0].ECDSAPub
	t.Log("Old committee keygen completed successfully")

	// Phase 2: Generate pre-params for new parties
	t.Log("Generating pre-parameters for new committee...")
	newPreParams := make([]LocalPreParams, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		pp, err := GeneratePreParams(5*time.Minute, 4)
		require.NoError(t, err, "GeneratePreParams should not fail for new party %d", i)
		newPreParams[i] = *pp
		t.Logf("New party %d pre-params generated", i)
	}

	// Phase 3: Run resharing
	// Generate new party IDs (no overlap with old)
	newPIDs := tss.GenerateTestPartyIDs(newPartyCount)
	// Offset new party IDs so they don't collide with old ones
	// GenerateTestPartyIDs generates IDs starting from 0, so new ones start from oldPartyCount
	// Actually, GenerateTestPartyIDs may generate different keys. Let's check.
	// For safety, generate new IDs with an offset.
	newPIDs = generateOffsetTestPartyIDs(newPartyCount, oldPartyCount)

	newP2pCtx := tss.NewPeerContext(newPIDs)

	// Create resharing hub with all parties
	allPartyIDs := make([]*tss.PartyID, 0, oldPartyCount+newPartyCount)
	allPartyIDs = append(allPartyIDs, oldPIDs...)
	allPartyIDs = append(allPartyIDs, newPIDs...)
	reshareHub := newResharingHub(allPartyIDs)

	t.Log("Starting resharing protocol...")

	resharings := make([]*Resharing, oldPartyCount+newPartyCount)

	// Create old committee resharing parties
	for i := 0; i < oldPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.S256(), oldP2pCtx, newP2pCtx, oldPIDs[i], oldPartyCount, oldThreshold, newPartyCount, newThreshold)
		params.SetNoProofMod()
		params.SetNoProofFac()
		params.SetBroker(reshareHub.brokerFor(oldPIDs[i]))

		rs, err := NewResharing(context.Background(), params, oldKeys[i])
		require.NoError(t, err, "NewResharing should not fail for old party %d", i)
		resharings[i] = rs
	}

	// Create new committee resharing parties
	for i := 0; i < newPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.S256(), oldP2pCtx, newP2pCtx, newPIDs[i], oldPartyCount, oldThreshold, newPartyCount, newThreshold)
		params.SetNoProofMod()
		params.SetNoProofFac()
		params.SetBroker(reshareHub.brokerFor(newPIDs[i]))

		rs, err := NewResharing(context.Background(), params, nil, newPreParams[i])
		require.NoError(t, err, "NewResharing should not fail for new party %d", i)
		resharings[oldPartyCount+i] = rs
	}

	// Collect results
	newKeys := make([]*Key, newPartyCount)
	for i := 0; i < oldPartyCount+newPartyCount; i++ {
		select {
		case k := <-resharings[i].Done:
			if i < oldPartyCount {
				t.Logf("Old party %d completed resharing (Xi zeroed)", i)
				// Old party's key should have Xi zeroed
				assert.Equal(t, int64(0), k.Xi.Int64(), "old party %d Xi should be zeroed", i)
			} else {
				newIdx := i - oldPartyCount
				newKeys[newIdx] = k
				t.Logf("New party %d completed resharing", newIdx)
			}
		case err := <-resharings[i].Err:
			if i < oldPartyCount {
				t.Fatalf("Old party %d resharing error: %v", i, err)
			} else {
				t.Fatalf("New party %d resharing error: %v", i-oldPartyCount, err)
			}
		case <-time.After(5 * time.Minute):
			if i < oldPartyCount {
				t.Fatalf("Old party %d resharing timed out", i)
			} else {
				t.Fatalf("New party %d resharing timed out", i-oldPartyCount)
			}
		}
	}

	// Verify new committee has the same ECDSAPub
	for i := 0; i < newPartyCount; i++ {
		require.NotNil(t, newKeys[i], "new party %d key should not be nil", i)
		assert.True(t, origECDSAPub.Equals(newKeys[i].ECDSAPub),
			"new party %d should have the same ECDSAPub as the original", i)
	}
	t.Log("Resharing completed: new committee has same ECDSAPub")

	// Phase 4: Sign with new committee
	msgHash := sha256.Sum256([]byte("resharing test"))
	msg := new(big.Int).SetBytes(msgHash[:])

	signHub := newTestHub(newPartyCount)
	signings := make([]*Signing, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		params := tss.NewParameters(tss.S256(), newP2pCtx, newPIDs[i], newPartyCount, newThreshold)
		params.SetBroker(signHub.brokers[i])

		sig, err := newKeys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err, "NewSigning should not fail for new party %d", i)
		signings[i] = sig
	}

	sigDatas := make([]*SignatureData, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		select {
		case sd := <-signings[i].Done:
			sigDatas[i] = sd
			t.Logf("New party %d completed signing", i)
		case err := <-signings[i].Err:
			t.Fatalf("New party %d signing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("New party %d signing timed out", i)
		}
	}

	// Verify ECDSA signature
	r := new(big.Int).SetBytes(sigDatas[0].R)
	sVal := new(big.Int).SetBytes(sigDatas[0].S)
	pk := ecdsa.PublicKey{
		Curve: tss.S256(),
		X:     origECDSAPub.X(),
		Y:     origECDSAPub.Y(),
	}

	ok := ecdsa.Verify(&pk, msgHash[:], r, sVal)
	assert.True(t, ok, "ECDSA signature verification with reshared keys should succeed")

	t.Log("Resharing + signing test completed successfully")
}

func generateOffsetTestPartyIDs(count, offset int) tss.SortedPartyIDs {
	ids := make(tss.UnSortedPartyIDs, 0, count)
	for i := 0; i < count; i++ {
		ids = append(ids, tss.NewPartyID(
			fmt.Sprintf("new-%d", i+offset),
			fmt.Sprintf("new-moniker-%d", i+offset),
			new(big.Int).SetInt64(int64(i+offset+1)*1000),
		))
	}
	return tss.SortPartyIDs(ids)
}
