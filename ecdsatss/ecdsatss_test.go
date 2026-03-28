package ecdsatss

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		LambdaN:  LambdaN,
		PhiN:     PhiN,
		P:        P,
		Q:        Q,
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

		kg, err := NewKeygen(params, preParams[i])
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

		kg, err := NewKeygen(params, preParams[i])
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

		sig, err := keys[i].NewSigning(msg, params)
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
