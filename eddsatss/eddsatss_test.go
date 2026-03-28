package eddsatss

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// hubBroker routes messages between parties in a test network.
// When the protocol calls broker.Receive(msg), it routes the message:
//   - If msg.From matches this party (outbound): route to destination party's broker
//   - If msg.From does NOT match this party (inbound): dispatch to local handler
//
// If no handler is registered yet for an inbound message, it is queued and
// delivered as soon as Connect() registers a handler for that type.
type hubBroker struct {
	partyIdx int
	hub      *testHub
	handlers map[string]tss.MessageReceiver
	pending  map[string][]*tss.JsonMessage // messages buffered before handler registered
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
	// drain any pending messages for this type
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
		// outbound from this party: route to destination
		if msg.To != nil {
			// P2P: route to specific party
			return b.hub.brokers[msg.To.Index].Receive(msg)
		}
		// broadcast to all other parties
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

	// inbound to this party: dispatch to handler or queue
	b.mu.Lock()
	handler, ok := b.handlers[msg.Type]
	if !ok {
		// no handler yet; buffer the message
		b.pending[msg.Type] = append(b.pending[msg.Type], msg)
		b.mu.Unlock()
		return nil
	}
	b.mu.Unlock()
	return handler.Receive(msg)
}

func TestKeygenFull(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)

	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])

		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err, "NewKeygen should not fail for party %d", i)
		keygens[i] = kg
	}

	// collect results from all parties
	keys := make([]*Key, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			keys[i] = k
			t.Logf("Party %d completed keygen", i)
		case err := <-keygens[i].Err:
			t.Fatalf("Party %d keygen error: %v", i, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("Party %d keygen timed out", i)
		}
	}

	// verify all parties got the same public key
	for i := 1; i < partyCount; i++ {
		assert.True(t, keys[0].EDDSAPub.Equals(keys[i].EDDSAPub),
			"party 0 and party %d should have the same public key", i)
	}

	// verify all parties have the same Ks
	for i := 1; i < partyCount; i++ {
		for j := range keys[0].Ks {
			assert.Equal(t, keys[0].Ks[j].Cmp(keys[i].Ks[j]), 0,
				"party 0 and party %d should have the same Ks[%d]", i, j)
		}
	}

	t.Log("All parties completed keygen with matching public keys")
}

// resharingHub routes messages between parties across old and new committees.
// Unlike testHub which routes by party index, this routes by PartyID key
// since old and new committees have different index spaces.
type resharingHub struct {
	brokers map[string]*resharingBroker // keyed by PartyID.KeyInt().String()
}

type resharingBroker struct {
	partyKey string
	hub      *resharingHub
	handlers map[string]tss.MessageReceiver
	pending  map[string][]*tss.JsonMessage
	mu       sync.Mutex
}

func newResharingHub() *resharingHub {
	return &resharingHub{
		brokers: make(map[string]*resharingBroker),
	}
}

func (h *resharingHub) addParty(partyID *tss.PartyID) *resharingBroker {
	key := partyID.KeyInt().String()
	if b, ok := h.brokers[key]; ok {
		return b
	}
	b := &resharingBroker{
		partyKey: key,
		hub:      h,
		handlers: make(map[string]tss.MessageReceiver),
		pending:  make(map[string][]*tss.JsonMessage),
	}
	h.brokers[key] = b
	return b
}

func (b *resharingBroker) Connect(typ string, dest tss.MessageReceiver) {
	b.mu.Lock()
	b.handlers[typ] = dest
	queued := b.pending[typ]
	delete(b.pending, typ)
	b.mu.Unlock()

	for _, msg := range queued {
		if err := dest.Receive(msg); err != nil {
			fmt.Printf("resharingBroker: error delivering queued message type %s to party %s: %v\n", typ, b.partyKey, err)
		}
	}
}

func (b *resharingBroker) Receive(msg *tss.JsonMessage) error {
	fromKey := msg.From.KeyInt().String()
	if fromKey == b.partyKey {
		// Outbound from this party: route to destination
		if msg.To != nil {
			toKey := msg.To.KeyInt().String()
			destBroker, ok := b.hub.brokers[toKey]
			if !ok {
				return fmt.Errorf("no broker for party key %s", toKey)
			}
			return destBroker.Receive(msg)
		}
		// No To field: broadcast to all other parties
		for key, broker := range b.hub.brokers {
			if key == b.partyKey {
				continue
			}
			if err := broker.Receive(msg); err != nil {
				return err
			}
		}
		return nil
	}

	// Inbound to this party: dispatch to handler or queue
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

func TestKeygenAndSign(t *testing.T) {
	const (
		partyCount = 3
		threshold  = 1
	)

	// --- PHASE 1: Keygen ---
	pIDs := tss.GenerateTestPartyIDs(partyCount)
	hub := newTestHub(partyCount)
	p2pCtx := tss.NewPeerContext(pIDs)

	keygens := make([]*Keygen, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(hub.brokers[i])

		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err)
		keygens[i] = kg
	}

	keys := make([]*Key, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case k := <-keygens[i].Done:
			keys[i] = k
		case err := <-keygens[i].Err:
			t.Fatalf("Keygen error for party %d: %v", i, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("Keygen timed out for party %d", i)
		}
	}

	// --- PHASE 2: Signing ---
	msg := big.NewInt(42)

	// create new hub for signing
	signHub := newTestHub(partyCount)

	signings := make([]*Signing, partyCount)
	for i := 0; i < partyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, pIDs[i], partyCount, threshold)
		params.SetBroker(signHub.brokers[i])

		sg, err := keys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err, "NewSigning should not fail for party %d", i)
		signings[i] = sg
	}

	// collect signature results
	sigs := make([]*SignatureData, partyCount)
	for i := 0; i < partyCount; i++ {
		select {
		case sig := <-signings[i].Done:
			sigs[i] = sig
			t.Logf("Party %d completed signing", i)
		case err := <-signings[i].Err:
			t.Fatalf("Party %d signing error: %v", i, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("Party %d signing timed out", i)
		}
	}

	// verify all parties produced the same signature
	for i := 1; i < partyCount; i++ {
		assert.Equal(t, sigs[0].Signature, sigs[i].Signature,
			"party 0 and party %d should have the same signature", i)
	}

	// verify signature length is 64 bytes
	assert.Len(t, sigs[0].Signature, 64, "signature should be 64 bytes")

	t.Logf("All parties completed signing, signature: %x", sigs[0].Signature)
}

func TestResharing(t *testing.T) {
	const (
		oldPartyCount = 3
		oldThreshold  = 1
		newPartyCount = 5
		newThreshold  = 2
	)

	// --- PHASE 1: Keygen with old committee ---
	oldPIDs := tss.GenerateTestPartyIDs(oldPartyCount)
	kgHub := newTestHub(oldPartyCount)
	oldP2PCtx := tss.NewPeerContext(oldPIDs)

	keygens := make([]*Keygen, oldPartyCount)
	for i := 0; i < oldPartyCount; i++ {
		params := tss.NewParameters(tss.Edwards(), oldP2PCtx, oldPIDs[i], oldPartyCount, oldThreshold)
		params.SetBroker(kgHub.brokers[i])

		kg, err := NewKeygen(context.Background(), params)
		require.NoError(t, err, "NewKeygen should not fail for party %d", i)
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
		case <-time.After(30 * time.Second):
			t.Fatalf("Old party %d keygen timed out", i)
		}
	}

	// Verify all old parties got the same public key
	for i := 1; i < oldPartyCount; i++ {
		require.True(t, oldKeys[0].EDDSAPub.Equals(oldKeys[i].EDDSAPub),
			"old party 0 and party %d should have the same public key", i)
	}
	originalPub := oldKeys[0].EDDSAPub
	t.Logf("Keygen complete. EDDSAPub: (%s, %s)", originalPub.X(), originalPub.Y())

	// --- PHASE 2: Resharing from old committee to new committee ---
	// No overlap between committees for simplicity
	newPIDs := tss.GenerateTestPartyIDs(newPartyCount)
	newP2PCtx := tss.NewPeerContext(newPIDs)

	rsHub := newResharingHub()

	// Add all old and new parties to the resharing hub
	oldBrokers := make([]*resharingBroker, oldPartyCount)
	for i, pid := range oldPIDs {
		oldBrokers[i] = rsHub.addParty(pid)
	}
	newBrokers := make([]*resharingBroker, newPartyCount)
	for i, pid := range newPIDs {
		newBrokers[i] = rsHub.addParty(pid)
	}

	totalParties := oldPartyCount + newPartyCount
	resharings := make([]*Resharing, totalParties)

	// Start old committee resharing parties
	for i := 0; i < oldPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.Edwards(), oldP2PCtx, newP2PCtx, oldPIDs[i], oldPartyCount, oldThreshold, newPartyCount, newThreshold)
		params.SetBroker(oldBrokers[i])

		rs, err := NewResharing(context.Background(), params, oldKeys[i])
		require.NoError(t, err, "NewResharing should not fail for old party %d", i)
		resharings[i] = rs
	}

	// Start new committee resharing parties
	for i := 0; i < newPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.Edwards(), oldP2PCtx, newP2PCtx, newPIDs[i], oldPartyCount, oldThreshold, newPartyCount, newThreshold)
		params.SetBroker(newBrokers[i])

		rs, err := NewResharing(context.Background(), params, nil)
		require.NoError(t, err, "NewResharing should not fail for new party %d", i)
		resharings[oldPartyCount+i] = rs
	}

	// Collect resharing results
	newKeys := make([]*Key, newPartyCount)
	for i := 0; i < totalParties; i++ {
		select {
		case k := <-resharings[i].Done:
			if i < oldPartyCount {
				// Old party: key should be nil (Xi zeroed)
				assert.Nil(t, k, "old party %d should get nil key", i)
				t.Logf("Old party %d completed resharing (Xi zeroed)", i)
			} else {
				// New party: should get new key
				require.NotNil(t, k, "new party %d should get a key", i-oldPartyCount)
				newKeys[i-oldPartyCount] = k
				t.Logf("New party %d completed resharing", i-oldPartyCount)
			}
		case err := <-resharings[i].Err:
			t.Fatalf("Party %d resharing error: %v", i, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("Party %d resharing timed out", i)
		}
	}

	// Verify all new parties have the same EDDSAPub as original
	for i := 0; i < newPartyCount; i++ {
		require.True(t, originalPub.Equals(newKeys[i].EDDSAPub),
			"new party %d should have the original EDDSAPub", i)
	}
	t.Log("Resharing complete. All new parties have the original EDDSAPub.")

	// --- PHASE 3: Sign with new committee ---
	msg := big.NewInt(42)
	signHub := newTestHub(newPartyCount)

	signings := make([]*Signing, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		signCtx := tss.NewPeerContext(newPIDs)
		params := tss.NewParameters(tss.Edwards(), signCtx, newPIDs[i], newPartyCount, newThreshold)
		params.SetBroker(signHub.brokers[i])

		sg, err := newKeys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err, "NewSigning should not fail for new party %d", i)
		signings[i] = sg
	}

	// Collect signatures
	sigs := make([]*SignatureData, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		select {
		case sig := <-signings[i].Done:
			sigs[i] = sig
			t.Logf("New party %d completed signing", i)
		case err := <-signings[i].Err:
			t.Fatalf("New party %d signing error: %v", i, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("New party %d signing timed out", i)
		}
	}

	// Verify all parties produced the same signature
	for i := 1; i < newPartyCount; i++ {
		assert.Equal(t, sigs[0].Signature, sigs[i].Signature,
			"new party 0 and party %d should have the same signature", i)
	}

	assert.Len(t, sigs[0].Signature, 64, "signature should be 64 bytes")
	t.Logf("Resharing + Signing complete. Signature: %x", sigs[0].Signature)
}
