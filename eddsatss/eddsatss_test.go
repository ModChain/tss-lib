package eddsatss

import (
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

		kg, err := NewKeygen(params)
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

		kg, err := NewKeygen(params)
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

		sg, err := keys[i].NewSigning(msg, params)
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
