package mldsatss

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/KarpelesLab/mldsa"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// --- test hub broker (copied from ecdsatss) ---

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
	h := &testHub{brokers: make([]*hubBroker, n)}
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
			fmt.Printf("hubBroker: queued delivery error for party %d type %s: %v\n",
				b.partyIdx, typ, err)
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

// --- helpers ---

// buildCommittee returns (partyIDs, committee peer ctx, keyIds) — the first T
// of N keygen parties, in ascending Id order.
func buildCommittee(n, t int) (tss.SortedPartyIDs, *tss.PeerContext, []uint8) {
	pids := make(tss.UnSortedPartyIDs, 0, t)
	keyIds := make([]uint8, 0, t)
	for i := 0; i < t; i++ {
		keyIds = append(keyIds, uint8(i))
		pids = append(pids, tss.NewPartyID(fmt.Sprintf("%d", i), fmt.Sprintf("P[%d]", i), big.NewInt(int64(i+1))))
	}
	sorted := tss.SortPartyIDs(pids)
	return sorted, tss.NewPeerContext(sorted), keyIds
}

// runOneAttempt runs a single 3-round signing exchange. Returns the signature
// produced by party 0, or an error if any party failed.
func runOneAttempt(t *testing.T, attemptID uint32, allKeys []*Key44, keyIds []uint8, signers tss.SortedPartyIDs, tParams *ThresholdParams44, msg, msgCtx []byte) ([]byte, error) {
	t.Helper()
	hub := newTestHub(len(signers))
	p2pCtx := tss.NewPeerContext(signers)

	sigs := make([]*Signing44, len(signers))
	for i, pid := range signers {
		params, err := NewParameters(pid, p2pCtx, tParams, keyIds, hub.brokers[i])
		require.NoError(t, err)
		params.SetAttemptID(attemptID)

		key := allKeys[keyIds[i]]
		s, err := NewSigning44(context.Background(), params, key, msg, msgCtx)
		require.NoError(t, err)
		sigs[i] = s
	}

	deadline := time.After(30 * time.Second)
	results := make([][]byte, len(signers))
	var firstErr error
	for i := range sigs {
		select {
		case sd := <-sigs[i].Done:
			results[i] = sd.Signature
		case err := <-sigs[i].Err:
			if firstErr == nil {
				firstErr = err
			}
		case <-deadline:
			t.Fatalf("party %d timed out", i)
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	// All parties must emit the same signature bytes.
	for i := 1; i < len(results); i++ {
		if string(results[i]) != string(results[0]) {
			return nil, fmt.Errorf("parties emitted divergent signatures")
		}
	}
	return results[0], nil
}

// signWithRetry runs up to maxAttempts 3-round exchanges, each with a fresh
// attempt id, until one succeeds.
func signWithRetry(t *testing.T, allKeys []*Key44, keyIds []uint8, signers tss.SortedPartyIDs, tParams *ThresholdParams44, msg, msgCtx []byte, maxAttempts int) ([]byte, int, error) {
	t.Helper()
	for a := 0; a < maxAttempts; a++ {
		sig, err := runOneAttempt(t, uint32(a), allKeys, keyIds, signers, tParams, msg, msgCtx)
		if err == nil {
			return sig, a + 1, nil
		}
		if err != ErrAllTriesRejected {
			return nil, 0, err
		}
	}
	return nil, maxAttempts, fmt.Errorf("exhausted %d attempts", maxAttempts)
}

// --- the actual tests ---

func TestTrustedDealerKeygen44_Smoke(t *testing.T) {
	var seed [32]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	params, err := GetThresholdParams44(2, 2)
	require.NoError(t, err)
	pk, keys, err := TrustedDealerKeygen44(seed, params)
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.Len(t, keys, 2)

	// Both keys share the same Rho / Tr / T1.
	require.Equal(t, keys[0].Rho, keys[1].Rho)
	require.Equal(t, keys[0].Tr, keys[1].Tr)
	require.Equal(t, keys[0].T1, keys[1].T1)

	// Each party's Id must correspond to every share mask it holds.
	for _, k := range keys {
		for m := range k.Shares {
			require.NotZero(t, m&(1<<k.Id))
		}
	}

	// pk should have the exact byte size.
	require.Equal(t, mldsa.PublicKeySize44, len(pk.Bytes()))
}

func TestSigning44_TN22(t *testing.T) {
	var seed [32]byte
	seed[0] = 0x42
	tParams, err := GetThresholdParams44(2, 2)
	require.NoError(t, err)
	pk, keys, err := TrustedDealerKeygen44(seed, tParams)
	require.NoError(t, err)

	signers, _, keyIds := buildCommittee(2, 2)
	msg := []byte("hello threshold dilithium")
	ctx := []byte("test-ctx")

	sig, attempts, err := signWithRetry(t, keys, keyIds, signers, tParams, msg, ctx, 256)
	require.NoError(t, err, "signing must succeed within attempts")
	t.Logf("succeeded after %d attempt(s), signature size = %d", attempts, len(sig))
	require.Equal(t, mldsa.SignatureSize44, len(sig))

	ok := pk.Verify(sig, msg, ctx)
	require.True(t, ok, "stock FIPS 204 verify must accept the threshold signature")
}

func TestSigning44_AllPairs(t *testing.T) {
	cases := []struct {
		n, t_ int
	}{
		{2, 2}, {3, 2}, {3, 3}, {4, 2}, {4, 3}, {4, 4},
		{5, 2}, {5, 3}, {5, 4}, {5, 5},
		{6, 2}, {6, 3}, {6, 4}, {6, 6},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("t%d_n%d", c.t_, c.n), func(t *testing.T) {
			var seed [32]byte
			seed[0] = byte(c.n<<4 | c.t_)
			tParams, err := GetThresholdParams44(c.t_, c.n)
			require.NoError(t, err)
			pk, keys, err := TrustedDealerKeygen44(seed, tParams)
			require.NoError(t, err)

			signers, _, keyIds := buildCommittee(c.n, c.t_)
			msg := []byte(fmt.Sprintf("message-%d-%d", c.t_, c.n))
			sig, attempts, err := signWithRetry(t, keys, keyIds, signers, tParams, msg, nil, 128)
			require.NoError(t, err)
			t.Logf("(t=%d, n=%d) succeeded after %d attempt(s)", c.t_, c.n, attempts)
			require.Equal(t, mldsa.SignatureSize44, len(sig))
			require.True(t, pk.Verify(sig, msg, nil))
		})
	}
}

func TestSigning44_BadContextMismatch(t *testing.T) {
	// A signature produced for context A must not verify under context B.
	var seed [32]byte
	seed[0] = 0x7
	tParams, _ := GetThresholdParams44(2, 2)
	pk, keys, _ := TrustedDealerKeygen44(seed, tParams)
	signers, _, keyIds := buildCommittee(2, 2)
	msg := []byte("ctx-mismatch test")
	sig, _, err := signWithRetry(t, keys, keyIds, signers, tParams, msg, []byte("ctx-A"), 128)
	require.NoError(t, err)
	require.True(t, pk.Verify(sig, msg, []byte("ctx-A")))
	require.False(t, pk.Verify(sig, msg, []byte("ctx-B")))
	require.False(t, pk.Verify(sig, []byte("other msg"), []byte("ctx-A")))
}
