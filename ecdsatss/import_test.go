package ecdsatss

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestImportKeyReshareAndSign imports a pre-existing secp256k1 ECDSA key as a
// trivial 1-of-1 share, reshares it into a real t-of-n committee, and verifies
// the new committee can produce signatures that validate under the original
// public key.
func TestImportKeyReshareAndSign(t *testing.T) {
	const (
		newPartyCount = 3
		newThreshold  = 1 // t+1 = 2 signers needed
	)

	// --- PHASE 1: Import an existing ECDSA key as a 1-of-1 share ---
	priv, err := ecdsa.GenerateKey(tss.S256(), rand.Reader)
	require.NoError(t, err, "GenerateKey should not fail")

	oldPIDs := tss.GenerateTestPartyIDs(1)
	require.Len(t, oldPIDs, 1)
	oldPID := oldPIDs[0]

	oldKey, err := ImportKey(priv, oldPID)
	require.NoError(t, err, "ImportKey should succeed on a valid key")
	require.NotNil(t, oldKey.ECDSAPub)
	require.Equal(t, 0, oldKey.Xi.Cmp(priv.D), "Xi should equal the imported scalar")
	require.Equal(t, oldPID.KeyInt().Bytes(), oldKey.ShareID.Bytes(), "ShareID should be the PartyID KeyInt")
	require.Len(t, oldKey.Ks, 1)
	require.Equal(t, 0, oldKey.ECDSAPub.X().Cmp(priv.PublicKey.X), "ECDSAPub.X must match priv.PublicKey.X")
	require.Equal(t, 0, oldKey.ECDSAPub.Y().Cmp(priv.PublicKey.Y), "ECDSAPub.Y must match priv.PublicKey.Y")

	originalPub := oldKey.ECDSAPub

	// --- PHASE 2: Generate pre-params for the new committee only ---
	// The single old party is just feeding a known scalar in; it has no Paillier/NTilde
	// material and doesn't need any. The new committee generates theirs fresh.
	t.Log("Generating pre-parameters for new committee...")
	newPreParams := make([]LocalPreParams, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		pp, err := GeneratePreParams(5*time.Minute, 4)
		require.NoError(t, err, "GeneratePreParams should not fail for new party %d", i)
		newPreParams[i] = *pp
		t.Logf("New party %d pre-params generated", i)
	}

	// --- PHASE 3: Reshare from the 1-party importer into the new t-of-n committee ---
	oldP2PCtx := tss.NewPeerContext(oldPIDs)

	// Offset new PIDs so they cannot collide with the old PID's KeyInt.
	newPIDsUnsorted := make(tss.UnSortedPartyIDs, 0, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		newPIDsUnsorted = append(newPIDsUnsorted, tss.NewPartyID(
			fmt.Sprintf("new-%d", i),
			fmt.Sprintf("new-moniker-%d", i),
			new(big.Int).SetInt64(int64(1000+i)),
		))
	}
	newPIDs := tss.SortPartyIDs(newPIDsUnsorted)
	newP2PCtx := tss.NewPeerContext(newPIDs)

	allPartyIDs := make([]*tss.PartyID, 0, 1+newPartyCount)
	allPartyIDs = append(allPartyIDs, oldPID)
	allPartyIDs = append(allPartyIDs, newPIDs...)
	reshareHub := newResharingHub(allPartyIDs)

	resharings := make([]*Resharing, 1+newPartyCount)

	// Sole old party: oldPartyCount=1, oldThreshold=0.
	oldParams := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, oldPID, 1, 0, newPartyCount, newThreshold)
	oldParams.SetNoProofMod()
	oldParams.SetNoProofFac()
	oldParams.SetBroker(reshareHub.brokerFor(oldPID))
	rs, err := NewResharing(context.Background(), oldParams, oldKey)
	require.NoError(t, err, "NewResharing should not fail for importing old party")
	resharings[0] = rs

	for i := 0; i < newPartyCount; i++ {
		params := tss.NewReSharingParameters(tss.S256(), oldP2PCtx, newP2PCtx, newPIDs[i], 1, 0, newPartyCount, newThreshold)
		params.SetNoProofMod()
		params.SetNoProofFac()
		params.SetBroker(reshareHub.brokerFor(newPIDs[i]))

		rs, err := NewResharing(context.Background(), params, nil, newPreParams[i])
		require.NoError(t, err, "NewResharing should not fail for new party %d", i)
		resharings[1+i] = rs
	}

	newKeys := make([]*Key, newPartyCount)
	for i := 0; i < 1+newPartyCount; i++ {
		select {
		case k := <-resharings[i].Done:
			if i == 0 {
				// Old party returns its (Xi-zeroed) Key rather than nil, matching eddsatss test convention.
				require.NotNil(t, k, "old party should receive its Xi-zeroed key")
				assert.Equal(t, int64(0), k.Xi.Int64(), "old party Xi must be zeroed after resharing")
			} else {
				require.NotNil(t, k, "new party %d should get a key", i-1)
				newKeys[i-1] = k
			}
		case err := <-resharings[i].Err:
			t.Fatalf("Party %d resharing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("Party %d resharing timed out", i)
		}
	}

	// All new parties must agree on the imported public key.
	for i := 0; i < newPartyCount; i++ {
		require.True(t, originalPub.Equals(newKeys[i].ECDSAPub),
			"new party %d must have the imported ECDSAPub", i)
	}
	t.Log("Resharing completed: new committee has the imported public key")

	// --- PHASE 4: Sign with the new committee ---
	msgHash := sha256.Sum256([]byte("import test"))
	msg := new(big.Int).SetBytes(msgHash[:])

	signHub := newTestHub(newPartyCount)
	signings := make([]*Signing, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		params := tss.NewParameters(tss.S256(), newP2PCtx, newPIDs[i], newPartyCount, newThreshold)
		params.SetBroker(signHub.brokers[i])

		sg, err := newKeys[i].NewSigning(context.Background(), msg, params)
		require.NoError(t, err, "NewSigning should not fail for new party %d", i)
		signings[i] = sg
	}

	sigDatas := make([]*SignatureData, newPartyCount)
	for i := 0; i < newPartyCount; i++ {
		select {
		case sd := <-signings[i].Done:
			sigDatas[i] = sd
		case err := <-signings[i].Err:
			t.Fatalf("New party %d signing error: %v", i, err)
		case <-time.After(5 * time.Minute):
			t.Fatalf("New party %d signing timed out", i)
		}
	}

	// --- PHASE 5: Verify the ECDSA signature under the original ecdsa.PublicKey ---
	r := new(big.Int).SetBytes(sigDatas[0].R)
	s := new(big.Int).SetBytes(sigDatas[0].S)
	ok := ecdsa.Verify(&priv.PublicKey, msgHash[:], r, s)
	assert.True(t, ok, "threshold signature from the imported key must verify under the original PublicKey")

	t.Logf("Import + reshare + sign complete. r=%x s=%x", sigDatas[0].R, sigDatas[0].S)
}

// TestImportKeyRejectsInvalidInput covers the defensive checks in ImportKey.
func TestImportKeyRejectsInvalidInput(t *testing.T) {
	goodPID := tss.GenerateTestPartyIDs(1)[0]
	goodPriv, err := ecdsa.GenerateKey(tss.S256(), rand.Reader)
	require.NoError(t, err)

	_, err = ImportKey(nil, goodPID)
	assert.Error(t, err, "nil priv should error")

	_, err = ImportKey(&ecdsa.PrivateKey{}, goodPID)
	assert.Error(t, err, "priv with no D/Curve should error")

	zero := &ecdsa.PrivateKey{D: big.NewInt(0), PublicKey: ecdsa.PublicKey{Curve: tss.S256()}}
	_, err = ImportKey(zero, goodPID)
	assert.Error(t, err, "D=0 should error")

	// PublicKey mismatch: use a valid priv but set its PublicKey to a different point.
	mismatched := &ecdsa.PrivateKey{
		D: goodPriv.D,
		PublicKey: ecdsa.PublicKey{
			Curve: tss.S256(),
			X:     big.NewInt(1),
			Y:     big.NewInt(2),
		},
	}
	_, err = ImportKey(mismatched, goodPID)
	assert.Error(t, err, "mismatched PublicKey should error")

	_, err = ImportKey(goodPriv, nil)
	assert.Error(t, err, "nil partyID should error")
}
