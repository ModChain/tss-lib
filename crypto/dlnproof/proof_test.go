package dlnproof

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/common"
)

// setupDLNParams mirrors the real keygen flow:
// generate two safe primes P=2p+1, Q=2q+1, then N=P*Q,
// and pass the Sophie Germain primes (p, q) to NewDLNProof.
func setupDLNParams(t *testing.T) (h1, h2, alpha, p, q, N *big.Int) {
	t.Helper()
	sgps, err := common.GetRandomSafePrimesConcurrent(context.Background(), 256, 2, 4, rand.Reader)
	require.NoError(t, err)
	require.Len(t, sgps, 2)

	P := sgps[0].SafePrime()
	Q := sgps[1].SafePrime()
	N = new(big.Int).Mul(P, Q)
	modN := common.ModInt(N)

	p = sgps[0].Prime()
	q = sgps[1].Prime()
	modPQ := common.ModInt(new(big.Int).Mul(p, q))

	f1 := common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, N)
	alpha = common.GetRandomPositiveRelativelyPrimeInt(rand.Reader, N)
	beta := modPQ.ModInverse(alpha)
	_ = beta
	h1 = modN.Mul(f1, f1)
	h2 = modN.Exp(h1, alpha)
	return
}

func TestNewDLNProofAndVerify(t *testing.T) {
	h1, h2, alpha, p, q, N := setupDLNParams(t)

	proof := NewDLNProof(h1, h2, alpha, p, q, N, rand.Reader)
	assert.NotNil(t, proof)

	assert.True(t, proof.Verify(h1, h2, N))

	// nil proof
	var nilProof *Proof
	assert.False(t, nilProof.Verify(h1, h2, N))
}

func TestDLNProofSerializeAndUnmarshal(t *testing.T) {
	h1, h2, alpha, p, q, N := setupDLNParams(t)

	proof := NewDLNProof(h1, h2, alpha, p, q, N, rand.Reader)

	bzs, err := proof.Serialize()
	require.NoError(t, err)
	assert.NotEmpty(t, bzs)

	restored, err := UnmarshalDLNProof(bzs)
	require.NoError(t, err)
	assert.NotNil(t, restored)

	assert.True(t, restored.Verify(h1, h2, N))
}

func TestDLNProofVerifyEdgeCases(t *testing.T) {
	h1, h2, alpha, p, q, N := setupDLNParams(t)

	proof := NewDLNProof(h1, h2, alpha, p, q, N, rand.Reader)

	// N <= 0
	assert.False(t, proof.Verify(h1, h2, big.NewInt(0)))
	assert.False(t, proof.Verify(h1, h2, big.NewInt(-1)))

	// h1 = h2
	assert.False(t, proof.Verify(h1, h1, N))

	// h1 = 1 (invalid)
	assert.False(t, proof.Verify(big.NewInt(1), h2, N))
}
