package crypto_test

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/KarpelesLab/tss-lib/v2/common"
	. "github.com/KarpelesLab/tss-lib/v2/crypto"
)

func TestGenerateNTildei(t *testing.T) {
	sgps, err := common.GetRandomSafePrimesConcurrent(context.Background(), 256, 2, 4, rand.Reader)
	require.NoError(t, err)
	primes := [2]*big.Int{sgps[0].SafePrime(), sgps[1].SafePrime()}

	N, h1, h2, err := GenerateNTildei(rand.Reader, primes)
	require.NoError(t, err)
	assert.NotNil(t, N)
	assert.NotNil(t, h1)
	assert.NotNil(t, h2)
	expected := new(big.Int).Mul(primes[0], primes[1])
	assert.Equal(t, 0, N.Cmp(expected))
}

func TestGenerateNTildeiNilPrimes(t *testing.T) {
	_, _, _, err := GenerateNTildei(rand.Reader, [2]*big.Int{nil, big.NewInt(7)})
	assert.Error(t, err)

	_, _, _, err = GenerateNTildei(rand.Reader, [2]*big.Int{big.NewInt(7), nil})
	assert.Error(t, err)
}

func TestGenerateNTildeiNotPrime(t *testing.T) {
	_, _, _, err := GenerateNTildei(rand.Reader, [2]*big.Int{big.NewInt(4), big.NewInt(6)})
	assert.Error(t, err)
}
