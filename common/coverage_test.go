package common

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRandomBytes(t *testing.T) {
	buf, err := GetRandomBytes(rand.Reader, 32)
	require.NoError(t, err)
	assert.Equal(t, 32, len(buf))

	// nil reader falls back to crypto/rand
	buf2, err := GetRandomBytes(nil, 16)
	require.NoError(t, err)
	assert.Equal(t, 16, len(buf2))

	// invalid length
	_, err = GetRandomBytes(rand.Reader, 0)
	assert.Error(t, err)

	_, err = GetRandomBytes(rand.Reader, -1)
	assert.Error(t, err)
}

func TestGetRandomGeneratorOfTheQuadraticResidue(t *testing.T) {
	// Use two small safe primes: 5 (from q=2, p=5) and 11 (from q=5, p=11)
	p := big.NewInt(5)
	q := big.NewInt(11)
	n := new(big.Int).Mul(p, q)

	gen := GetRandomGeneratorOfTheQuadraticResidue(rand.Reader, n)
	assert.NotNil(t, gen)
	assert.True(t, gen.Sign() > 0)
	assert.True(t, gen.Cmp(n) < 0)
}

func TestGetRandomQuadraticNonResidue(t *testing.T) {
	// n must be odd and > 2
	n := big.NewInt(55) // 5 * 11
	w := GetRandomQuadraticNonResidue(rand.Reader, n)
	assert.NotNil(t, w)
	assert.Equal(t, -1, big.Jacobi(w, n))
}

func TestPadToLengthBytesInPlace(t *testing.T) {
	src := []byte{0x01, 0x02, 0x03}
	padded := PadToLengthBytesInPlace(src, 5)
	assert.Equal(t, 5, len(padded))
	assert.Equal(t, byte(0), padded[0])
	assert.Equal(t, byte(0), padded[1])
	assert.Equal(t, byte(0x01), padded[2])

	// no padding needed
	src2 := []byte{0x01, 0x02, 0x03}
	notPadded := PadToLengthBytesInPlace(src2, 3)
	assert.Equal(t, 3, len(notPadded))
	assert.Equal(t, byte(0x01), notPadded[0])

	// already longer
	src3 := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	same := PadToLengthBytesInPlace(src3, 3)
	assert.Equal(t, 5, len(same))
}

func TestGermainSafePrimeAccessors(t *testing.T) {
	// q = 11 is a Sophie Germain prime, p = 23 = 2*11 + 1 is the safe prime
	q := big.NewInt(11)
	p := big.NewInt(23)
	gsp := &GermainSafePrime{q: q, p: p}

	assert.Equal(t, q, gsp.Prime())
	assert.Equal(t, p, gsp.SafePrime())
	assert.True(t, gsp.Validate())
}

func TestGermainSafePrimeValidateFails(t *testing.T) {
	// q = 10 is not prime
	gsp := &GermainSafePrime{q: big.NewInt(10), p: big.NewInt(21)}
	assert.False(t, gsp.Validate())
}

func TestGetRandomPrimeInt(t *testing.T) {
	p := GetRandomPrimeInt(rand.Reader, 64)
	assert.NotNil(t, p)
	assert.True(t, p.ProbablyPrime(20))

	// invalid bits
	assert.Nil(t, GetRandomPrimeInt(rand.Reader, 0))
	assert.Nil(t, GetRandomPrimeInt(rand.Reader, -1))
}

func TestGetRandomPositiveInt(t *testing.T) {
	bound := big.NewInt(1000)
	v := GetRandomPositiveInt(rand.Reader, bound)
	assert.NotNil(t, v)
	assert.True(t, v.Cmp(bound) < 0)

	// nil/zero bound
	assert.Nil(t, GetRandomPositiveInt(rand.Reader, nil))
	assert.Nil(t, GetRandomPositiveInt(rand.Reader, big.NewInt(0)))
	assert.Nil(t, GetRandomPositiveInt(rand.Reader, big.NewInt(-1)))
}

func TestIsNumberInMultiplicativeGroup(t *testing.T) {
	n := big.NewInt(15) // 3*5
	assert.True(t, IsNumberInMultiplicativeGroup(n, big.NewInt(7)))
	assert.True(t, IsNumberInMultiplicativeGroup(n, big.NewInt(1)))
	assert.False(t, IsNumberInMultiplicativeGroup(n, big.NewInt(3)))  // gcd(3,15)=3
	assert.False(t, IsNumberInMultiplicativeGroup(n, big.NewInt(15))) // v >= n
	assert.False(t, IsNumberInMultiplicativeGroup(n, big.NewInt(0)))  // v < 1
	assert.False(t, IsNumberInMultiplicativeGroup(nil, big.NewInt(1)))
	assert.False(t, IsNumberInMultiplicativeGroup(n, nil))
}

func TestGetRandomPositiveRelativelyPrimeInt(t *testing.T) {
	n := big.NewInt(100)
	v := GetRandomPositiveRelativelyPrimeInt(rand.Reader, n)
	assert.NotNil(t, v)
	gcd := new(big.Int).GCD(nil, nil, v, n)
	assert.Equal(t, 0, gcd.Cmp(big.NewInt(1)))

	assert.Nil(t, GetRandomPositiveRelativelyPrimeInt(rand.Reader, nil))
	assert.Nil(t, GetRandomPositiveRelativelyPrimeInt(rand.Reader, big.NewInt(0)))
}

func TestMustGetRandomIntPanics(t *testing.T) {
	assert.Panics(t, func() { MustGetRandomInt(rand.Reader, 0) })
	assert.Panics(t, func() { MustGetRandomInt(rand.Reader, -1) })
	assert.Panics(t, func() { MustGetRandomInt(rand.Reader, 5001) })
}
