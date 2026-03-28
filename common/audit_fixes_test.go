package common_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/KarpelesLab/tss-lib/v2/common"
)

// TestRejectionSampleDoesNotMutateInput verifies that RejectionSample does not
// modify the input eHash (previously it called eHash.Mod(eHash, q) which mutated eHash).
func TestRejectionSampleDoesNotMutateInput(t *testing.T) {
	q := big.NewInt(97)
	eHash := big.NewInt(200)
	originalHash := new(big.Int).Set(eHash)

	_ = common.RejectionSample(q, eHash)

	assert.Equal(t, originalHash, eHash, "RejectionSample must not mutate eHash input")
}

// TestRejectionSampleResultInRange verifies the output is always in [0, q).
func TestRejectionSampleResultInRange(t *testing.T) {
	q := common.GetRandomPrimeInt(rand.Reader, 128)
	for i := 0; i < 100; i++ {
		hash := common.MustGetRandomInt(rand.Reader, 256)
		result := common.RejectionSample(q, hash)
		assert.True(t, result.Cmp(q) < 0, "result must be < q")
		assert.True(t, result.Sign() >= 0, "result must be >= 0")
	}
}

// TestSHA512_256iNilInput verifies that SHA512_256i handles nil *big.Int values
// without panicking (previously it would panic on n.Bytes() with nil n).
func TestSHA512_256iNilInput(t *testing.T) {
	assert.NotPanics(t, func() {
		result := common.SHA512_256i(nil, big.NewInt(42))
		assert.NotNil(t, result, "should produce a hash even with nil input")
	})

	assert.NotPanics(t, func() {
		result := common.SHA512_256i(big.NewInt(1), nil, big.NewInt(3))
		assert.NotNil(t, result, "should produce a hash even with nil input in the middle")
	})
}

// TestModIntDivByZero verifies that modInt.Div handles zero divisor gracefully.
func TestModIntDivByZero(t *testing.T) {
	mod := big.NewInt(97)
	modN := common.ModInt(mod)

	result := modN.Div(big.NewInt(10), big.NewInt(0))
	assert.Nil(t, result, "Div by zero should return nil")

	result = modN.Div(big.NewInt(10), nil)
	assert.Nil(t, result, "Div by nil should return nil")
}
