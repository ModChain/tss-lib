package common_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ModChain/tss-lib/v2/common"
)

func TestModIntArithmetic(t *testing.T) {
	mod := big.NewInt(97)
	modN := common.ModInt(mod)

	// Add
	result := modN.Add(big.NewInt(50), big.NewInt(60))
	assert.Equal(t, big.NewInt(13), result, "50+60 mod 97 = 13")

	// Sub
	result = modN.Sub(big.NewInt(10), big.NewInt(30))
	expected := new(big.Int).Mod(new(big.Int).Sub(big.NewInt(10), big.NewInt(30)), mod)
	assert.Equal(t, expected, result)

	// Mul
	result = modN.Mul(big.NewInt(10), big.NewInt(10))
	assert.Equal(t, big.NewInt(3), result, "10*10 mod 97 = 3")

	// Exp
	result = modN.Exp(big.NewInt(2), big.NewInt(10))
	assert.Equal(t, big.NewInt(54), result, "2^10 mod 97 = 54")

	// ModInverse
	result = modN.ModInverse(big.NewInt(2))
	assert.NotNil(t, result)
	product := modN.Mul(big.NewInt(2), result)
	assert.Equal(t, big.NewInt(1), product, "2 * inv(2) mod 97 = 1")
}

func TestModIntDivValidDivisor(t *testing.T) {
	mod := big.NewInt(97)
	modN := common.ModInt(mod)
	result := modN.Div(big.NewInt(10), big.NewInt(2))
	assert.Equal(t, big.NewInt(5), result, "10/2 mod 97 = 5")
}

func TestIsInInterval(t *testing.T) {
	assert.True(t, common.IsInInterval(big.NewInt(5), big.NewInt(10)))
	assert.True(t, common.IsInInterval(big.NewInt(0), big.NewInt(10)))
	assert.False(t, common.IsInInterval(big.NewInt(10), big.NewInt(10)))
	assert.False(t, common.IsInInterval(big.NewInt(-1), big.NewInt(10)))
	assert.False(t, common.IsInInterval(big.NewInt(11), big.NewInt(10)))
}

func TestAppendBigIntToBytesSlice(t *testing.T) {
	prefix := []byte{0x01, 0x02}
	val := big.NewInt(256) // 0x0100
	result := common.AppendBigIntToBytesSlice(prefix, val)
	assert.Equal(t, []byte{0x01, 0x02, 0x01, 0x00}, result)
}
