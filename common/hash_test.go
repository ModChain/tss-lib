package common_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ModChain/tss-lib/v2/common"
)

func TestSHA512_256(t *testing.T) {
	result := common.SHA512_256([]byte("hello"), []byte("world"))
	assert.NotNil(t, result)
	assert.Equal(t, 32, len(result), "SHA-512/256 should produce 32 bytes")
}

func TestSHA512_256Empty(t *testing.T) {
	result := common.SHA512_256()
	assert.Nil(t, result, "empty input should return nil")
}

func TestSHA512_256iDeterministic(t *testing.T) {
	a := common.SHA512_256i(big.NewInt(42), big.NewInt(100))
	b := common.SHA512_256i(big.NewInt(42), big.NewInt(100))
	assert.Equal(t, a, b, "same inputs should produce same hash")
}

func TestSHA512_256iDifferentInputs(t *testing.T) {
	a := common.SHA512_256i(big.NewInt(1), big.NewInt(2))
	b := common.SHA512_256i(big.NewInt(2), big.NewInt(1))
	assert.NotEqual(t, a, b, "different input order should produce different hash")
}

func TestSHA512_256iTaggedDeterministic(t *testing.T) {
	tag := []byte("test-tag")
	a := common.SHA512_256i_TAGGED(tag, big.NewInt(42))
	b := common.SHA512_256i_TAGGED(tag, big.NewInt(42))
	assert.Equal(t, a, b, "same inputs should produce same hash")
}

func TestSHA512_256iTaggedDifferentTags(t *testing.T) {
	a := common.SHA512_256i_TAGGED([]byte("tag1"), big.NewInt(42))
	b := common.SHA512_256i_TAGGED([]byte("tag2"), big.NewInt(42))
	assert.NotEqual(t, a, b, "different tags should produce different hash")
}

func TestSHA512_256iOneNil(t *testing.T) {
	result := common.SHA512_256iOne(nil)
	assert.Nil(t, result, "nil input should return nil")
}

func TestSHA512_256iOneHappy(t *testing.T) {
	result := common.SHA512_256iOne(big.NewInt(42))
	assert.NotNil(t, result)
	assert.True(t, result.Sign() > 0)
}
