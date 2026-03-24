package common_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ModChain/tss-lib/v2/common"
)

func TestBigIntsToBytes(t *testing.T) {
	ints := []*big.Int{big.NewInt(1), big.NewInt(256)}
	result := common.BigIntsToBytes(ints)
	assert.Len(t, result, 2)
	assert.Equal(t, big.NewInt(1).Bytes(), result[0])
	assert.Equal(t, big.NewInt(256).Bytes(), result[1])
}

func TestMultiBytesToBigInts(t *testing.T) {
	bzs := [][]byte{big.NewInt(1).Bytes(), big.NewInt(256).Bytes()}
	result := common.MultiBytesToBigInts(bzs)
	assert.Len(t, result, 2)
	assert.Equal(t, big.NewInt(1), result[0])
	assert.Equal(t, big.NewInt(256), result[1])
}

func TestNonEmptyBytes(t *testing.T) {
	assert.True(t, common.NonEmptyBytes(big.NewInt(1).Bytes()))
	assert.False(t, common.NonEmptyBytes(big.NewInt(0).Bytes()), "big.NewInt(0).Bytes() is empty")
	assert.False(t, common.NonEmptyBytes(nil))
	assert.False(t, common.NonEmptyBytes([]byte{}))
}

func TestNonEmptyMultiBytes(t *testing.T) {
	assert.True(t, common.NonEmptyMultiBytes([][]byte{{0x01}, {0x02}}, 2))
	assert.False(t, common.NonEmptyMultiBytes([][]byte{{0x01}}, 2), "expected count mismatch")
	assert.False(t, common.NonEmptyMultiBytes(nil, 1))
}
