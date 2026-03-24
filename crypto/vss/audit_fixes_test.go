package vss_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/ModChain/tss-lib/v2/common"
	. "github.com/ModChain/tss-lib/v2/crypto/vss"
	"github.com/ModChain/tss-lib/v2/tss"
)

// TestReConstructNilShares verifies that ReConstruct handles nil/empty shares.
func TestReConstructNilShares(t *testing.T) {
	var nilShares Shares
	_, err := nilShares.ReConstruct(tss.EC())
	assert.Error(t, err, "nil shares should return error")

	emptyShares := Shares{}
	_, err = emptyShares.ReConstruct(tss.EC())
	assert.Error(t, err, "empty shares should return error")
}

// TestReConstructDuplicateShareIDs verifies that ReConstruct returns an error
// when two shares have the same ID (previously it would panic due to nil ModInverse).
func TestReConstructDuplicateShareIDs(t *testing.T) {
	num, threshold := 5, 3
	secret := common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(rand.Reader, tss.EC().Params().N))
	}

	_, shares, err := Create(tss.EC(), threshold, secret, ids, rand.Reader)
	assert.NoError(t, err)

	// Create duplicate share IDs
	dupShares := make(Shares, threshold+1)
	copy(dupShares, shares[:threshold+1])
	dupShares[1] = &Share{
		Threshold: threshold,
		ID:        new(big.Int).Set(dupShares[0].ID), // duplicate ID
		Share:     big.NewInt(42),
	}

	_, err = dupShares.ReConstruct(tss.EC())
	assert.Error(t, err, "duplicate share IDs should return error, not panic")
}
