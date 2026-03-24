package tss

import (
	"math/big"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSortedPartyIDsLessIsStrict(t *testing.T) {
	// Less must be strict (a < b, not a <= b) per sort.Interface contract
	pIDs := GenerateTestPartyIDs(5)

	// Verify sorted order is correct
	assert.True(t, sort.IsSorted(pIDs))

	// Verify no element is Less than itself
	for i := range pIDs {
		assert.False(t, pIDs.Less(i, i), "Less(i, i) must be false for strict ordering")
	}
}

func TestSortedPartyIDsExclude(t *testing.T) {
	pIDs := GenerateTestPartyIDs(5)
	excluded := pIDs.Exclude(pIDs[2])
	assert.Len(t, excluded, 4)
	for _, pid := range excluded {
		assert.NotEqual(t, pIDs[2].KeyInt(), pid.KeyInt())
	}
}

func TestSortedPartyIDsFindByKey(t *testing.T) {
	pIDs := GenerateTestPartyIDs(5)
	found := pIDs.FindByKey(pIDs[3].KeyInt())
	assert.NotNil(t, found)
	assert.Equal(t, pIDs[3].KeyInt(), found.KeyInt())

	notFound := pIDs.FindByKey(big.NewInt(999999))
	assert.Nil(t, notFound)
}

func TestSortedPartyIDsKeys(t *testing.T) {
	pIDs := GenerateTestPartyIDs(3)
	keys := pIDs.Keys()
	assert.Len(t, keys, 3)
	for i, pid := range pIDs {
		assert.Equal(t, pid.KeyInt(), keys[i])
	}
}

func TestPartyIDValidateBasic(t *testing.T) {
	// NewPartyID sets Index=-1 (unknown until sorted), so ValidateBasic is false
	pid := NewPartyID("id", "moniker", big.NewInt(1))
	assert.False(t, pid.ValidateBasic(), "Index=-1 should fail validation")

	// After sorting, index is assigned and validation should pass
	pIDs := GenerateTestPartyIDs(3)
	assert.True(t, pIDs[0].ValidateBasic())

	var nilPID *PartyID
	assert.False(t, nilPID.ValidateBasic())
}
