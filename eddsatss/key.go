package eddsatss

import (
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
)

// Key represents the data for a local share of an EdDSA key.
//
// Key is JSON-compatible with the old eddsa/keygen.LocalPartySaveData struct,
// so existing serialized key data can be deserialized directly into this type.
type Key struct {
	Xi, ShareID *big.Int
	Ks          []*big.Int
	BigXj       []*crypto.ECPoint
	EDDSAPub    *crypto.ECPoint
}

// NewKey initializes a Key with slices pre-allocated for the given party count.
func NewKey(partyCount int) *Key {
	return &Key{
		Ks:    make([]*big.Int, partyCount),
		BigXj: make([]*crypto.ECPoint, partyCount),
	}
}
