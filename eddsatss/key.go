package eddsatss

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
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

// SubsetForParties returns a new Key whose Ks and BigXj slices are reordered to match the
// given sorted party IDs. Parties are matched by their ShareID — i.e. the Ks value stored
// by keygen, compared to PartyID.Key.
//
// This reindexing is required whenever the current party set is a strict subset of the
// parties that participated in keygen (for example, a t+1 signing committee picked out of
// an n-party keygen, or resharing's old committee). The signing and resharing rounds index
// these slices by the current-party index, so the slices must be in current-party order.
//
// The returned Key shares Xi, ShareID, and EDDSAPub with the receiver; only Ks and BigXj
// are rebuilt.
func (key *Key) SubsetForParties(sortedIDs tss.SortedPartyIDs) (*Key, error) {
	keysToIndices := make(map[string]int, len(key.Ks))
	for j, kj := range key.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	subset := &Key{
		Xi:       key.Xi,
		ShareID:  key.ShareID,
		Ks:       make([]*big.Int, len(sortedIDs)),
		BigXj:    make([]*crypto.ECPoint, len(sortedIDs)),
		EDDSAPub: key.EDDSAPub,
	}
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			return nil, fmt.Errorf("SubsetForParties: party %s not found in keygen save data", id)
		}
		subset.Ks[j] = key.Ks[savedIdx]
		subset.BigXj[j] = key.BigXj[savedIdx]
	}
	return subset, nil
}
