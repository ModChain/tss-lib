// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"

	"github.com/ModChain/tss-lib/v2/common"
)

type (
	// PartyID represents a participant in the TSS protocol rounds.
	// Note: The `id` and `moniker` are provided for convenience to allow you to track participants easier.
	// The `id` is intended to be a unique string representation of `key` and `moniker` can be anything (even left blank).
	PartyID struct {
		*MessageWrapper_PartyID
		Index int `json:"index"`
	}

	// UnSortedPartyIDs is an unsorted slice of PartyID pointers.
	UnSortedPartyIDs []*PartyID
	// SortedPartyIDs is a slice of PartyID pointers sorted by key in ascending order.
	SortedPartyIDs []*PartyID
)

// ValidateBasic returns true if the PartyID has a non-nil key and a non-negative index.
func (pid *PartyID) ValidateBasic() bool {
	return pid != nil && pid.Key != nil && 0 <= pid.Index
}

// --- ProtoBuf Extensions

// KeyInt returns the key as a *big.Int.
func (mpid *MessageWrapper_PartyID) KeyInt() *big.Int {
	return new(big.Int).SetBytes(mpid.Key)
}

// ----- //

// NewPartyID constructs a new PartyID
// Exported, used in `tss` client. `key` should remain consistent between runs for each party.
func NewPartyID(id, moniker string, key *big.Int) *PartyID {
	return &PartyID{
		MessageWrapper_PartyID: &MessageWrapper_PartyID{
			Id:      id,
			Moniker: moniker,
			Key:     key.Bytes(),
		},
		Index: -1, // not known until sorted
	}
}

// String returns a human-readable representation of the PartyID including its index and moniker.
func (pid PartyID) String() string {
	return fmt.Sprintf("{%d,%s}", pid.Index, pid.Moniker)
}

// ----- //

// SortPartyIDs sorts a list of []*PartyID by their keys in ascending order
// Exported, used in `tss` client
func SortPartyIDs(ids UnSortedPartyIDs, startAt ...int) SortedPartyIDs {
	sorted := make(SortedPartyIDs, 0, len(ids))
	for _, id := range ids {
		sorted = append(sorted, id)
	}
	sort.Sort(sorted)
	// assign party indexes
	for i, id := range sorted {
		frm := 0
		if len(startAt) > 0 {
			frm = startAt[0]
		}
		id.Index = i + frm
	}
	return sorted
}

// GenerateTestPartyIDs generates a list of mock PartyIDs for tests
func GenerateTestPartyIDs(count int, startAt ...int) SortedPartyIDs {
	ids := make(UnSortedPartyIDs, 0, count)
	key := common.MustGetRandomInt(rand.Reader, 256)
	frm := 0
	i := 0 // default `i`
	if len(startAt) > 0 {
		frm = startAt[0]
		i = startAt[0]
	}
	for ; i < count+frm; i++ {
		ids = append(ids, &PartyID{
			MessageWrapper_PartyID: &MessageWrapper_PartyID{
				Id:      fmt.Sprintf("%d", i+1),
				Moniker: fmt.Sprintf("P[%d]", i+1),
				Key:     new(big.Int).Sub(key, big.NewInt(int64(count)-int64(i))).Bytes(),
			},
			Index: i,
			// this key makes tests more deterministic
		})
	}
	return SortPartyIDs(ids, startAt...)
}

// Keys returns a slice of the keys for all party IDs in the sorted list.
func (spids SortedPartyIDs) Keys() []*big.Int {
	ids := make([]*big.Int, spids.Len())
	for i, pid := range spids {
		ids[i] = pid.KeyInt()
	}
	return ids
}

// ToUnSorted converts the SortedPartyIDs to an UnSortedPartyIDs type.
func (spids SortedPartyIDs) ToUnSorted() UnSortedPartyIDs {
	return UnSortedPartyIDs(spids)
}

// FindByKey returns the PartyID matching the given key, or nil if not found.
func (spids SortedPartyIDs) FindByKey(key *big.Int) *PartyID {
	for _, pid := range spids {
		if pid.KeyInt().Cmp(key) == 0 {
			return pid
		}
	}
	return nil
}

// Exclude returns a new SortedPartyIDs with the specified party removed.
func (spids SortedPartyIDs) Exclude(exclude *PartyID) SortedPartyIDs {
	newSpIDs := make(SortedPartyIDs, 0, len(spids))
	for _, pid := range spids {
		if pid.KeyInt().Cmp(exclude.KeyInt()) == 0 {
			continue // exclude
		}
		newSpIDs = append(newSpIDs, pid)
	}
	return newSpIDs
}

// Sortable

// Len returns the number of party IDs in the sorted list, implementing sort.Interface.
func (spids SortedPartyIDs) Len() int {
	return len(spids)
}

// Less reports whether the party at index a has a smaller key than the party at index b, implementing sort.Interface.
func (spids SortedPartyIDs) Less(a, b int) bool {
	return spids[a].KeyInt().Cmp(spids[b].KeyInt()) < 0
}

// Swap swaps the party IDs at the given indices, implementing sort.Interface.
func (spids SortedPartyIDs) Swap(a, b int) {
	spids[a], spids[b] = spids[b], spids[a]
}
