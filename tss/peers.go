// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

type (
	// PeerContext holds the sorted list of party IDs participating in a TSS session.
	PeerContext struct {
		partyIDs SortedPartyIDs
	}
)

// NewPeerContext creates a new PeerContext from the given sorted party IDs.
func NewPeerContext(parties SortedPartyIDs) *PeerContext {
	return &PeerContext{partyIDs: parties}
}

// IDs returns the sorted list of party IDs in this peer context.
func (p2pCtx *PeerContext) IDs() SortedPartyIDs {
	return p2pCtx.partyIDs
}

// SetIDs replaces the sorted party IDs in this peer context.
func (p2pCtx *PeerContext) SetIDs(ids SortedPartyIDs) {
	p2pCtx.partyIDs = ids
}
