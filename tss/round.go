// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

// Round defines the interface for a single round of the TSS protocol.
type Round interface {
	Params() *Parameters
	Start() error
	Update() (bool, error)
	RoundNumber() int
	CanAccept(msg ParsedMessage) bool
	CanProceed() bool
	NextRound() Round
	WaitingFor() []*PartyID
	WrapError(err error, culprits ...*PartyID) error
}
