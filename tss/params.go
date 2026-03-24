// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"runtime"
	"time"
)

type (
	// Parameters holds the configuration for a TSS party, including curve, threshold, and peer information.
	Parameters struct {
		ec                  elliptic.Curve
		partyID             *PartyID
		parties             *PeerContext
		partyCount          int
		threshold           int
		concurrency         int
		safePrimeGenTimeout time.Duration
		// proof session info
		nonce int
		// for keygen
		noProofMod bool
		noProofFac bool
		// random sources
		partialKeyRand, rand io.Reader
		broker               MessageBroker
	}

	// ReSharingParameters extends Parameters with additional configuration for key re-sharing between old and new committees.
	ReSharingParameters struct {
		*Parameters
		newParties    *PeerContext
		newPartyCount int
		newThreshold  int
	}
)

const (
	defaultSafePrimeGenTimeout = 5 * time.Minute
)

// Exported, used in `tss` client
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID, partyCount, threshold int) *Parameters {
	if ec == nil {
		panic("NewParameters: ec must not be nil")
	}
	if partyCount < 1 {
		panic("NewParameters: partyCount must be positive")
	}
	if threshold < 0 || threshold >= partyCount {
		panic("NewParameters: threshold must satisfy 0 <= threshold < partyCount")
	}
	return &Parameters{
		ec:                  ec,
		parties:             ctx,
		partyID:             partyID,
		partyCount:          partyCount,
		threshold:           threshold,
		concurrency:         runtime.GOMAXPROCS(0),
		safePrimeGenTimeout: defaultSafePrimeGenTimeout,
		partialKeyRand:      rand.Reader,
		rand:                rand.Reader,
		broker:              NewTestBroker(),
	}
}

// EC returns the elliptic curve used by this set of parameters.
func (params *Parameters) EC() elliptic.Curve {
	return params.ec
}

// Parties returns the PeerContext containing all party IDs for this session.
func (params *Parameters) Parties() *PeerContext {
	return params.parties
}

// PartyID returns the PartyID of this party within the session.
func (params *Parameters) PartyID() *PartyID {
	return params.partyID
}

// PartyCount returns the total number of parties in the session.
func (params *Parameters) PartyCount() int {
	return params.partyCount
}

// Threshold returns the threshold value t, where t+1 parties are needed to sign.
func (params *Parameters) Threshold() int {
	return params.threshold
}

// Concurrency returns the concurrency level used for parallelizable operations.
func (params *Parameters) Concurrency() int {
	return params.concurrency
}

// SafePrimeGenTimeout returns the timeout duration for safe prime generation.
func (params *Parameters) SafePrimeGenTimeout() time.Duration {
	return params.safePrimeGenTimeout
}

// The concurrency level must be >= 1.
func (params *Parameters) SetConcurrency(concurrency int) {
	params.concurrency = concurrency
}

// SetSafePrimeGenTimeout sets the timeout duration for safe prime generation.
func (params *Parameters) SetSafePrimeGenTimeout(timeout time.Duration) {
	params.safePrimeGenTimeout = timeout
}

// NoProofMod returns whether the modular proof is disabled for key generation.
func (params *Parameters) NoProofMod() bool {
	return params.noProofMod
}

// NoProofFac returns whether the factor proof is disabled for key generation.
func (params *Parameters) NoProofFac() bool {
	return params.noProofFac
}

// SetNoProofMod disables the modular proof during key generation.
func (params *Parameters) SetNoProofMod() {
	params.noProofMod = true
}

// SetNoProofFac disables the factor proof during key generation.
func (params *Parameters) SetNoProofFac() {
	params.noProofFac = true
}

// SetBroker sets the message broker used for routing messages between parties.
func (params *Parameters) SetBroker(b MessageBroker) {
	params.broker = b
}

// Broker returns the message broker used for routing messages between parties.
func (params *Parameters) Broker() MessageBroker {
	return params.broker
}

// PartialKeyRand returns the random source used for partial key generation.
func (params *Parameters) PartialKeyRand() io.Reader {
	return params.partialKeyRand
}

// Rand returns the general-purpose random source for the parameters.
func (params *Parameters) Rand() io.Reader {
	return params.rand
}

// SetPartialKeyRand sets the random source used for partial key generation.
func (params *Parameters) SetPartialKeyRand(rand io.Reader) {
	params.partialKeyRand = rand
}

// SetRand sets the general-purpose random source for the parameters.
func (params *Parameters) SetRand(rand io.Reader) {
	params.rand = rand
}

// ----- //

// Exported, used in `tss` client
func NewReSharingParameters(ec elliptic.Curve, ctx, newCtx *PeerContext, partyID *PartyID, partyCount, threshold, newPartyCount, newThreshold int) *ReSharingParameters {
	params := NewParameters(ec, ctx, partyID, partyCount, threshold)
	return &ReSharingParameters{
		Parameters:    params,
		newParties:    newCtx,
		newPartyCount: newPartyCount,
		newThreshold:  newThreshold,
	}
}

// OldParties returns the PeerContext for the old committee in a re-sharing session.
func (rgParams *ReSharingParameters) OldParties() *PeerContext {
	return rgParams.Parties() // wr use the original method for old parties
}

// OldPartyCount returns the number of parties in the old committee.
func (rgParams *ReSharingParameters) OldPartyCount() int {
	return rgParams.partyCount
}

// NewParties returns the PeerContext for the new committee in a re-sharing session.
func (rgParams *ReSharingParameters) NewParties() *PeerContext {
	return rgParams.newParties
}

// NewPartyCount returns the number of parties in the new committee.
func (rgParams *ReSharingParameters) NewPartyCount() int {
	return rgParams.newPartyCount
}

// NewThreshold returns the threshold for the new committee after re-sharing.
func (rgParams *ReSharingParameters) NewThreshold() int {
	return rgParams.newThreshold
}

// OldAndNewParties returns the combined list of party IDs from both old and new committees.
func (rgParams *ReSharingParameters) OldAndNewParties() []*PartyID {
	return append(rgParams.OldParties().IDs(), rgParams.NewParties().IDs()...)
}

// OldAndNewPartyCount returns the total number of parties across both old and new committees.
func (rgParams *ReSharingParameters) OldAndNewPartyCount() int {
	return rgParams.OldPartyCount() + rgParams.NewPartyCount()
}

// IsOldCommittee returns true if this party belongs to the old committee.
func (rgParams *ReSharingParameters) IsOldCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.parties.IDs() {
		if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {
			return true
		}
	}
	return false
}

// IsNewCommittee returns true if this party belongs to the new committee.
func (rgParams *ReSharingParameters) IsNewCommittee() bool {
	partyID := rgParams.partyID
	for _, Pj := range rgParams.newParties.IDs() {
		if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {
			return true
		}
	}
	return false
}
