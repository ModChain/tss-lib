// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto/dlnproof"
)

// DlnProofVerifier verifies DLN proofs with bounded concurrency.
type DlnProofVerifier struct {
	semaphore chan interface{}
}

type message interface {
	UnmarshalDLNProof1() (*dlnproof.Proof, error)
	UnmarshalDLNProof2() (*dlnproof.Proof, error)
}

// NewDlnProofVerifier creates a new DlnProofVerifier with the given concurrency limit.
func NewDlnProofVerifier(concurrency int) *DlnProofVerifier {
	if concurrency == 0 {
		panic(errors.New("NewDlnProofverifier: concurrency level must not be zero"))
	}

	semaphore := make(chan interface{}, concurrency)

	return &DlnProofVerifier{
		semaphore: semaphore,
	}
}

// VerifyDLNProof1 asynchronously verifies the first DLN proof from the message and calls onDone with the result.
func (dpv *DlnProofVerifier) VerifyDLNProof1(
	m message,
	h1, h2, n *big.Int,
	onDone func(bool),
) {
	dpv.semaphore <- struct{}{}
	go func() {
		defer func() { <-dpv.semaphore }()

		dlnProof, err := m.UnmarshalDLNProof1()
		if err != nil {
			onDone(false)
			return
		}

		onDone(dlnProof.Verify(h1, h2, n))
	}()
}

// VerifyDLNProof2 asynchronously verifies the second DLN proof from the message and calls onDone with the result.
func (dpv *DlnProofVerifier) VerifyDLNProof2(
	m message,
	h1, h2, n *big.Int,
	onDone func(bool),
) {
	dpv.semaphore <- struct{}{}
	go func() {
		defer func() { <-dpv.semaphore }()

		dlnProof, err := m.UnmarshalDLNProof2()
		if err != nil {
			onDone(false)
			return
		}

		onDone(dlnProof.Verify(h1, h2, n))
	}()
}
