// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	cmt "github.com/KarpelesLab/tss-lib/v2/crypto/commitments"
	"github.com/KarpelesLab/tss-lib/v2/crypto/mta"
	"github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-signing.pb.go
// The following messages are registered on the Protocol Buffers "wire"

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*SignRound1Message1)(nil),
		(*SignRound1Message2)(nil),
		(*SignRound2Message)(nil),
		(*SignRound3Message)(nil),
		(*SignRound4Message)(nil),
		(*SignRound5Message)(nil),
		(*SignRound6Message)(nil),
		(*SignRound7Message)(nil),
		(*SignRound8Message)(nil),
		(*SignRound9Message)(nil),
	}
)

// ----- //

// NewSignRound1Message1 creates a point-to-point message for signing round 1 containing the Paillier ciphertext and range proof.
func NewSignRound1Message1(
	to, from *tss.PartyID,
	c *big.Int,
	proof *mta.RangeProofAlice,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pfBz := proof.Bytes()
	content := &SignRound1Message1{
		C:               c.Bytes(),
		RangeProofAlice: pfBz[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that all required fields in the round 1 message 1 are non-empty.
func (m *SignRound1Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetC()) &&
		common.NonEmptyMultiBytes(m.GetRangeProofAlice(), mta.RangeProofAliceBytesParts)
}

// UnmarshalC deserializes the Paillier ciphertext from the message.
func (m *SignRound1Message1) UnmarshalC() *big.Int {
	return new(big.Int).SetBytes(m.GetC())
}

// UnmarshalRangeProofAlice deserializes Alice's range proof from the message.
func (m *SignRound1Message1) UnmarshalRangeProofAlice() (*mta.RangeProofAlice, error) {
	return mta.RangeProofAliceFromBytes(m.GetRangeProofAlice())
}

// ----- //

// NewSignRound1Message2 creates a broadcast message for signing round 1 containing the hash commitment.
func NewSignRound1Message2(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound1Message2{
		Commitment: commitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that the commitment field in the round 1 message 2 is non-empty.
func (m *SignRound1Message2) ValidateBasic() bool {
	return m.Commitment != nil &&
		common.NonEmptyBytes(m.GetCommitment())
}

// UnmarshalCommitment deserializes the hash commitment from the message.
func (m *SignRound1Message2) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

// NewSignRound2Message creates a point-to-point message for signing round 2 containing MtA ciphertexts and Bob proofs.
func NewSignRound2Message(
	to, from *tss.PartyID,
	c1Ji *big.Int,
	pi1Ji *mta.ProofBob,
	c2Ji *big.Int,
	pi2Ji *mta.ProofBobWC,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	pfBob := pi1Ji.Bytes()
	pfBobWC := pi2Ji.Bytes()
	content := &SignRound2Message{
		C1:         c1Ji.Bytes(),
		C2:         c2Ji.Bytes(),
		ProofBob:   pfBob[:],
		ProofBobWc: pfBobWC[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that all required fields in the round 2 message are non-empty.
func (m *SignRound2Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.C1) &&
		common.NonEmptyBytes(m.C2) &&
		common.NonEmptyMultiBytes(m.ProofBob, mta.ProofBobBytesParts) &&
		common.NonEmptyMultiBytes(m.ProofBobWc, mta.ProofBobWCBytesParts)
}

// UnmarshalProofBob deserializes Bob's MtA proof from the message.
func (m *SignRound2Message) UnmarshalProofBob() (*mta.ProofBob, error) {
	return mta.ProofBobFromBytes(m.ProofBob)
}

// UnmarshalProofBobWC deserializes Bob's MtA proof with check from the message.
func (m *SignRound2Message) UnmarshalProofBobWC(ec elliptic.Curve) (*mta.ProofBobWC, error) {
	return mta.ProofBobWCFromBytes(ec, m.ProofBobWc)
}

// ----- //

// NewSignRound3Message creates a broadcast message for signing round 3 containing the theta value.
func NewSignRound3Message(
	from *tss.PartyID,
	theta *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound3Message{
		Theta: theta.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that all required fields in the round 3 message are non-empty.
func (m *SignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Theta)
}

// ----- //

// NewSignRound4Message creates a broadcast message for signing round 4 containing the de-commitment and Schnorr proof.
func NewSignRound4Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *schnorr.ZKProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &SignRound4Message{
		DeCommitment: dcBzs,
		ProofAlphaX:  proof.Alpha.X().Bytes(),
		ProofAlphaY:  proof.Alpha.Y().Bytes(),
		ProofT:       proof.T.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that all required fields in the round 4 message are non-empty.
func (m *SignRound4Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 3) &&
		common.NonEmptyBytes(m.ProofAlphaX) &&
		common.NonEmptyBytes(m.ProofAlphaY) &&
		common.NonEmptyBytes(m.ProofT)
}

// UnmarshalDeCommitment deserializes the hash de-commitment from the message.
func (m *SignRound4Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// UnmarshalZKProof deserializes the Schnorr zero-knowledge proof from the message.
func (m *SignRound4Message) UnmarshalZKProof(ec elliptic.Curve) (*schnorr.ZKProof, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetProofAlphaX()),
		new(big.Int).SetBytes(m.GetProofAlphaY()))
	if err != nil {
		return nil, err
	}
	return &schnorr.ZKProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetProofT()),
	}, nil
}

// ----- //

// NewSignRound5Message creates a broadcast message for signing round 5 containing the hash commitment.
func NewSignRound5Message(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound5Message{
		Commitment: commitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that all required fields in the round 5 message are non-empty.
func (m *SignRound5Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Commitment)
}

// UnmarshalCommitment deserializes the hash commitment from the message.
func (m *SignRound5Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

// NewSignRound6Message creates a broadcast message for signing round 6 containing the de-commitment, Schnorr proof, and V-proof.
func NewSignRound6Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *schnorr.ZKProof,
	vProof *schnorr.ZKVProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &SignRound6Message{
		DeCommitment: dcBzs,
		ProofAlphaX:  proof.Alpha.X().Bytes(),
		ProofAlphaY:  proof.Alpha.Y().Bytes(),
		ProofT:       proof.T.Bytes(),
		VProofAlphaX: vProof.Alpha.X().Bytes(),
		VProofAlphaY: vProof.Alpha.Y().Bytes(),
		VProofT:      vProof.T.Bytes(),
		VProofU:      vProof.U.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that all required fields in the round 6 message are non-empty.
func (m *SignRound6Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 5) &&
		common.NonEmptyBytes(m.ProofAlphaX) &&
		common.NonEmptyBytes(m.ProofAlphaY) &&
		common.NonEmptyBytes(m.ProofT) &&
		common.NonEmptyBytes(m.VProofAlphaX) &&
		common.NonEmptyBytes(m.VProofAlphaY) &&
		common.NonEmptyBytes(m.VProofT) &&
		common.NonEmptyBytes(m.VProofU)
}

// UnmarshalDeCommitment deserializes the hash de-commitment from the message.
func (m *SignRound6Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// UnmarshalZKProof deserializes the Schnorr zero-knowledge proof from the message.
func (m *SignRound6Message) UnmarshalZKProof(ec elliptic.Curve) (*schnorr.ZKProof, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetProofAlphaX()),
		new(big.Int).SetBytes(m.GetProofAlphaY()))
	if err != nil {
		return nil, err
	}
	return &schnorr.ZKProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetProofT()),
	}, nil
}

// UnmarshalZKVProof deserializes the Schnorr V-proof from the message.
func (m *SignRound6Message) UnmarshalZKVProof(ec elliptic.Curve) (*schnorr.ZKVProof, error) {
	point, err := crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.GetVProofAlphaX()),
		new(big.Int).SetBytes(m.GetVProofAlphaY()))
	if err != nil {
		return nil, err
	}
	return &schnorr.ZKVProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetVProofT()),
		U:     new(big.Int).SetBytes(m.GetVProofU()),
	}, nil
}

// ----- //

// NewSignRound7Message creates a broadcast message for signing round 7 containing the hash commitment.
func NewSignRound7Message(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound7Message{
		Commitment: commitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that all required fields in the round 7 message are non-empty.
func (m *SignRound7Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Commitment)
}

// UnmarshalCommitment deserializes the hash commitment from the message.
func (m *SignRound7Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

// NewSignRound8Message creates a broadcast message for signing round 8 containing the de-commitment.
func NewSignRound8Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &SignRound8Message{
		DeCommitment: dcBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that all required fields in the round 8 message are non-empty.
func (m *SignRound8Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 5)
}

// UnmarshalDeCommitment deserializes the hash de-commitment from the message.
func (m *SignRound8Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

// NewSignRound9Message creates a broadcast message for signing round 9 containing the partial signature.
func NewSignRound9Message(
	from *tss.PartyID,
	si *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &SignRound9Message{
		S: si.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that all required fields in the round 9 message are non-empty.
func (m *SignRound9Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.S)
}

// UnmarshalS deserializes the partial signature value from the message.
func (m *SignRound9Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.S)
}
