// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"crypto/elliptic"
	"math/big"

	"github.com/ModChain/tss-lib/v2/common"
	"github.com/ModChain/tss-lib/v2/crypto"
	cmt "github.com/ModChain/tss-lib/v2/crypto/commitments"
	"github.com/ModChain/tss-lib/v2/crypto/dlnproof"
	"github.com/ModChain/tss-lib/v2/crypto/facproof"
	"github.com/ModChain/tss-lib/v2/crypto/modproof"
	"github.com/ModChain/tss-lib/v2/crypto/paillier"
	"github.com/ModChain/tss-lib/v2/crypto/vss"
	"github.com/ModChain/tss-lib/v2/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-resharing.pb.go

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*DGRound1Message)(nil),
		(*DGRound2Message1)(nil),
		(*DGRound2Message2)(nil),
		(*DGRound3Message1)(nil),
		(*DGRound3Message2)(nil),
		(*DGRound4Message1)(nil),
		(*DGRound4Message2)(nil),
	}
)

// ----- //

// NewDGRound1Message creates a broadcast message for resharing round 1 containing the ECDSA public key, commitment, and SSID.
func NewDGRound1Message(
	to []*tss.PartyID,
	from *tss.PartyID,
	ecdsaPub *crypto.ECPoint,
	vct cmt.HashCommitment,
	ssid []byte,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	content := &DGRound1Message{
		EcdsaPubX:   ecdsaPub.X().Bytes(),
		EcdsaPubY:   ecdsaPub.Y().Bytes(),
		VCommitment: vct.Bytes(),
		Ssid:        ssid,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that all required fields in the resharing round 1 message are non-empty.
func (m *DGRound1Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.EcdsaPubX) &&
		common.NonEmptyBytes(m.EcdsaPubY) &&
		common.NonEmptyBytes(m.VCommitment)
}

// UnmarshalECDSAPub deserializes the ECDSA public key from the message.
func (m *DGRound1Message) UnmarshalECDSAPub(ec elliptic.Curve) (*crypto.ECPoint, error) {
	return crypto.NewECPoint(
		ec,
		new(big.Int).SetBytes(m.EcdsaPubX),
		new(big.Int).SetBytes(m.EcdsaPubY))
}

// UnmarshalVCommitment deserializes the VSS commitment from the message.
func (m *DGRound1Message) UnmarshalVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetVCommitment())
}

// UnmarshalSSID deserializes the session identifier from the message.
func (m *DGRound1Message) UnmarshalSSID() []byte {
	return m.GetSsid()
}

// ----- //

// NewDGRound2Message1 creates a broadcast message for resharing round 2 containing the Paillier key, modulus proof, and DLN proofs.
func NewDGRound2Message1(
	to []*tss.PartyID,
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	modProof *modproof.ProofMod,
	NTildei, H1i, H2i *big.Int,
	dlnProof1, dlnProof2 *dlnproof.Proof,
) (tss.ParsedMessage, error) {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	modPfBzs := modProof.Bytes()
	dlnProof1Bz, err := dlnProof1.Serialize()
	if err != nil {
		return nil, err
	}
	dlnProof2Bz, err := dlnProof2.Serialize()
	if err != nil {
		return nil, err
	}
	content := &DGRound2Message1{
		PaillierN:  paillierPK.N.Bytes(),
		ModProof:   modPfBzs[:],
		NTilde:     NTildei.Bytes(),
		H1:         H1i.Bytes(),
		H2:         H2i.Bytes(),
		Dlnproof_1: dlnProof1Bz,
		Dlnproof_2: dlnProof2Bz,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

// ValidateBasic checks that all required fields in the resharing round 2 message 1 are non-empty.
func (m *DGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		// use with NoProofFac()
		// common.NonEmptyMultiBytes(m.ModProof, modproof.ProofModBytesParts) &&
		common.NonEmptyBytes(m.PaillierN) &&
		common.NonEmptyBytes(m.NTilde) &&
		common.NonEmptyBytes(m.H1) &&
		common.NonEmptyBytes(m.H2) &&
		// expected len of dln proof = sizeof(int64) + len(alpha) + len(t)
		common.NonEmptyMultiBytes(m.GetDlnproof_1(), 2+(dlnproof.Iterations*2)) &&
		common.NonEmptyMultiBytes(m.GetDlnproof_2(), 2+(dlnproof.Iterations*2))
}

// UnmarshalPaillierPK deserializes the Paillier public key from the message.
func (m *DGRound2Message1) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{
		N: new(big.Int).SetBytes(m.PaillierN),
	}
}

// UnmarshalNTilde deserializes the NTilde value from the message.
func (m *DGRound2Message1) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

// UnmarshalH1 deserializes the H1 value from the message.
func (m *DGRound2Message1) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

// UnmarshalH2 deserializes the H2 value from the message.
func (m *DGRound2Message1) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

// UnmarshalModProof deserializes the modulus proof from the message.
func (m *DGRound2Message1) UnmarshalModProof() (*modproof.ProofMod, error) {
	return modproof.NewProofFromBytes(m.GetModProof())
}

// UnmarshalDLNProof1 deserializes the first DLN proof from the message.
func (m *DGRound2Message1) UnmarshalDLNProof1() (*dlnproof.Proof, error) {
	return dlnproof.UnmarshalDLNProof(m.GetDlnproof_1())
}

// UnmarshalDLNProof2 deserializes the second DLN proof from the message.
func (m *DGRound2Message1) UnmarshalDLNProof2() (*dlnproof.Proof, error) {
	return dlnproof.UnmarshalDLNProof(m.GetDlnproof_2())
}

// ----- //

// NewDGRound2Message2 creates a broadcast message from the new committee to the old committee signaling readiness.
func NewDGRound2Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: true,
	}
	content := &DGRound2Message2{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic always returns true as this message carries no payload.
func (m *DGRound2Message2) ValidateBasic() bool {
	return true
}

// ----- //

// NewDGRound3Message1 creates a point-to-point message for resharing round 3 containing a VSS share.
func NewDGRound3Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	content := &DGRound3Message1{
		Share: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that the share field in the resharing round 3 message 1 is non-empty.
func (m *DGRound3Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Share)
}

// ----- //

// NewDGRound3Message2 creates a broadcast message for resharing round 3 containing the VSS de-commitment.
func NewDGRound3Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
	vdct cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	vDctBzs := common.BigIntsToBytes(vdct)
	content := &DGRound3Message2{
		VDecommitment: vDctBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that the de-commitment field in the resharing round 3 message 2 is non-empty.
func (m *DGRound3Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.VDecommitment)
}

// UnmarshalVDeCommitment deserializes the VSS de-commitment from the message.
func (m *DGRound3Message2) UnmarshalVDeCommitment() cmt.HashDeCommitment {
	deComBzs := m.GetVDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

// NewDGRound4Message2 creates a broadcast message for resharing round 4 sent to both old and new committees.
func NewDGRound4Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldAndNewCommittees: true,
	}
	content := &DGRound4Message2{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic always returns true as this message carries no payload.
func (m *DGRound4Message2) ValidateBasic() bool {
	return true
}

// NewDGRound4Message1 creates a point-to-point message for resharing round 4 containing the factorization proof.
func NewDGRound4Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	proof *facproof.ProofFac,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	pfBzs := proof.Bytes()
	content := &DGRound4Message1{
		FacProof: pfBzs[:],
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

// ValidateBasic checks that the round 4 message 1 is non-nil.
func (m *DGRound4Message1) ValidateBasic() bool {
	return m != nil
	// use with NoProofFac()
	// && common.NonEmptyMultiBytes(m.GetFacProof(), facproof.ProofFacBytesParts)
}

// UnmarshalFacProof deserializes the factorization proof from the message.
func (m *DGRound4Message1) UnmarshalFacProof() (*facproof.ProofFac, error) {
	return facproof.NewProofFromBytes(m.GetFacProof())
}
