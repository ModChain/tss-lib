package eddsatss

import (
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// ImportKey wraps a plain EdDSA scalar as a trivial 1-of-1 Key owned entirely by
// partyID. The returned Key is intended to be passed as the sole old-committee
// input to NewResharing, paired with tss.NewReSharingParameters(..., oldPartyCount=1,
// oldThreshold=0, newPartyCount=n, newThreshold=t), so the full key can be split
// into a real t-of-n committee.
//
// priv is the Ed25519 private scalar, interpreted modulo the curve order; it must
// not be zero. partyID is the identity the sole old-committee party will use when
// running resharing — its KeyInt() becomes both the ShareID and the single entry
// of Ks in the returned Key.
//
// The returned Key's EDDSAPub is priv*G on tss.Edwards(); callers should check
// that value against whatever public key they already have before running the
// reshare so a mismatched private key is caught before committee messages start
// flowing.
//
// This helper is for migrating an existing (non-TSS) Ed25519 key into a threshold
// committee. It deliberately defeats the "key never existed whole" property of
// DKG: at the moment of import, one party holds the complete private scalar.
// Only use it when you already have an existing key to bring into TSS; for new
// keys, generate them with NewKeygen instead.
func ImportKey(priv *big.Int, partyID *tss.PartyID) (*Key, error) {
	if priv == nil {
		return nil, fmt.Errorf("ImportKey: priv is nil")
	}
	if partyID == nil {
		return nil, fmt.Errorf("ImportKey: partyID is nil")
	}

	ec := tss.Edwards()
	n := ec.Params().N

	xi := new(big.Int).Mod(priv, n)
	if xi.Sign() == 0 {
		return nil, fmt.Errorf("ImportKey: priv is zero mod curve order")
	}

	pub := crypto.ScalarBaseMult(ec, xi)

	shareID := partyID.KeyInt()
	if shareID == nil || shareID.Sign() == 0 {
		return nil, fmt.Errorf("ImportKey: partyID has empty KeyInt")
	}

	key := &Key{
		Xi:       xi,
		ShareID:  new(big.Int).Set(shareID),
		Ks:       []*big.Int{new(big.Int).Set(shareID)},
		BigXj:    []*crypto.ECPoint{pub},
		EDDSAPub: pub,
	}
	return key, nil
}
