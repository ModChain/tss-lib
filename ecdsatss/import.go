package ecdsatss

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/paillier"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// ImportKey wraps a plain ECDSA private key as a trivial 1-of-1 Key owned entirely
// by partyID. The returned Key is intended to be passed as the sole old-committee
// input to NewResharing, paired with tss.NewReSharingParameters(..., oldPartyCount=1,
// oldThreshold=0, newPartyCount=n, newThreshold=t), so the full key can be split
// into a real t-of-n committee.
//
// priv supplies both the private scalar (priv.D) and the curve. partyID is the
// identity the sole old-committee party will use when running resharing — its
// KeyInt() becomes both the ShareID and the single entry of Ks in the returned
// Key.
//
// The returned Key's ECDSAPub is priv.D*G; callers should check that value
// against whatever public key they already have before running the reshare so a
// mismatched private key is caught before committee messages start flowing.
//
// Fields related to the ECDSA Paillier/range-proof machinery (LocalPreParams,
// NTildej, H1j, H2j, PaillierPKs) are intentionally left unset on the returned
// Key. The resharing protocol only needs them on the NEW committee, where they
// are generated fresh; the old-side rounds only read these slots when hashing
// the SSID, which treats missing entries as zero. Passing this Key to signing
// would fail — it is only valid as resharing input.
//
// This helper is for migrating an existing (non-TSS) ECDSA key into a threshold
// committee. It deliberately defeats the "key never existed whole" property of
// DKG: at the moment of import, one party holds the complete private scalar.
// Only use it when you already have an existing key to bring into TSS; for new
// keys, generate them with NewKeygen instead.
func ImportKey(priv *ecdsa.PrivateKey, partyID *tss.PartyID) (*Key, error) {
	if priv == nil {
		return nil, fmt.Errorf("ImportKey: priv is nil")
	}
	if priv.D == nil {
		return nil, fmt.Errorf("ImportKey: priv.D is nil")
	}
	if priv.Curve == nil {
		return nil, fmt.Errorf("ImportKey: priv.Curve is nil")
	}
	if partyID == nil {
		return nil, fmt.Errorf("ImportKey: partyID is nil")
	}

	n := priv.Curve.Params().N

	xi := new(big.Int).Mod(priv.D, n)
	if xi.Sign() == 0 {
		return nil, fmt.Errorf("ImportKey: priv.D is zero mod curve order")
	}

	pub := crypto.ScalarBaseMult(priv.Curve, xi)
	if priv.PublicKey.X != nil && priv.PublicKey.Y != nil {
		declared, err := crypto.NewECPoint(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
		if err != nil {
			return nil, fmt.Errorf("ImportKey: declared public key is not on the curve: %w", err)
		}
		if !declared.Equals(pub) {
			return nil, fmt.Errorf("ImportKey: priv.PublicKey does not match priv.D * G")
		}
	}

	shareID := partyID.KeyInt()
	if shareID == nil || shareID.Sign() == 0 {
		return nil, fmt.Errorf("ImportKey: partyID has empty KeyInt")
	}

	key := &Key{
		Ks:          []*big.Int{new(big.Int).Set(shareID)},
		NTildej:     []*big.Int{nil},
		H1j:         []*big.Int{nil},
		H2j:         []*big.Int{nil},
		BigXj:       []*crypto.ECPoint{pub},
		PaillierPKs: []*paillier.PublicKey{nil},
		ECDSAPub:    pub,
	}
	key.Xi = xi
	key.ShareID = new(big.Int).Set(shareID)
	return key, nil
}
