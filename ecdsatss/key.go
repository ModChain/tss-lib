package ecdsatss

import (
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/crypto/paillier"
)

// Key represents the data for a local share of key.
//
// Key is JSON-compatible with the old ecdsa/keygen.LocalPartySaveData struct,
// so existing serialized key data can be deserialized directly into this type.
type Key struct {
	LocalPreParams
	LocalSecrets

	Ks                []*big.Int // original indexes (ki in signing preparation phase)
	NTildej, H1j, H2j []*big.Int // // n-tilde, h1, h2 for range proofs
	// public keys (Xj = uj*G for each Pj)
	BigXj       []*crypto.ECPoint     // Xj
	PaillierPKs []*paillier.PublicKey // pkj
	// used for test assertions (may be discarded)
	ECDSAPub *crypto.ECPoint // y
}

// NewKey creates a new Key with all slice fields initialized for the given party count.
func NewKey(partyCount int) *Key {
	return &Key{
		Ks:          make([]*big.Int, partyCount),
		NTildej:     make([]*big.Int, partyCount),
		H1j:         make([]*big.Int, partyCount),
		H2j:         make([]*big.Int, partyCount),
		BigXj:       make([]*crypto.ECPoint, partyCount),
		PaillierPKs: make([]*paillier.PublicKey, partyCount),
	}
}

// LocalPreParams contains the pre-computed Paillier key and safe prime parameters for a party.
type LocalPreParams struct {
	PaillierSK                           *paillier.PrivateKey // ski
	NTildei, H1i, H2i, Alpha, Beta, P, Q *big.Int
}

// LocalSecrets holds the secret share data that is not shared with other parties.
type LocalSecrets struct {
	// secret fields (not shared, but stored locally)
	Xi, ShareID *big.Int // xi, kj
}

// Validate returns true if the essential pre-parameters (Paillier key, NTilde, H1, H2) are non-nil.
func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil &&
		preParams.NTildei != nil &&
		preParams.H1i != nil &&
		preParams.H2i != nil
}

// ValidateWithProof returns true if the pre-parameters and all proof-related fields (Alpha, Beta, P, Q) are non-nil.
func (preParams LocalPreParams) ValidateWithProof() bool {
	return preParams.Validate() &&
		preParams.PaillierSK.P != nil &&
		preParams.PaillierSK.Q != nil &&
		preParams.Alpha != nil &&
		preParams.Beta != nil &&
		preParams.P != nil &&
		preParams.Q != nil
}
