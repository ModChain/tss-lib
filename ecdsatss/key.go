package ecdsatss

import (
	"math/big"

	"github.com/ModChain/tss-lib/v2/crypto"
	"github.com/ModChain/tss-lib/v2/crypto/paillier"
)

// Key represents the data for a local share of key
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

type LocalPreParams struct {
	PaillierSK                           *paillier.PrivateKey // ski
	NTildei, H1i, H2i, Alpha, Beta, P, Q *big.Int
}

type LocalSecrets struct {
	// secret fields (not shared, but stored locally)
	Xi, ShareID *big.Int // xi, kj
}

func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil &&
		preParams.NTildei != nil &&
		preParams.H1i != nil &&
		preParams.H2i != nil
}

func (preParams LocalPreParams) ValidateWithProof() bool {
	return preParams.Validate() &&
		preParams.PaillierSK.P != nil &&
		preParams.PaillierSK.Q != nil &&
		preParams.Alpha != nil &&
		preParams.Beta != nil &&
		preParams.P != nil &&
		preParams.Q != nil
}
