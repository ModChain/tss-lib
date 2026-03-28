package schnorr_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto"
	. "github.com/KarpelesLab/tss-lib/v2/crypto/schnorr"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

// TestZKProofVerifyNilX verifies that Verify rejects a nil ECPoint for X.
func TestZKProofVerifyNilX(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(rand.Reader, q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	proof, err := NewZKProof(Session, u, X, rand.Reader)
	assert.NoError(t, err)

	res := proof.Verify(Session, nil)
	assert.False(t, res, "verify with nil X must return false")
}

// TestZKVProofVerifyNilInputs verifies that ZKVProof.Verify rejects nil inputs.
func TestZKVProofVerifyNilInputs(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(rand.Reader, q)
	s := common.GetRandomPositiveInt(rand.Reader, q)
	l := common.GetRandomPositiveInt(rand.Reader, q)
	R := crypto.ScalarBaseMult(tss.EC(), k)
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, err := NewZKVProof(Session, V, R, s, l, rand.Reader)
	assert.NoError(t, err)

	assert.False(t, proof.Verify(Session, nil, R), "verify with nil V must return false")
	assert.False(t, proof.Verify(Session, V, nil), "verify with nil R must return false")
}
