package commitments_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/KarpelesLab/tss-lib/v2/crypto/commitments"
)

func TestNewHashCommitmentDeterministic(t *testing.T) {
	// Two commitments with different randomness should have different C values
	cmt1 := NewHashCommitment(rand.Reader, big.NewInt(42))
	cmt2 := NewHashCommitment(rand.Reader, big.NewInt(42))
	assert.NotEqual(t, cmt1.C, cmt2.C, "commitments with different randomness should differ")
}

func TestDeCommitWrongValues(t *testing.T) {
	cmt := NewHashCommitment(rand.Reader, big.NewInt(42))
	// Tamper with the decommitment
	tampered := HashCommitDecommit{C: cmt.C, D: append(cmt.D[:0:0], cmt.D...)}
	tampered.D[len(tampered.D)-1] = nil
	ok, _ := tampered.DeCommit()
	assert.False(t, ok, "tampered decommitment should fail")
}

func TestVerifyAfterDeCommit(t *testing.T) {
	cmt := NewHashCommitment(rand.Reader, big.NewInt(1), big.NewInt(2))
	ok, values := cmt.DeCommit()
	assert.True(t, ok)
	assert.Len(t, values, 2)
	assert.True(t, cmt.Verify())
}

func TestNewBuilder(t *testing.T) {
	b := NewBuilder()
	assert.NotNil(t, b)
	assert.Len(t, b.Parts(), 0)

	b.AddPart([]*big.Int{big.NewInt(1), big.NewInt(2)})
	assert.Len(t, b.Parts(), 1)

	secrets, err := b.Secrets()
	assert.NoError(t, err)
	// 1 length prefix + 2 values = 3
	assert.Len(t, secrets, 3)
}

func TestParseSecretsRoundTrip(t *testing.T) {
	b := NewBuilder()
	b.AddPart([]*big.Int{big.NewInt(10), big.NewInt(20)})
	b.AddPart([]*big.Int{big.NewInt(30)})

	secrets, err := b.Secrets()
	assert.NoError(t, err)

	parts, err := ParseSecrets(secrets)
	assert.NoError(t, err)
	assert.Len(t, parts, 2)
	assert.Len(t, parts[0], 2)
	assert.Len(t, parts[1], 1)
	assert.Equal(t, big.NewInt(10), parts[0][0])
	assert.Equal(t, big.NewInt(30), parts[1][0])
}
