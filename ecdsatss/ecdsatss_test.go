package ecdsatss

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/KarpelesLab/tss-lib/v2/crypto/paillier"
)

func newTestPaillierSK() *paillier.PrivateKey {
	// small test primes for fast test
	P := big.NewInt(107)
	Q := big.NewInt(113)
	N := new(big.Int).Mul(P, Q)
	PMinus1 := new(big.Int).Sub(P, big.NewInt(1))
	QMinus1 := new(big.Int).Sub(Q, big.NewInt(1))
	PhiN := new(big.Int).Mul(PMinus1, QMinus1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	LambdaN := new(big.Int).Div(PhiN, gcd)

	return &paillier.PrivateKey{
		PublicKey: paillier.PublicKey{N: N},
		LambdaN:  LambdaN,
		PhiN:     PhiN,
		P:        P,
		Q:        Q,
	}
}

func TestLocalPreParamsValidate(t *testing.T) {
	sk := newTestPaillierSK()

	pp := LocalPreParams{
		PaillierSK: sk,
		NTildei:    big.NewInt(100),
		H1i:        big.NewInt(200),
		H2i:        big.NewInt(300),
	}
	assert.True(t, pp.Validate())

	// missing NTildei
	pp2 := LocalPreParams{PaillierSK: sk}
	assert.False(t, pp2.Validate())

	// missing H1i
	pp3 := LocalPreParams{PaillierSK: sk, NTildei: big.NewInt(1)}
	assert.False(t, pp3.Validate())

	// missing H2i
	pp4 := LocalPreParams{PaillierSK: sk, NTildei: big.NewInt(1), H1i: big.NewInt(2)}
	assert.False(t, pp4.Validate())

	// missing PaillierSK
	pp5 := LocalPreParams{NTildei: big.NewInt(1), H1i: big.NewInt(2), H2i: big.NewInt(3)}
	assert.False(t, pp5.Validate())
}

func TestLocalPreParamsValidateWithProof(t *testing.T) {
	sk := newTestPaillierSK()

	pp := LocalPreParams{
		PaillierSK: sk,
		NTildei:    big.NewInt(100),
		H1i:        big.NewInt(200),
		H2i:        big.NewInt(300),
		Alpha:      big.NewInt(400),
		Beta:       big.NewInt(500),
		P:          big.NewInt(600),
		Q:          big.NewInt(700),
	}
	assert.True(t, pp.ValidateWithProof())

	// missing Alpha
	pp2 := LocalPreParams{
		PaillierSK: sk,
		NTildei:    big.NewInt(100),
		H1i:        big.NewInt(200),
		H2i:        big.NewInt(300),
	}
	assert.False(t, pp2.ValidateWithProof())

	// missing P
	pp3 := LocalPreParams{
		PaillierSK: sk,
		NTildei:    big.NewInt(100),
		H1i:        big.NewInt(200),
		H2i:        big.NewInt(300),
		Alpha:      big.NewInt(400),
		Beta:       big.NewInt(500),
	}
	assert.False(t, pp3.ValidateWithProof())
}
