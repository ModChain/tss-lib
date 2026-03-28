package eddsatss

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/KarpelesLab/tss-lib/v2/common"
)

// PrepareForSigning computes the Lagrange coefficient wi = xi * product(kj/(kj-ki)) for j != i,
// used during the EdDSA signing preparation phase.
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int) *big.Int {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != pax {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax))
	}
	if len(ks) <= i {
		panic(fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i))
	}

	wi := new(big.Int).Set(xi)
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			panic(fmt.Errorf("index of two parties are equal"))
		}
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		wi = modQ.Mul(wi, coef)
	}

	return wi
}
