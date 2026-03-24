// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

// RejectionSample reduces a hash value modulo q. The input eHash is a
// 256-bit output of SHA-512/256. When q is close to or larger than 2^256
// the bias from modular reduction is negligible. For smaller q values the
// bias is at most 2^{-128} which is within acceptable security bounds.
func RejectionSample(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	e := new(big.Int).Mod(eHash, q)
	return e
}
