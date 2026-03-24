// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

// modInt is a *big.Int that performs all of its arithmetic with modular reduction.
type modInt big.Int

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
	two  = big.NewInt(2)
)

// ModInt creates a new modInt that performs arithmetic modulo the given value.
func ModInt(mod *big.Int) *modInt {
	return (*modInt)(mod)
}

// Add returns (x + y) mod m.
func (mi *modInt) Add(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Add(x, y)
	return i.Mod(i, mi.i())
}

// Sub returns (x - y) mod m.
func (mi *modInt) Sub(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Sub(x, y)
	return i.Mod(i, mi.i())
}

// Div returns (x / y) mod m, or nil if y is zero.
func (mi *modInt) Div(x, y *big.Int) *big.Int {
	if y == nil || y.Sign() == 0 {
		return nil
	}
	i := new(big.Int)
	i.Div(x, y)
	return i.Mod(i, mi.i())
}

// Mul returns (x * y) mod m.
func (mi *modInt) Mul(x, y *big.Int) *big.Int {
	i := new(big.Int)
	i.Mul(x, y)
	return i.Mod(i, mi.i())
}

// Exp returns (x ^ y) mod m.
func (mi *modInt) Exp(x, y *big.Int) *big.Int {
	return new(big.Int).Exp(x, y, mi.i())
}

// ModInverse returns the modular inverse of g mod m.
func (mi *modInt) ModInverse(g *big.Int) *big.Int {
	return new(big.Int).ModInverse(g, mi.i())
}

func (mi *modInt) i() *big.Int {
	return (*big.Int)(mi)
}

// IsInInterval returns true if b is in the interval [0, bound).
func IsInInterval(b *big.Int, bound *big.Int) bool {
	return b.Cmp(bound) == -1 && b.Cmp(zero) >= 0
}

// AppendBigIntToBytesSlice appends the byte representation of a big.Int to the given byte slice.
func AppendBigIntToBytesSlice(commonBytes []byte, appended *big.Int) []byte {
	resultBytes := make([]byte, len(commonBytes), len(commonBytes)+len(appended.Bytes()))
	copy(resultBytes, commonBytes)
	resultBytes = append(resultBytes, appended.Bytes()...)
	return resultBytes
}
