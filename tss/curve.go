// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"errors"
	"reflect"

	"github.com/ModChain/edwards25519"
	"github.com/ModChain/secp256k1"
)

// CurveName is a string identifier for an elliptic curve used in TSS operations.
type CurveName string

const (
	// Secp256k1 is the curve name for the secp256k1 elliptic curve.
	Secp256k1 CurveName = "secp256k1"
	// Ed25519 is the curve name for the Ed25519 twisted Edwards curve.
	Ed25519 CurveName = "ed25519"
)

var (
	ec       elliptic.Curve
	registry map[CurveName]elliptic.Curve
)

// Init default curve (secp256k1)
func init() {
	ec = secp256k1.S256()

	registry = make(map[CurveName]elliptic.Curve)
	registry[Secp256k1] = secp256k1.S256()
	registry[Ed25519] = edwards25519.Edwards()
}

// RegisterCurve registers an elliptic curve under the given name in the global curve registry.
func RegisterCurve(name CurveName, curve elliptic.Curve) {
	registry[name] = curve
}

// return curve, exist(bool)
func GetCurveByName(name CurveName) (elliptic.Curve, bool) {
	if val, exist := registry[name]; exist {
		return val, true
	}

	return nil, false
}

// return name, exist(bool)
func GetCurveName(curve elliptic.Curve) (CurveName, bool) {
	for name, e := range registry {
		if reflect.TypeOf(curve) == reflect.TypeOf(e) {
			return name, true
		}
	}

	return "", false
}

// SameCurve returns true if both lhs and rhs are the same known curve
func SameCurve(lhs, rhs elliptic.Curve) bool {
	lName, lOk := GetCurveName(lhs)
	rName, rOk := GetCurveName(rhs)
	if lOk && rOk {
		return lName == rName
	}
	// if lhs/rhs not exist, return false
	return false
}

// EC returns the current elliptic curve in use. The default is secp256k1
func EC() elliptic.Curve {
	return ec
}

// SetCurve sets the curve used by TSS. Must be called before Start. The default is secp256k1
// Deprecated
func SetCurve(curve elliptic.Curve) {
	if curve == nil {
		panic(errors.New("SetCurve received a nil curve"))
	}
	ec = curve
}

// S256 returns the secp256k1 elliptic curve.
func S256() elliptic.Curve {
	return secp256k1.S256()
}

// Edwards returns the Ed25519 twisted Edwards elliptic curve.
func Edwards() elliptic.Curve {
	return edwards25519.Edwards()
}
