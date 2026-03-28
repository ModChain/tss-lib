package crypto_test

import (
	"encoding/gob"
	"bytes"
	"math/big"
	"testing"

	"github.com/KarpelesLab/edwards25519"
	"github.com/KarpelesLab/secp256k1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/KarpelesLab/tss-lib/v2/crypto"
	"github.com/KarpelesLab/tss-lib/v2/tss"
)

func TestNewECPoint(t *testing.T) {
	curve := tss.S256()
	// generator point
	x, y := curve.Params().Gx, curve.Params().Gy
	p, err := NewECPoint(curve, x, y)
	require.NoError(t, err)
	assert.True(t, p.IsOnCurve())

	// invalid point
	_, err = NewECPoint(curve, big.NewInt(1), big.NewInt(2))
	assert.Error(t, err)

	// nil coords
	_, err = NewECPoint(curve, nil, big.NewInt(1))
	assert.Error(t, err)
}

func TestNewECPointNoCurveCheck(t *testing.T) {
	curve := tss.S256()
	p := NewECPointNoCurveCheck(curve, big.NewInt(1), big.NewInt(2))
	assert.Equal(t, big.NewInt(1), p.X())
	assert.Equal(t, big.NewInt(2), p.Y())
	assert.Equal(t, curve, p.Curve())
}

func TestECPointXY(t *testing.T) {
	curve := tss.S256()
	gx, gy := curve.Params().Gx, curve.Params().Gy
	p, _ := NewECPoint(curve, gx, gy)
	// returns copies
	x := p.X()
	y := p.Y()
	assert.Equal(t, 0, gx.Cmp(x))
	assert.Equal(t, 0, gy.Cmp(y))
	// mutating the copy should not affect the point
	x.SetInt64(0)
	assert.Equal(t, 0, gx.Cmp(p.X()))
}

func TestECPointAdd(t *testing.T) {
	curve := tss.S256()
	g, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	sum, err := g.Add(g)
	require.NoError(t, err)
	assert.True(t, sum.IsOnCurve())
	assert.False(t, sum.Equals(g))
}

func TestECPointScalarMult(t *testing.T) {
	curve := tss.S256()
	g, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	p2 := g.ScalarMult(big.NewInt(2))
	assert.True(t, p2.IsOnCurve())

	sum, _ := g.Add(g)
	assert.True(t, p2.Equals(sum))
}

func TestScalarBaseMult(t *testing.T) {
	curve := tss.S256()
	p := ScalarBaseMult(curve, big.NewInt(1))
	assert.Equal(t, 0, curve.Params().Gx.Cmp(p.X()))
	assert.Equal(t, 0, curve.Params().Gy.Cmp(p.Y()))

	p2 := ScalarBaseMult(curve, big.NewInt(2))
	g, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	sum, _ := g.Add(g)
	assert.True(t, p2.Equals(sum))
}

func TestECPointEquals(t *testing.T) {
	curve := tss.S256()
	g1, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	g2, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	assert.True(t, g1.Equals(g2))

	p2 := g1.ScalarMult(big.NewInt(2))
	assert.False(t, g1.Equals(p2))

	assert.False(t, g1.Equals(nil))
	var nilPt *ECPoint
	assert.False(t, nilPt.Equals(g1))
}

func TestECPointValidateBasic(t *testing.T) {
	curve := tss.S256()
	g, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	assert.True(t, g.ValidateBasic())

	var nilPt *ECPoint
	assert.False(t, nilPt.ValidateBasic())
}

func TestECPointSetCurve(t *testing.T) {
	curve := tss.S256()
	g, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	newCurve := tss.Edwards()
	g.SetCurve(newCurve)
	assert.Equal(t, newCurve, g.Curve())
}

func TestECPointToECDSAPubKey(t *testing.T) {
	curve := tss.S256()
	g, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	pk := g.ToECDSAPubKey()
	assert.Equal(t, curve, pk.Curve)
	assert.Equal(t, 0, curve.Params().Gx.Cmp(pk.X))
	assert.Equal(t, 0, curve.Params().Gy.Cmp(pk.Y))
}

func TestECPointToSecp256k1PubKey(t *testing.T) {
	curve := secp256k1.S256()
	g, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	pk := g.ToSecp256k1PubKey()
	assert.NotNil(t, pk)

	// not secp256k1
	edCurve := edwards25519.Edwards()
	gEd, _ := NewECPoint(edCurve, edCurve.Params().Gx, edCurve.Params().Gy)
	assert.Nil(t, gEd.ToSecp256k1PubKey())
}

func TestECPointToEd25519PubKey(t *testing.T) {
	curve := edwards25519.Edwards()
	g, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	pk := g.ToEd25519PubKey()
	assert.NotNil(t, pk)
	assert.Equal(t, 0, curve.Params().Gx.Cmp(pk.X))
}

func TestECPointGobEncoding(t *testing.T) {
	curve := tss.S256()
	g, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(g)
	require.NoError(t, err)

	var decoded ECPoint
	dec := gob.NewDecoder(&buf)
	err = dec.Decode(&decoded)
	require.NoError(t, err)
	assert.True(t, g.Equals(&decoded))
}

func TestECPointEightInvEight(t *testing.T) {
	curve := edwards25519.Edwards()
	g, _ := NewECPoint(curve, curve.Params().Gx, curve.Params().Gy)
	result := g.EightInvEight()
	assert.True(t, result.IsOnCurve())
	assert.True(t, g.Equals(result))
}
