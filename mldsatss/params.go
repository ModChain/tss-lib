package mldsatss

import (
	"errors"
	"fmt"
)

// MaxParties is the upper bound on N in the (t, n) parameter table.
// The table is derived from params/recover.py in the reference
// implementation at github.com/GuilhemN/threshold-ml-dsa-and-raccoon
// and is only defined for N ≤ 6.
const MaxParties = 6

// ThresholdParams44 holds the parameters for one (t, n) configuration of
// threshold ML-DSA-44. See ePrint 2025/1166 for the meaning of K, R, Rp, Nu.
type ThresholdParams44 struct {
	T  uint8   // threshold: minimum signers required
	N  uint8   // total parties
	K  uint16  // parallel signing tries per attempt (fresh w per try)
	Nu float64 // ν: anisotropic scaling factor of the L-part in the hyperball
	R  float64 // r: primary ν-scaled L2 radius (party rejection bound)
	Rp float64 // r': secondary L2 radius used in Combine-side correctness check
}

// tnKey encodes (t, n) into a single comparable key.
type tnKey struct{ t, n uint8 }

// thresholdParamsTable is copied verbatim from
// thmldsa44/internal/dilithium.go:125-184 in the reference implementation.
var thresholdParamsTable = map[tnKey]ThresholdParams44{
	// N = 2
	{2, 2}: {T: 2, N: 2, K: 2, Nu: 3, R: 252778, Rp: 252833},

	// N = 3
	{2, 3}: {T: 2, N: 3, K: 3, Nu: 3, R: 310060, Rp: 310138},
	{3, 3}: {T: 3, N: 3, K: 4, Nu: 3, R: 246490, Rp: 246546},

	// N = 4
	{2, 4}: {T: 2, N: 4, K: 3, Nu: 3, R: 305919, Rp: 305997},
	{3, 4}: {T: 3, N: 4, K: 7, Nu: 3, R: 279235, Rp: 279314},
	{4, 4}: {T: 4, N: 4, K: 8, Nu: 3, R: 243463, Rp: 243519},

	// N = 5
	{2, 5}: {T: 2, N: 5, K: 3, Nu: 3, R: 285363, Rp: 285459},
	{3, 5}: {T: 3, N: 5, K: 14, Nu: 3, R: 282800, Rp: 282912},
	{4, 5}: {T: 4, N: 5, K: 30, Nu: 3, R: 259427, Rp: 259526},
	{5, 5}: {T: 5, N: 5, K: 16, Nu: 3, R: 239924, Rp: 239981},

	// N = 6
	{2, 6}: {T: 2, N: 6, K: 4, Nu: 3, R: 300265, Rp: 300362},
	{3, 6}: {T: 3, N: 6, K: 19, Nu: 3, R: 277014, Rp: 277139},
	{4, 6}: {T: 4, N: 6, K: 74, Nu: 3, R: 268705, Rp: 268831},
	{5, 6}: {T: 5, N: 6, K: 100, Nu: 3, R: 250590, Rp: 250686},
	{6, 6}: {T: 6, N: 6, K: 37, Nu: 3, R: 219245, Rp: 219301},
}

// GetThresholdParams44 returns the (t, n) parameters if supported.
func GetThresholdParams44(t, n int) (*ThresholdParams44, error) {
	if t < 2 {
		return nil, errors.New("mldsatss: threshold t must be ≥ 2")
	}
	if n < t {
		return nil, errors.New("mldsatss: total parties n must be ≥ t")
	}
	if n > MaxParties {
		return nil, fmt.Errorf("mldsatss: total parties n must be ≤ %d", MaxParties)
	}
	p, ok := thresholdParamsTable[tnKey{uint8(t), uint8(n)}]
	if !ok {
		return nil, fmt.Errorf("mldsatss: unsupported (t=%d, n=%d)", t, n)
	}
	return &p, nil
}

// sharingPatterns encodes, for each supported (t, n) configuration, the list
// (indexed by the party's rank within the signing set `act`) of honest-signer
// masks this party must XOR together to reconstruct its Lagrange-free share of
// the aggregated secret.
//
// The patterns are the output of params/recover.py from the reference
// implementation and are copied verbatim from
// thmldsa44/internal/dilithium.go:544-573.
//
// Key: (t, n). Entry i: masks for the i-th party in the current signing set.
var sharingPatterns = map[tnKey][][]uint8{
	// t == 1 or t == n is the trivial case (handled directly by recoverShare);
	// no pattern needed here.
	{2, 3}: {{3, 5}, {6}},
	{2, 4}: {{11, 13}, {7, 14}},
	{3, 4}: {{3, 9}, {6, 10}, {12, 5}},
	{2, 5}: {{27, 29, 23}, {30, 15}},
	{3, 5}: {{25, 11, 19, 13}, {7, 14, 22, 26}, {28, 21}},
	{4, 5}: {{3, 9, 17}, {6, 10, 18}, {12, 5, 20}, {24}},
	{2, 6}: {{61, 47, 55}, {62, 31, 59}},
	{3, 6}: {{27, 23, 43, 57, 39}, {51, 58, 46, 30, 54}, {45, 53, 29, 15, 60}},
	{4, 6}: {{19, 13, 35, 7, 49}, {42, 26, 38, 50, 22}, {52, 21, 44, 28, 37}, {25, 11, 14, 56, 41}},
	{5, 6}: {{3, 5, 33}, {6, 10, 34}, {12, 20, 36}, {9, 24, 40}, {48, 17, 18}},
}

// getSharingPattern returns the per-party mask lists for (t, n) when the
// scheme is non-trivial (i.e. t < n and t > 1). It returns nil for the
// trivial cases (t == 1 or t == n), which are handled by recoverShare.
func getSharingPattern(t, n uint8) [][]uint8 {
	if t == 1 || t == n {
		return nil
	}
	return sharingPatterns[tnKey{t, n}]
}
