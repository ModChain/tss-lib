package mldsatss

import (
	"crypto/sha3"
	"errors"

	"github.com/KarpelesLab/mldsa"
)

// TrustedDealerKeygen44 derives a threshold ML-DSA-44 public key and N
// per-party private-key shares from a 32-byte seed. It mirrors
// thmldsa44/internal/NewThresholdKeysFromSeed from the reference
// implementation (a trusted dealer; no DKG).
//
// The returned PublicKey is byte-identical to a stock FIPS 204 ML-DSA-44
// public key and can be used with mldsa.PublicKey44.Verify.
func TrustedDealerKeygen44(seed [32]byte, params *ThresholdParams44) (*PublicKey, []*Key44, error) {
	if params == nil {
		return nil, nil, errors.New("mldsatss: params must not be nil")
	}
	n := int(params.N)
	t := int(params.T)
	if n > MaxParties || t < 2 || t > n {
		return nil, nil, errors.New("mldsatss: invalid threshold params")
	}

	// Expand seed into rho + per-party signing keys.
	h := sha3.NewSHAKE256()
	h.Write(seed[:])
	// Domain-separation byte pair, same as stock ML-DSA-44.
	h.Write([]byte{byte(mldsa.K44), byte(mldsa.L44)})

	keys := make([]*Key44, n)
	var rho [32]byte
	h.Read(rho[:])

	// Consume one per-party 32-byte signing key slot to stay symmetric with
	// the reference's SHAKE stream layout (we don't actually use it for
	// threshold signing since each Round1 draws rhop from fresh randomness).
	var discard [32]byte
	for i := 0; i < n; i++ {
		h.Read(discard[:])
		keys[i] = &Key44{
			Id:     uint8(i),
			Rho:    rho,
			Shares: make(map[uint8]*Share44),
		}
		for row := 0; row < mldsa.K44; row++ {
			for col := 0; col < mldsa.L44; col++ {
				keys[i].A[row*mldsa.L44+col] = mldsa.SampleA(rho[:], row, col)
			}
		}
	}

	// Matrix A is shared by all parties and used for pk too.
	var A [mldsa.K44 * mldsa.L44]mldsa.NttElement = keys[0].A

	// Aggregate secret accumulators — held only by the dealer (discarded
	// after pk is computed).
	var s1hTotal [mldsa.L44]mldsa.NttElement
	var s2Total [mldsa.K44]mldsa.RingElement

	// Enumerate every honest-signer mask of popcount (n - t + 1) via
	// Gosper's hack. Each mask's share is distributed to every party whose
	// bit is set in the mask.
	mask := uint8((1 << uint(n-t+1)) - 1)
	end := uint8(1) << uint(n)
	for mask < end {
		var sSeed [64]byte
		h.Read(sSeed[:])

		var s1 [mldsa.L44]mldsa.RingElement
		var s2 [mldsa.K44]mldsa.RingElement
		for j := 0; j < mldsa.L44; j++ {
			s1[j] = mldsa.SampleBoundedEta2(sSeed[:], uint16(j))
		}
		for j := 0; j < mldsa.K44; j++ {
			s2[j] = mldsa.SampleBoundedEta2(sSeed[:], uint16(j+mldsa.L44))
		}
		share := &Share44{S1: s1, S2: s2}
		for j := 0; j < mldsa.L44; j++ {
			share.S1h[j] = mldsa.NTT(s1[j])
		}
		for j := 0; j < mldsa.K44; j++ {
			share.S2h[j] = mldsa.NTT(s2[j])
		}

		// Aggregate into s1h and s2 (plain) for pk computation.
		for j := 0; j < mldsa.L44; j++ {
			s1hTotal[j] = mldsa.NttAdd(s1hTotal[j], share.S1h[j])
		}
		for j := 0; j < mldsa.K44; j++ {
			s2Total[j] = mldsa.RingAdd(s2Total[j], s2[j])
		}

		// Distribute the share to every party whose bit is in mask.
		for i := 0; i < n; i++ {
			if mask&(1<<uint(i)) != 0 {
				keys[i].Shares[mask] = share
			}
		}

		// Gosper's hack: next mask with same popcount.
		c := mask & -mask
		r := mask + c
		mask = (((r ^ mask) >> 2) / c) | r
	}

	// Compute t = A*s1h + s2, then t1 = Power2Round_high(t).
	var t1 [mldsa.K44]mldsa.RingElement
	for i := 0; i < mldsa.K44; i++ {
		var acc mldsa.NttElement
		for j := 0; j < mldsa.L44; j++ {
			acc = mldsa.NttAdd(acc, mldsa.NttMul(A[i*mldsa.L44+j], s1hTotal[j]))
		}
		tPoly := mldsa.RingAdd(mldsa.InvNTT(acc), s2Total[i])
		for j := 0; j < mldsa.N; j++ {
			hi, _ := mldsa.Power2Round(tPoly[j])
			t1[i][j] = hi
		}
	}

	// Pack the public key into its canonical FIPS 204 form.
	pkBytes := make([]byte, 32+mldsa.K44*mldsa.EncodingSizeT1)
	copy(pkBytes[:32], rho[:])
	off := 32
	for i := 0; i < mldsa.K44; i++ {
		copy(pkBytes[off:], mldsa.PackT1(t1[i]))
		off += mldsa.EncodingSizeT1
	}

	pk, err := mldsa.NewPublicKey44(pkBytes)
	if err != nil {
		return nil, nil, err
	}

	// Tr = SHAKE256(packed pk).
	var tr [64]byte
	hTr := sha3.NewSHAKE256()
	hTr.Write(pkBytes)
	hTr.Read(tr[:])

	for i := 0; i < n; i++ {
		keys[i].Tr = tr
		keys[i].T1 = t1
	}

	return pk, keys, nil
}
