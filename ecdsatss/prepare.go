package ecdsatss

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"runtime"
	"sync"
	"time"

	"github.com/KarpelesLab/tss-lib/v2/common"
	"github.com/KarpelesLab/tss-lib/v2/crypto/paillier"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	paillierModulusLen = 2048
	// Two 1024-bit safe primes to produce NTilde
	safePrimeBitLen = 1024
	// Ticker for printing log statements while generating primes/modulus
	logProgressTickInterval = 8 * time.Second
	// Safe big len using random for ssid
	SafeBitLen = 1024
)

// LocalPreGenerator configures and generates pre-parameters for the ECDSA TSS protocol.
type LocalPreGenerator struct {
	context.Context                                // Context used to stop generation if needed
	Rand            io.Reader                      // reader used for random, defaults to rand.Reader if nil
	Concurrency     int                            // concurrency, defaults to runtime.NumCPU() if nil
	Progress        func(p PreParamsProgress)      // optional; invoked as safe primes are found. Safe to be nil.
}

// PreParamsProgress reports progress of pre-parameter generation.
// Generate finds 4 safe primes total (2 for the Paillier key, 2 for NTilde);
// SafePrimesFound increases monotonically from 0 to SafePrimesTotal as each
// prime is accepted. Rejected Paillier candidates (when |P-Q| is too small)
// do not decrement the counter.
type PreParamsProgress struct {
	SafePrimesFound int           // number of safe primes accepted so far (0..SafePrimesTotal)
	SafePrimesTotal int           // always 4
	Elapsed         time.Duration // time since Generate started
}

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
// If pre-parameters could not be generated before the timeout, an error is returned.
func GeneratePreParams(timeout time.Duration, optionalConcurrency ...int) (*LocalPreParams, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	opts := &LocalPreGenerator{Context: ctx}
	if len(optionalConcurrency) > 0 {
		opts.Concurrency = optionalConcurrency[0]
	}
	return opts.Generate()
}

func (g *LocalPreGenerator) getConcurrency() int {
	if g == nil || g.Concurrency <= 0 {
		return runtime.NumCPU()
	}
	return g.Concurrency
}

func (g *LocalPreGenerator) getRand() io.Reader {
	if g == nil || g.Rand == nil {
		return rand.Reader
	}
	return g.Rand
}

func (g *LocalPreGenerator) getContext() context.Context {
	if g == nil || g.Context == nil {
		return context.Background()
	}
	return g
}

// Generate computes the Paillier key pair and safe primes required for the protocol.
func (g *LocalPreGenerator) Generate() (*LocalPreParams, error) {
	concurrency := g.getConcurrency()

	if concurrency /= 3; concurrency < 1 {
		concurrency = 1
	}

	// progress tracking: 4 safe primes total, 2 per branch. Paillier's |P-Q|
	// rejection loop can emit more than 2 callbacks; we cap each branch's
	// contribution at 2 so the reported count stays within [0, total].
	const (
		paillierBranchPrimes = 2
		ntildeBranchPrimes   = 2
		totalSafePrimes      = paillierBranchPrimes + ntildeBranchPrimes
	)
	var (
		progressMu      sync.Mutex
		paillierCount   int
		ntildeCount     int
		started         = time.Now()
	)
	report := func() {
		if g == nil || g.Progress == nil {
			return
		}
		progressMu.Lock()
		found := paillierCount + ntildeCount
		progressMu.Unlock()
		g.Progress(PreParamsProgress{
			SafePrimesFound: found,
			SafePrimesTotal: totalSafePrimes,
			Elapsed:         time.Since(started),
		})
	}
	paillierOnFound := func() {
		progressMu.Lock()
		if paillierCount < paillierBranchPrimes {
			paillierCount++
		}
		progressMu.Unlock()
		report()
	}
	ntildeOnFound := func() {
		progressMu.Lock()
		if ntildeCount < ntildeBranchPrimes {
			ntildeCount++
		}
		progressMu.Unlock()
		report()
	}

	// prepare for concurrent Paillier and safe prime generation
	paiCh := make(chan *paillier.PrivateKey, 1)
	sgpCh := make(chan []*common.GermainSafePrime, 1)

	// 4. generate Paillier public key E_i, private key and proof
	go func(ch chan<- *paillier.PrivateKey) {
		// more concurrency weight is assigned here because the paillier primes have a requirement of having "large" P-Q
		PiPaillierSk, _, err := paillier.GenerateKeyPairFn(g.getContext(), g.getRand(), paillierModulusLen, paillierOnFound, concurrency*2)
		if err != nil {
			ch <- nil
			return
		}
		ch <- PiPaillierSk
	}(paiCh)

	// 5-7. generate safe primes for ZKPs used later on
	go func(ch chan<- []*common.GermainSafePrime) {
		var err error
		sgps, err := common.GetRandomSafePrimesConcurrentFn(g.getContext(), safePrimeBitLen, 2, concurrency, g.getRand(), ntildeOnFound)
		if err != nil {
			ch <- nil
			return
		}
		ch <- sgps
	}(sgpCh)

	var sgps []*common.GermainSafePrime
	var paiSK *paillier.PrivateKey

consumer:
	for {
		select {
		case sgps = <-sgpCh:
			if sgps == nil ||
				sgps[0] == nil || sgps[1] == nil ||
				!sgps[0].Prime().ProbablyPrime(30) || !sgps[1].Prime().ProbablyPrime(30) ||
				!sgps[0].SafePrime().ProbablyPrime(30) || !sgps[1].SafePrime().ProbablyPrime(30) {
				return nil, errors.New("timeout or error while generating the safe primes")
			}
			if paiSK != nil {
				break consumer
			}
		case paiSK = <-paiCh:
			if paiSK == nil {
				return nil, errors.New("timeout or error while generating the Paillier secret key")
			}
			if sgps != nil {
				break consumer
			}
		}
	}

	P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
	NTildei := new(big.Int).Mul(P, Q)
	modNTildeI := common.ModInt(NTildei)

	p, q := sgps[0].Prime(), sgps[1].Prime()
	modPQ := common.ModInt(new(big.Int).Mul(p, q))
	f1 := common.GetRandomPositiveRelativelyPrimeInt(g.getRand(), NTildei)
	alpha := common.GetRandomPositiveRelativelyPrimeInt(g.getRand(), NTildei)
	beta := modPQ.ModInverse(alpha)
	h1i := modNTildeI.Mul(f1, f1)
	h2i := modNTildeI.Exp(h1i, alpha)

	preParams := &LocalPreParams{
		PaillierSK: paiSK,
		NTildei:    NTildei,
		H1i:        h1i,
		H2i:        h2i,
		Alpha:      alpha,
		Beta:       beta,
		P:          p,
		Q:          q,
	}
	return preParams, nil
}
