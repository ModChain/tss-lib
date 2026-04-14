// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"context"
	"crypto/rand"
	"math/big"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_getSafePrime(t *testing.T) {
	prime := new(big.Int).SetInt64(5)
	sPrime := getSafePrime(prime)
	assert.True(t, sPrime.ProbablyPrime(50))
}

func Test_getSafePrime_Bad(t *testing.T) {
	prime := new(big.Int).SetInt64(12)
	sPrime := getSafePrime(prime)
	assert.False(t, sPrime.ProbablyPrime(50))
}

func Test_Validate(t *testing.T) {
	prime := new(big.Int).SetInt64(5)
	sPrime := getSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.True(t, sgp.Validate())
}

func Test_Validate_Bad(t *testing.T) {
	prime := new(big.Int).SetInt64(12)
	sPrime := getSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.False(t, sgp.Validate())
}

func TestGetRandomGermainPrimeConcurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	sgps, err := GetRandomSafePrimesConcurrent(ctx, 1024, 2, runtime.NumCPU(), rand.Reader)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(sgps))
	for _, sgp := range sgps {
		assert.NotNil(t, sgp)
		assert.True(t, sgp.Validate())
	}
}

func TestGetRandomSafePrimesConcurrentFn_Callback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const numPrimes = 3
	var calls int32
	sgps, err := GetRandomSafePrimesConcurrentFn(ctx, 64, numPrimes, runtime.NumCPU(), rand.Reader, func() {
		atomic.AddInt32(&calls, 1)
	})
	assert.NoError(t, err)
	assert.Equal(t, numPrimes, len(sgps))
	assert.EqualValues(t, numPrimes, atomic.LoadInt32(&calls), "onFound should fire once per accepted prime")
}

func TestGetRandomSafePrimesConcurrentFn_NilCallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sgps, err := GetRandomSafePrimesConcurrentFn(ctx, 64, 2, runtime.NumCPU(), rand.Reader, nil)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(sgps))
}
