package ecdsatss

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalPreGenerator_Progress(t *testing.T) {
	if testing.Short() {
		t.Skip("pre-parameter generation is slow; skipped in -short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var (
		mu     sync.Mutex
		events []PreParamsProgress
	)

	gen := &LocalPreGenerator{
		Context: ctx,
		Progress: func(p PreParamsProgress) {
			mu.Lock()
			events = append(events, p)
			mu.Unlock()
		},
	}

	pre, err := gen.Generate()
	require.NoError(t, err)
	require.NotNil(t, pre)

	mu.Lock()
	defer mu.Unlock()

	require.NotEmpty(t, events, "Progress callback should fire at least once")

	// SafePrimesTotal is a fixed contract.
	for _, e := range events {
		assert.Equal(t, 4, e.SafePrimesTotal)
		assert.GreaterOrEqual(t, e.SafePrimesFound, 0)
		assert.LessOrEqual(t, e.SafePrimesFound, e.SafePrimesTotal)
		assert.Greater(t, e.Elapsed, time.Duration(0))
	}

	// Final event must reflect a completed run: all 4 primes found.
	last := events[len(events)-1]
	assert.Equal(t, 4, last.SafePrimesFound, "final event should report all 4 safe primes found")

	// Reported counts must be monotonic.
	prev := 0
	for i, e := range events {
		assert.GreaterOrEqual(t, e.SafePrimesFound, prev, "SafePrimesFound must be monotonic (event %d)", i)
		prev = e.SafePrimesFound
	}
}

func TestLocalPreGenerator_NilProgress(t *testing.T) {
	// Ensure a nil Progress callback does not panic. Using the public timeout
	// entry point keeps this test cheap — it errors out quickly rather than
	// running full generation.
	_, err := GeneratePreParams(10 * time.Millisecond)
	assert.Error(t, err, "expected timeout error with a very short deadline")
}
