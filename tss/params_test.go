package tss

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewParametersValidation verifies that NewParameters panics on invalid inputs.
func TestNewParametersValidation(t *testing.T) {
	ec := EC()

	assert.Panics(t, func() {
		NewParameters(nil, nil, nil, 3, 1)
	}, "nil curve should panic")

	assert.Panics(t, func() {
		NewParameters(ec, nil, nil, 0, 0)
	}, "partyCount=0 should panic")

	assert.Panics(t, func() {
		NewParameters(ec, nil, nil, -1, 0)
	}, "negative partyCount should panic")

	assert.Panics(t, func() {
		NewParameters(ec, nil, nil, 3, 3)
	}, "threshold=partyCount should panic")

	assert.Panics(t, func() {
		NewParameters(ec, nil, nil, 3, 5)
	}, "threshold>partyCount should panic")

	assert.Panics(t, func() {
		NewParameters(ec, nil, nil, 3, -1)
	}, "negative threshold should panic")

	// Valid parameters should not panic
	assert.NotPanics(t, func() {
		NewParameters(ec, nil, nil, 3, 1)
	}, "valid parameters should not panic")

	assert.NotPanics(t, func() {
		NewParameters(ec, nil, nil, 1, 0)
	}, "threshold=0, partyCount=1 should be valid")
}
