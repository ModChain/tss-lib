package tss

import (
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewError(t *testing.T) {
	cause := errors.New("test cause")
	culprit := NewPartyID("c1", "culprit1", big.NewInt(1))
	victim := NewPartyID("v1", "victim1", big.NewInt(2))

	tssErr := NewError(cause, "test-task", 3, victim, culprit)

	assert.Equal(t, cause, tssErr.Cause())
	assert.Equal(t, cause, tssErr.Unwrap())
	assert.Equal(t, "test-task", tssErr.Task())
	assert.Equal(t, 3, tssErr.Round())
	assert.Equal(t, victim, tssErr.Victim())
	assert.Len(t, tssErr.Culprits(), 1)
	assert.Equal(t, culprit, tssErr.Culprits()[0])
	assert.Contains(t, tssErr.Error(), "test cause")
}
