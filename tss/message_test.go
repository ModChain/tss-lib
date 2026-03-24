package tss

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMessageWrapper(t *testing.T) {
	from := NewPartyID("from", "sender", big.NewInt(1))
	to := NewPartyID("to", "receiver", big.NewInt(2))

	routing := MessageRouting{
		From:        from,
		To:          []*PartyID{to},
		IsBroadcast: true,
	}

	wrapper := NewMessageWrapper(routing, nil)
	assert.NotNil(t, wrapper)
	assert.True(t, wrapper.IsBroadcast)
	assert.Equal(t, from.MessageWrapper_PartyID, wrapper.From)
	assert.Len(t, wrapper.To, 1)
}
