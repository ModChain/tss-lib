package tss

import (
	"encoding/json"
	"errors"
	"fmt"
	sync "sync"
)

type JsonExpect interface {
	Receive(msg *JsonMessage) error
}

// JsonExpect is an object used to collect messages from peers and trigger a callback once
// enough messages have been collected
type jsonExpect[T any] struct {
	Type    string
	From    []*PartyID
	Packet  []*T
	missing int
	lock    sync.Mutex
	cb      func([]*PartyID, []*T)
}

// JsonMessage is an object storing any kind of object for json transmission
type JsonMessage struct {
	Type string   `json:"type"`
	From *PartyID `json:"from"`
	To   *PartyID `json:"to"`
	Data any      `json:"data"`
}

type rawJsonMsg struct {
	Type string          `json:"type"`
	From *PartyID        `json:"from"`
	To   *PartyID        `json:"to"`
	Data json.RawMessage `json:"data"`
}

// UnmarshalJSON will set Type to the right value, and Data to a json.RawMessage of the actual data
func (j *JsonMessage) UnmarshalJSON(data []byte) error {
	// use rawJsonMsg to ensure Data is json.RawMessage
	var v *rawJsonMsg
	err := json.Unmarshal(data, &v)
	if err != nil {
		return err
	}
	j.Type = v.Type
	j.Data = v.Data
	j.From = v.From
	j.To = v.To
	return nil
}

// JsonGet returns the object included in a JsonMessage if it is of the given type, or will unmarshal
// to said type if the message was just recieved
func JsonGet[T any](j *JsonMessage) (*T, error) {
	switch n := j.Data.(type) {
	case json.RawMessage:
		var r *T
		err := json.Unmarshal(n, &r)
		return r, err
	case *T:
		return n, nil
	default:
		return nil, fmt.Errorf("incompatible type %T while getting %T", n, (*T)(nil))
	}
}

// Jsonwrap wraps any object into a JsonMessage for transmission
func JsonWrap(typ string, o any, from *PartyID, to *PartyID) *JsonMessage {
	return &JsonMessage{Type: typ, From: from, To: to, Data: o}
}

// NewJsonExpect returns a new JsonExpect of the given type that can be used to collect
// packets from multiple parties, and trigger a callback once everything has been collected
func NewJsonExpect[T any](typ string, parties []*PartyID, cb func([]*PartyID, []*T)) JsonExpect {
	res := &jsonExpect[T]{
		Type:    typ,
		From:    parties,
		Packet:  make([]*T, len(parties)),
		missing: len(parties), // nothing received yet
	}
	return res
}

func (e *jsonExpect[T]) Receive(msg *JsonMessage) error {
	if msg.Type != e.Type {
		// ignore
		return fmt.Errorf("unexpected message type %s while we want %s", msg.Type, e.Type)
	}

	e.lock.Lock()
	defer e.lock.Unlock()

	if e.missing == 0 {
		return errors.New("json expect has completed")
	}

	// parse object if needed
	obj, err := JsonGet[T](msg)
	if err != nil {
		return err
	}

	// locate the party
	ki := msg.From.KeyInt()
	for n, p := range e.From {
		if e.Packet[n] != nil {
			// do not need to run expensive big.Int.Cmp() if we already got the packet
			continue
		}
		if p.KeyInt().Cmp(ki) == 0 {
			e.Packet[n] = obj
			e.missing -= 1
			if e.missing == 0 {
				// complete!
				e.cb(e.From, e.Packet)
			}
			return nil
		}
	}

	// no party found
	return errors.New("unexpected source peer")
}
