package tss

import (
	"encoding/json"
	"fmt"
)

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

func JsonWrap(typ string, o any, from *PartyID, to *PartyID) *JsonMessage {
	return &JsonMessage{Type: typ, From: from, To: to, Data: o}
}
