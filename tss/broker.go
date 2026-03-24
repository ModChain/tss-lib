package tss

import "fmt"

// MessageReceiver defines an interface for receiving JSON messages.
type MessageReceiver interface {
	Receive(msg *JsonMessage) error
}

// MessageBroker extends MessageReceiver with the ability to connect message handlers by type.
type MessageBroker interface {
	MessageReceiver
	Connect(typ string, dest MessageReceiver)
}

type testBroker struct {
	rcv map[string]MessageReceiver
}

// NewTestBroker creates a simple in-memory message broker for testing purposes.
func NewTestBroker() *testBroker {
	return &testBroker{rcv: make(map[string]MessageReceiver)}
}

func (b *testBroker) Receive(msg *JsonMessage) error {
	tgt, ok := b.rcv[msg.Type]
	if !ok {
		return fmt.Errorf("no handler for message type %s", msg.Type)
	}
	return tgt.Receive(msg)
}

func (b *testBroker) Connect(typ string, dest MessageReceiver) {
	b.rcv[typ] = dest
}
