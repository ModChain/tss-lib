package tss

import (
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -----
// Error tests (extending existing error_test.go)
// -----

func TestErrorStringWithCulprits(t *testing.T) {
	cause := errors.New("bad data")
	victim := NewPartyID("1", "P1", big.NewInt(1))
	victim.Index = 0
	culprit := NewPartyID("2", "P2", big.NewInt(2))
	culprit.Index = 1

	e := NewError(cause, "signing", 5, victim, culprit)
	s := e.Error()
	assert.Contains(t, s, "signing")
	assert.Contains(t, s, "round 5")
	assert.Contains(t, s, "culprits")
}

func TestErrorStringNoCulprits(t *testing.T) {
	cause := errors.New("bad data")
	victim := NewPartyID("1", "P1", big.NewInt(1))
	victim.Index = 0

	e := NewError(cause, "resharing", 2, victim)
	s := e.Error()
	assert.Contains(t, s, "resharing")
	assert.Contains(t, s, "round 2")
	assert.NotContains(t, s, "culprits")
}

func TestErrorStringNil(t *testing.T) {
	var e *Error
	assert.Equal(t, "Error is nil", e.Error())

	e2 := &Error{}
	assert.Equal(t, "Error is nil", e2.Error())
}

// -----
// ErrorParty tests
// -----

func TestErrorParty(t *testing.T) {
	err := errors.New("test error")
	ep := ErrorParty{Err: err}

	assert.Equal(t, err, ep.Start())
	ok, e := ep.UpdateFromBytes(nil, nil, false)
	assert.False(t, ok)
	assert.Equal(t, err, e)
	ok, e = ep.Update(nil)
	assert.False(t, ok)
	assert.Equal(t, err, e)
	assert.False(t, ep.Running())
	assert.Nil(t, ep.WaitingFor())
	ok, e = ep.ValidateMessage(nil)
	assert.False(t, ok)
	assert.Equal(t, err, e)
	ok, e = ep.StoreMessage(nil)
	assert.False(t, ok)
	assert.Equal(t, err, e)
	assert.Nil(t, ep.FirstRound())
	assert.Equal(t, err, ep.WrapError(errors.New("other")))
	assert.Nil(t, ep.PartyID())
	assert.Equal(t, "test error", ep.String())
}

// -----
// PartyID tests (extending existing party_id_test.go)
// -----

func TestNewPartyID(t *testing.T) {
	key := big.NewInt(42)
	pid := NewPartyID("alice", "Alice", key)
	assert.Equal(t, "alice", pid.Id)
	assert.Equal(t, "Alice", pid.Moniker)
	assert.Equal(t, 0, key.Cmp(pid.KeyInt()))
	assert.Equal(t, -1, pid.Index)
}

func TestPartyIDString(t *testing.T) {
	pid := NewPartyID("1", "Alice", big.NewInt(10))
	pid.Index = 3
	assert.Equal(t, "{3,Alice}", pid.String())
}

func TestSortPartyIDs(t *testing.T) {
	p1 := NewPartyID("1", "A", big.NewInt(30))
	p2 := NewPartyID("2", "B", big.NewInt(10))
	p3 := NewPartyID("3", "C", big.NewInt(20))

	sorted := SortPartyIDs(UnSortedPartyIDs{p1, p2, p3})
	assert.Equal(t, 3, len(sorted))
	assert.Equal(t, 0, big.NewInt(10).Cmp(sorted[0].KeyInt()))
	assert.Equal(t, 0, big.NewInt(20).Cmp(sorted[1].KeyInt()))
	assert.Equal(t, 0, big.NewInt(30).Cmp(sorted[2].KeyInt()))
	assert.Equal(t, 0, sorted[0].Index)
	assert.Equal(t, 1, sorted[1].Index)
	assert.Equal(t, 2, sorted[2].Index)
}

func TestSortPartyIDsStartAt(t *testing.T) {
	p1 := NewPartyID("1", "A", big.NewInt(30))
	p2 := NewPartyID("2", "B", big.NewInt(10))

	sorted := SortPartyIDs(UnSortedPartyIDs{p1, p2}, 5)
	assert.Equal(t, 5, sorted[0].Index)
	assert.Equal(t, 6, sorted[1].Index)
}

func TestSortedPartyIDsToUnSorted(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	unsorted := ids.ToUnSorted()
	assert.Equal(t, len(ids), len(unsorted))
}

func TestGenerateTestPartyIDs(t *testing.T) {
	ids := GenerateTestPartyIDs(5)
	assert.Equal(t, 5, len(ids))
	for i := 0; i < len(ids)-1; i++ {
		assert.True(t, ids[i].KeyInt().Cmp(ids[i+1].KeyInt()) < 0)
	}
}

func TestGenerateTestPartyIDsStartAt(t *testing.T) {
	ids := GenerateTestPartyIDs(3, 10)
	assert.Equal(t, 3, len(ids))
	assert.Equal(t, 10, ids[0].Index)
}

// -----
// Curve tests
// -----

func TestCurves(t *testing.T) {
	assert.NotNil(t, S256())
	assert.NotNil(t, Edwards())
	assert.NotNil(t, EC())
	assert.Equal(t, S256(), EC())
}

func TestGetCurveByName(t *testing.T) {
	c, ok := GetCurveByName(Secp256k1)
	assert.True(t, ok)
	assert.NotNil(t, c)

	c2, ok2 := GetCurveByName(Ed25519)
	assert.True(t, ok2)
	assert.NotNil(t, c2)

	_, ok3 := GetCurveByName("nonexistent")
	assert.False(t, ok3)
}

func TestGetCurveName(t *testing.T) {
	name, ok := GetCurveName(S256())
	assert.True(t, ok)
	assert.Equal(t, Secp256k1, name)

	name2, ok2 := GetCurveName(Edwards())
	assert.True(t, ok2)
	assert.Equal(t, Ed25519, name2)

	_, ok3 := GetCurveName(elliptic.P256())
	assert.False(t, ok3)
}

func TestSameCurve(t *testing.T) {
	assert.True(t, SameCurve(S256(), S256()))
	assert.True(t, SameCurve(Edwards(), Edwards()))
	assert.False(t, SameCurve(S256(), Edwards()))
	assert.False(t, SameCurve(S256(), elliptic.P256()))
}

func TestRegisterCurve(t *testing.T) {
	p256 := elliptic.P256()
	RegisterCurve("p256", p256)
	c, ok := GetCurveByName("p256")
	assert.True(t, ok)
	assert.Equal(t, p256, c)
	delete(registry, "p256")
}

func TestSetCurve(t *testing.T) {
	original := EC()
	defer SetCurve(original)

	SetCurve(Edwards())
	assert.Equal(t, Edwards(), EC())

	assert.Panics(t, func() { SetCurve(nil) })
}

// -----
// PeerContext tests
// -----

func TestPeerContext(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	ctx := NewPeerContext(ids)
	assert.Equal(t, ids, ctx.IDs())

	newIds := GenerateTestPartyIDs(5)
	ctx.SetIDs(newIds)
	assert.Equal(t, newIds, ctx.IDs())
}

// -----
// Parameters tests (extending existing params_test.go)
// -----

func TestNewParametersAccessors(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	ctx := NewPeerContext(ids)
	params := NewParameters(S256(), ctx, ids[0], 3, 1)

	assert.Equal(t, S256(), params.EC())
	assert.Equal(t, ctx, params.Parties())
	assert.Equal(t, ids[0], params.PartyID())
	assert.Equal(t, 3, params.PartyCount())
	assert.Equal(t, 1, params.Threshold())
	assert.True(t, params.Concurrency() > 0)
	assert.Equal(t, 5*time.Minute, params.SafePrimeGenTimeout())
	assert.False(t, params.NoProofMod())
	assert.False(t, params.NoProofFac())
	assert.NotNil(t, params.PartialKeyRand())
	assert.NotNil(t, params.Rand())
	assert.NotNil(t, params.Broker())
}

func TestParametersSetters(t *testing.T) {
	ids := GenerateTestPartyIDs(3)
	ctx := NewPeerContext(ids)
	params := NewParameters(S256(), ctx, ids[0], 3, 1)

	params.SetConcurrency(4)
	assert.Equal(t, 4, params.Concurrency())

	params.SetSafePrimeGenTimeout(10 * time.Second)
	assert.Equal(t, 10*time.Second, params.SafePrimeGenTimeout())

	params.SetNoProofMod()
	assert.True(t, params.NoProofMod())

	params.SetNoProofFac()
	assert.True(t, params.NoProofFac())

	broker := NewTestBroker()
	params.SetBroker(broker)
	assert.Equal(t, broker, params.Broker())

	params.SetPartialKeyRand(nil)
	assert.Nil(t, params.PartialKeyRand())

	params.SetRand(nil)
	assert.Nil(t, params.Rand())
}

// -----
// ReSharingParameters tests
// -----

func TestReSharingParameters(t *testing.T) {
	oldIDs := GenerateTestPartyIDs(3)
	newIDs := GenerateTestPartyIDs(5)
	oldCtx := NewPeerContext(oldIDs)
	newCtx := NewPeerContext(newIDs)

	rgParams := NewReSharingParameters(S256(), oldCtx, newCtx, oldIDs[0], 3, 1, 5, 2)

	assert.Equal(t, oldCtx, rgParams.OldParties())
	assert.Equal(t, 3, rgParams.OldPartyCount())
	assert.Equal(t, newCtx, rgParams.NewParties())
	assert.Equal(t, 5, rgParams.NewPartyCount())
	assert.Equal(t, 2, rgParams.NewThreshold())
	assert.Equal(t, 8, rgParams.OldAndNewPartyCount())
	assert.Equal(t, 8, len(rgParams.OldAndNewParties()))
	assert.True(t, rgParams.IsOldCommittee())
}

func TestReSharingParametersIsNewCommittee(t *testing.T) {
	oldIDs := GenerateTestPartyIDs(3)
	newIDs := GenerateTestPartyIDs(5)
	oldCtx := NewPeerContext(oldIDs)
	newCtx := NewPeerContext(newIDs)

	rgParams := NewReSharingParameters(S256(), oldCtx, newCtx, newIDs[0], 3, 1, 5, 2)
	assert.True(t, rgParams.IsNewCommittee())
}

func TestReSharingParametersNotInEitherCommittee(t *testing.T) {
	oldIDs := GenerateTestPartyIDs(3)
	newIDs := GenerateTestPartyIDs(5)
	oldCtx := NewPeerContext(oldIDs)
	newCtx := NewPeerContext(newIDs)

	outsider := NewPartyID("outsider", "Outsider", big.NewInt(999999))
	outsider.Index = 0
	rgParams := NewReSharingParameters(S256(), oldCtx, newCtx, outsider, 3, 1, 5, 2)
	assert.False(t, rgParams.IsOldCommittee())
	assert.False(t, rgParams.IsNewCommittee())
}

// -----
// JSON message tests
// -----

func TestJsonWrap(t *testing.T) {
	from := NewPartyID("1", "P1", big.NewInt(1))
	to := NewPartyID("2", "P2", big.NewInt(2))
	data := map[string]int{"value": 42}
	msg := JsonWrap("test_type", data, from, to)

	assert.Equal(t, "test_type", msg.Type)
	assert.Equal(t, from, msg.From)
	assert.Equal(t, to, msg.To)
	assert.Equal(t, data, msg.Data)
}

func TestJsonGet(t *testing.T) {
	type Payload struct {
		Value int `json:"value"`
	}

	// from direct type
	p := &Payload{Value: 42}
	msg := &JsonMessage{Type: "test", Data: p}
	got, err := JsonGet[Payload](msg)
	require.NoError(t, err)
	assert.Equal(t, 42, got.Value)

	// from raw JSON
	raw := json.RawMessage(`{"value":99}`)
	msg2 := &JsonMessage{Type: "test", Data: raw}
	got2, err := JsonGet[Payload](msg2)
	require.NoError(t, err)
	assert.Equal(t, 99, got2.Value)

	// incompatible type
	msg3 := &JsonMessage{Type: "test", Data: "not a payload"}
	_, err = JsonGet[Payload](msg3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "incompatible type")
}

func TestJsonMessageUnmarshalJSON(t *testing.T) {
	jsonStr := `{"type":"round1","from":null,"to":null,"data":{"hello":"world"}}`
	var msg JsonMessage
	err := json.Unmarshal([]byte(jsonStr), &msg)
	require.NoError(t, err)
	assert.Equal(t, "round1", msg.Type)
	raw, ok := msg.Data.(json.RawMessage)
	assert.True(t, ok)
	assert.Contains(t, string(raw), "hello")
}

// -----
// Broker tests
// -----

func TestTestBroker(t *testing.T) {
	broker := NewTestBroker()

	received := false
	var handler MessageReceiver = receiverFunc(func(msg *JsonMessage) error {
		received = true
		return nil
	})

	broker.Connect("test_msg", handler)

	err := broker.Receive(&JsonMessage{Type: "test_msg"})
	assert.NoError(t, err)
	assert.True(t, received)

	err = broker.Receive(&JsonMessage{Type: "unknown"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no handler")
}

type receiverFunc func(msg *JsonMessage) error

func (f receiverFunc) Receive(msg *JsonMessage) error { return f(msg) }

// -----
// JsonExpect tests
// -----

func TestNewJsonExpect(t *testing.T) {
	type Payload struct {
		Value int `json:"value"`
	}

	p1 := NewPartyID("1", "P1", big.NewInt(1))
	p2 := NewPartyID("2", "P2", big.NewInt(2))
	parties := []*PartyID{p1, p2}

	var cbParties []*PartyID
	var cbPackets []*Payload

	rcv := NewJsonExpect[Payload]("round1", parties, func(from []*PartyID, packets []*Payload) {
		cbParties = from
		cbPackets = packets
	})

	err := rcv.Receive(&JsonMessage{Type: "round1", From: p1, Data: &Payload{Value: 10}})
	assert.NoError(t, err)
	assert.Nil(t, cbParties)

	err = rcv.Receive(&JsonMessage{Type: "round2", From: p2, Data: &Payload{Value: 20}})
	assert.Error(t, err)

	err = rcv.Receive(&JsonMessage{Type: "round1", From: p2, Data: &Payload{Value: 20}})
	assert.NoError(t, err)
	assert.NotNil(t, cbParties)
	assert.Equal(t, 2, len(cbPackets))
	assert.Equal(t, 10, cbPackets[0].Value)
	assert.Equal(t, 20, cbPackets[1].Value)

	err = rcv.Receive(&JsonMessage{Type: "round1", From: p1, Data: &Payload{Value: 30}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "completed")
}

func TestNewJsonExpectUnknownPeer(t *testing.T) {
	type Payload struct {
		Value int `json:"value"`
	}

	p1 := NewPartyID("1", "P1", big.NewInt(1))
	unknown := NewPartyID("99", "Unknown", big.NewInt(99))
	parties := []*PartyID{p1}

	rcv := NewJsonExpect[Payload]("round1", parties, func([]*PartyID, []*Payload) {})
	err := rcv.Receive(&JsonMessage{Type: "round1", From: unknown, Data: &Payload{Value: 10}})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected source")
}

// -----
// BaseParty tests
// -----

func TestBasePartyRunning(t *testing.T) {
	bp := &BaseParty{}
	assert.False(t, bp.Running())
}

func TestBasePartyString(t *testing.T) {
	bp := &BaseParty{}
	assert.Equal(t, "No more rounds", bp.String())
}

func TestBasePartyWaitingForEmpty(t *testing.T) {
	bp := &BaseParty{}
	assert.Equal(t, []*PartyID{}, bp.WaitingFor())
}

func TestBasePartyWrapErrorNoRound(t *testing.T) {
	bp := &BaseParty{}
	err := bp.WrapError(errors.New("test"))
	tssErr, ok := err.(*Error)
	require.True(t, ok)
	assert.Equal(t, -1, tssErr.Round())
}

func TestBasePartyValidateMessageNil(t *testing.T) {
	bp := &BaseParty{}
	ok, err := bp.ValidateMessage(nil)
	assert.False(t, ok)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "nil"))
}

// -----
// MessageImpl tests (extending existing message_test.go)
// -----

func TestMessageImplString(t *testing.T) {
	from := NewPartyID("1", "P1", big.NewInt(1))
	from.Index = 0
	routing := MessageRouting{
		From:        from,
		To:          nil,
		IsBroadcast: true,
	}
	wrapper := NewMessageWrapper(routing, nil)
	msg := NewMessage(routing, nil, wrapper)
	s := msg.String()
	assert.Contains(t, s, "all")
	assert.Contains(t, s, "P1")
}

func TestMessageImplGetters(t *testing.T) {
	from := NewPartyID("1", "P1", big.NewInt(1))
	from.Index = 0
	to := NewPartyID("2", "P2", big.NewInt(2))
	to.Index = 1
	routing := MessageRouting{
		From:                    from,
		To:                      []*PartyID{to},
		IsBroadcast:             true,
		IsToOldCommittee:        true,
		IsToOldAndNewCommittees: false,
	}
	wrapper := NewMessageWrapper(routing, nil)
	msg := NewMessage(routing, nil, wrapper)

	assert.Equal(t, from, msg.GetFrom())
	assert.Equal(t, []*PartyID{to}, msg.GetTo())
	assert.True(t, msg.IsBroadcast())
	assert.True(t, msg.IsToOldCommittee())
	assert.False(t, msg.IsToOldAndNewCommittees())
	assert.NotNil(t, msg.WireMsg())
}
