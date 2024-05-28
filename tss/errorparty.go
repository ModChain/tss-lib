package tss

// ErrorParty is an object that looks like a Party but will always return error
// Useful to return an error when a tss.Party is expected
type ErrorParty struct {
	Err error
}

var _ = Party(&ErrorParty{})

func (e ErrorParty) Start() error {
	return e.Err
}

func (e ErrorParty) UpdateFromBytes(wireBytes []byte, from *PartyID, isBroadcast bool) (ok bool, err error) {
	return false, e.Err
}

func (e ErrorParty) Update(msg ParsedMessage) (ok bool, err error) {
	return false, e.Err
}

func (e ErrorParty) Running() bool {
	return false
}

func (e ErrorParty) WaitingFor() []*PartyID {
	return nil
}

func (e ErrorParty) ValidateMessage(msg ParsedMessage) (bool, error) {
	return false, e.Err
}

func (e ErrorParty) StoreMessage(msg ParsedMessage) (bool, error) {
	return false, e.Err
}

func (e ErrorParty) FirstRound() Round {
	return nil
}

func (e ErrorParty) WrapError(err error, culprits ...*PartyID) error {
	return e.Err
}

func (e ErrorParty) PartyID() *PartyID {
	return nil
}

func (e ErrorParty) String() string {
	return e.Err.Error()
}

func (e ErrorParty) setRound(Round) error {
	return e.Err
}

func (e ErrorParty) round() Round {
	return nil
}

func (e ErrorParty) advance() {}
func (e ErrorParty) lock()    {}
func (e ErrorParty) unlock()  {}
