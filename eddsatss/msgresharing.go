package eddsatss

// messages for EdDSA resharing

// resharingRound1msg is broadcast from old committee to new committee.
// Contains the EDDSAPub and a commitment to the VSS polynomial.
type resharingRound1msg struct {
	EDDSAPubX   []byte `json:"eddsa_pub_x"`
	EDDSAPubY   []byte `json:"eddsa_pub_y"`
	VCommitment []byte `json:"v_commitment"`
}

// resharingRound2msg is an empty ACK from new committee to old committee.
type resharingRound2msg struct{}

// resharingRound3msg1 is a P2P message from old committee to each new party,
// containing the VSS share for that party.
type resharingRound3msg1 struct {
	Share []byte `json:"share"`
}

// resharingRound3msg2 is broadcast from old committee to new committee,
// containing the decommitment to the VSS polynomial.
type resharingRound3msg2 struct {
	VDecommitment [][]byte `json:"v_decommitment"`
}

// resharingRound4msg is an empty ACK from new committee to both old and new committees.
type resharingRound4msg struct{}
