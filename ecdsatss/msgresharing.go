package ecdsatss

// messages for resharing

// resharingRound1msg is broadcast from old committee to new committee.
// Contains the ECDSA public key, VSS commitment, and session ID.
type resharingRound1msg struct {
	ECDSAPubX   []byte `json:"ecdsa_pub_x"`
	ECDSAPubY   []byte `json:"ecdsa_pub_y"`
	VCommitment []byte `json:"v_commitment"`
	SSID        []byte `json:"ssid"`
}

// resharingRound2msg1 is broadcast from new committee to new committee.
// Contains Paillier public key, modulus proof, and DLN proofs.
type resharingRound2msg1 struct {
	PaillierN  []byte   `json:"paillier_n"`
	ModProof   [][]byte `json:"mod_proof"`
	NTilde     []byte   `json:"n_tilde"`
	H1         []byte   `json:"h1"`
	H2         []byte   `json:"h2"`
	Dlnproof_1 [][]byte `json:"dlnproof_1"`
	Dlnproof_2 [][]byte `json:"dlnproof_2"`
}

// resharingRound2msg2 is broadcast from new committee to old committee (ACK).
type resharingRound2msg2 struct{}

// resharingRound3msg1 is a P2P message from old committee to each new party,
// containing the VSS share.
type resharingRound3msg1 struct {
	Share []byte `json:"share"`
}

// resharingRound3msg2 is broadcast from old committee to new committee,
// containing the VSS de-commitment.
type resharingRound3msg2 struct {
	VDecommitment [][]byte `json:"v_decommitment"`
}

// resharingRound4msg1 is a P2P message from new committee to new committee,
// containing the factorization proof.
type resharingRound4msg1 struct {
	FacProof [][]byte `json:"fac_proof"`
}

// resharingRound4msg2 is broadcast from new committee to both old and new committees (ACK).
type resharingRound4msg2 struct{}
