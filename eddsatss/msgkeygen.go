package eddsatss

// messages for EdDSA keygen

type keygenRound1msg struct {
	Commitment []byte `json:"commitment"`
}

type keygenRound2msg1 struct {
	Share []byte `json:"share"`
}

type keygenRound2msg2 struct {
	DeCommitment       [][]byte `json:"de_commitment"`
	SchnorrProofAlphaX []byte   `json:"schnorr_proof_alpha_x"`
	SchnorrProofAlphaY []byte   `json:"schnorr_proof_alpha_y"`
	SchnorrProofT      []byte   `json:"schnorr_proof_t"`
}
