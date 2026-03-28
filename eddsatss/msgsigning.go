package eddsatss

// messages for EdDSA signing

type signRound1msg struct {
	Commitment []byte `json:"commitment"`
}

type signRound2msg struct {
	DeCommitment       [][]byte `json:"de_commitment"`
	SchnorrProofAlphaX []byte   `json:"schnorr_proof_alpha_x"`
	SchnorrProofAlphaY []byte   `json:"schnorr_proof_alpha_y"`
	SchnorrProofT      []byte   `json:"schnorr_proof_t"`
}

type signRound3msg struct {
	Si []byte `json:"si"`
}
