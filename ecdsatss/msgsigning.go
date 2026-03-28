package ecdsatss

// messages for ECDSA signing

// signRound1msg1 is a P2P message containing the Paillier ciphertext and range proof (Alice init).
type signRound1msg1 struct {
	C               []byte   `json:"c"`
	RangeProofAlice [][]byte `json:"range_proof_alice"`
}

// signRound1msg2 is a broadcast message containing the commitment to pointGamma.
type signRound1msg2 struct {
	Commitment []byte `json:"commitment"`
}

// signRound2msg is a P2P message containing the MtA ciphertexts and Bob proofs.
type signRound2msg struct {
	C1       []byte   `json:"c1"`
	ProofBob [][]byte `json:"proof_bob"`
	C2       []byte   `json:"c2"`
	ProofBobWC [][]byte `json:"proof_bob_wc"`
}

// signRound3msg is a broadcast message containing the theta value.
type signRound3msg struct {
	Theta []byte `json:"theta"`
}

// signRound4msg is a broadcast message containing the de-commitment and Schnorr proof for gamma.
type signRound4msg struct {
	DeCommitment [][]byte `json:"de_commitment"`
	ProofAlphaX  []byte   `json:"proof_alpha_x"`
	ProofAlphaY  []byte   `json:"proof_alpha_y"`
	ProofT       []byte   `json:"proof_t"`
}

// signRound5msg is a broadcast message containing the commitment to (Vi, Ai).
type signRound5msg struct {
	Commitment []byte `json:"commitment"`
}

// signRound6msg is a broadcast message containing the de-commitment and both Schnorr proofs.
type signRound6msg struct {
	DeCommitment [][]byte `json:"de_commitment"`
	ProofAlphaX  []byte   `json:"proof_alpha_x"`
	ProofAlphaY  []byte   `json:"proof_alpha_y"`
	ProofT       []byte   `json:"proof_t"`
	VProofAlphaX []byte   `json:"v_proof_alpha_x"`
	VProofAlphaY []byte   `json:"v_proof_alpha_y"`
	VProofT      []byte   `json:"v_proof_t"`
	VProofU      []byte   `json:"v_proof_u"`
}

// signRound7msg is a broadcast message containing the commitment to (Ui, Ti).
type signRound7msg struct {
	Commitment []byte `json:"commitment"`
}

// signRound8msg is a broadcast message containing the de-commitment to (Ui, Ti).
type signRound8msg struct {
	DeCommitment [][]byte `json:"de_commitment"`
}

// signRound9msg is a broadcast message containing the partial signature si.
type signRound9msg struct {
	Si []byte `json:"si"`
}
