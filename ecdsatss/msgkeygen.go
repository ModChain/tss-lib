package ecdsatss

// messages for keygen

type keygenRound1msg struct {
	Commitment []byte
	PaillierN  []byte
	NTilde     []byte
	H1         []byte
	H2         []byte
	Dlnproof_1 [][]byte
	Dlnproof_2 [][]byte
}

type keygenRound2msg1 struct {
	Share    []byte
	FacProof [][]byte
}

type keygenRound2msg2 struct {
	DeCommitment [][]byte
	ModProof     [][]byte
}

type keygenRound3msg struct {
	PaillierProof [][]byte
}
