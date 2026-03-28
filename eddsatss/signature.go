package eddsatss

// SignatureData holds the output of a threshold EdDSA signing operation.
type SignatureData struct {
	R, S      []byte // R and S components
	Signature []byte // 64-byte Ed25519 signature (R || S)
	M         []byte // original message that was signed
}
