package ecdsatss

// SignatureData holds the output of a threshold ECDSA signing operation.
type SignatureData struct {
	R, S      []byte // R and S components
	Signature []byte // R || S
	Recovery  byte   // recovery byte for public key recovery
	M         []byte // original message hash that was signed
}
