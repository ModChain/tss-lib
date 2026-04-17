package mldsatss

// SignatureData is the output of a successful threshold ML-DSA-44 signing
// session. Signature is byte-identical to a stock FIPS 204 signature and
// verifies with mldsa.PublicKey44.Verify.
type SignatureData struct {
	Signature []byte
}
