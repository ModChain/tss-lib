// Package mldsatss implements threshold ML-DSA (FIPS 204) signing.
//
// The protocol is the ML-DSA variant from "Threshold Signatures Reloaded:
// ML-DSA and Enhanced Raccoon with Identifiable Aborts" by Borin, Celi,
// del Pino, Espitau, Niot, Prest (ePrint 2025/1166). It produces
// byte-identical FIPS 204 signatures that verify against a stock ML-DSA
// public key.
//
// The current implementation targets ML-DSA-44 and supports any
// (threshold t, parties n) with 2 ≤ t ≤ n ≤ 6. Key generation uses a
// trusted dealer (matching the paper's reference); a distributed key
// generation protocol is not yet defined for this scheme and is left as
// future work.
//
// WARNING: This is an academic-grade prototype. It has not received
// independent cryptanalytic review and is not suitable for production use.
package mldsatss
