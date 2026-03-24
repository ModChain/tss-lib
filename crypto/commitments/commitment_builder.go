// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package commitments

import (
	"errors"
	"fmt"
	"math/big"
)

const (
	// PartsCap is the maximum number of parts allowed in a commitment.
	PartsCap = 3
	// MaxPartSize is the maximum byte size of a single commitment part (1 MB).
	MaxPartSize = int64(1 * 1024 * 1024) // 1 MB - rather liberal
)

type builder struct {
	parts [][]*big.Int
}

// NewBuilder creates a new commitment builder for assembling multi-part secrets.
func NewBuilder() *builder {
	b := new(builder)
	b.parts = make([][]*big.Int, 0, PartsCap)
	return b
}

// Parts returns the current list of parts added to the builder.
func (b *builder) Parts() [][]*big.Int {
	return b.parts[:]
}

// AddPart appends a part (slice of big.Int values) to the builder and returns it for chaining.
func (b *builder) AddPart(part []*big.Int) *builder {
	b.parts = append(b.parts, part[:])
	return b
}

// Secrets encodes all parts into a flat slice of big.Int values with length-prefix framing.
func (b *builder) Secrets() ([]*big.Int, error) {
	secretsLen := 0
	if len(b.parts) > PartsCap {
		return nil, fmt.Errorf("builder.Secrets: too many commitment parts provided: got %d, max %d", len(b.parts), PartsCap)
	}
	for _, p := range b.parts {
		secretsLen += 1 + len(p) // +1 to accommodate length prefix element
	}
	secrets := make([]*big.Int, 0, secretsLen)
	for i, p := range b.parts {
		partLen := int64(len(p))
		if MaxPartSize < partLen {
			return nil, fmt.Errorf("builder.Secrets: commitment part too large: part %d, size %d", i, partLen)
		}
		secrets = append(secrets, big.NewInt(partLen))
		secrets = append(secrets, p...)
	}
	return secrets, nil
}

// ParseSecrets decodes a length-prefixed flat slice of big.Int values back into separate parts.
func ParseSecrets(secrets []*big.Int) ([][]*big.Int, error) {
	if secrets == nil || len(secrets) < 2 {
		return nil, errors.New("ParseSecrets: secrets == nil or is too small")
	}
	var el, nextPartLen int64
	parts := make([][]*big.Int, 0, PartsCap)
	isLenEl := true // are we looking at a length prefix element? (first one is)
	inLen := int64(len(secrets))
	for el < inLen {
		if el < 0 {
			return nil, errors.New("ParseSecrets: `el` overflow")
		}
		if isLenEl {
			nextPartLen = secrets[el].Int64()
			if MaxPartSize < nextPartLen {
				return nil, fmt.Errorf("ParseSecrets: commitment part too large: part %d, size %d", len(parts), nextPartLen)
			}
			el += 1
		} else {
			if PartsCap <= len(parts) {
				return nil, fmt.Errorf("ParseSecrets: commitment has too many parts: part %d, max %d", len(parts), PartsCap)
			}
			if inLen < el+nextPartLen {
				return nil, errors.New("ParseSecrets: not enough data to consume stated data length")
			}
			part := secrets[el : el+nextPartLen]
			parts = append(parts, part)
			el += nextPartLen
		}
		isLenEl = !isLenEl
	}
	return parts, nil
}
