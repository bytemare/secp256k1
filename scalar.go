// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bytemare/secp256k1/internal/scalar"
)

var (
	// ErrParamScalarLength indicates an invalid Scalar length.
	ErrParamScalarLength = errors.New("invalid scalar length")

	// ErrParamNilScalar indicates a forbidden nil or empty Scalar.
	ErrParamNilScalar = errors.New("nil or empty scalar")

	// ErrParamScalarTooBig reports an error when the input Scalar is too big.
	ErrParamScalarTooBig = errors.New("scalar too big")

	// ErrParamInvalidInputLength indicates the input length is invalid.
	ErrParamInvalidInputLength = errors.New("invalid input length")
)

type disallowEqual [0]func()

// Scalar implements the Scalar interface for Edwards25519 group scalars.
type Scalar struct {
	_ disallowEqual
	S scalar.MontgomeryDomainFieldElement
}

func newScalar() *Scalar {
	return &Scalar{S: scalar.MontgomeryDomainFieldElement{}}
}

// NewScalar returns a new Scalar set to 0.
func NewScalar() *Scalar {
	return newScalar()
}

// Zero sets the Scalar to 0, and returns it.
func (s *Scalar) Zero() *Scalar {
	s.S[0] = 0
	s.S[1] = 0
	s.S[2] = 0
	s.S[3] = 0

	return s
}

// One sets the Scalar to 1, and returns it.
func (s *Scalar) One() *Scalar {
	scalar.SetOne(&s.S)
	return s
}

// MinusOne sets the Scalar to -1 = p-1, and returns it.
func (s *Scalar) MinusOne() *Scalar {
	// From the MontgomeryDomainFieldElement representation.
	s.S[0] = 9197684256760693378
	s.S[1] = 8457119966977671287
	s.S[2] = 18446744073709551613
	s.S[3] = 18446744073709551615

	return s
}

// Random sets the receiver to a uniformly random non-zero scalar sampled from the system CSPRNG.
func (s *Scalar) Random() *Scalar {
	var (
		buf [scalarLength]byte
		nm  scalar.NonMontgomeryDomainFieldElement
	)

	for {
		_, _ = rand.Read(buf[:])
		if !isValidScalar(&nm, &buf) {
			continue
		}

		scalar.ToMontgomery(&s.S, &nm)

		break
	}

	return s
}

// isValidScalar reports whether buf encodes a non-zero scalar below the group order.
func isValidScalar(
	nm *scalar.NonMontgomeryDomainFieldElement,
	buf *[scalarLength]byte,
) bool {
	nm[3] = binary.BigEndian.Uint64(buf[0:8])
	nm[2] = binary.BigEndian.Uint64(buf[8:16])
	nm[1] = binary.BigEndian.Uint64(buf[16:24])
	nm[0] = binary.BigEndian.Uint64(buf[24:32])

	if scalar.IsZero(nm[0]|nm[1]|nm[2]|nm[3]) == 1 {
		return false
	}

	return scalar.Reduce(nm) == 1
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (s *Scalar) Add(t *Scalar) *Scalar {
	if t == nil {
		return s
	}

	scalar.Add(&s.S, &s.S, &t.S)

	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(t *Scalar) *Scalar {
	if t == nil {
		return s
	}

	scalar.Sub(&s.S, &s.S, &t.S)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(t *Scalar) *Scalar {
	if t == nil {
		return s.Zero()
	}

	scalar.Mul(&s.S, &s.S, &t.S)

	return s
}

// Square sets the receiver to its square.
func (s *Scalar) Square() *Scalar {
	scalar.Square(&s.S, &s.S)
	return s
}

// Invert sets the receiver to its inverse.
func (s *Scalar) Invert() *Scalar {
	scalar.Invert(&s.S, s.S)
	return s
}

// Bits returns the bit expansion of the receiver.
func (s *Scalar) Bits() [256]uint8 {
	var (
		n   scalar.NonMontgomeryDomainFieldElement
		out [256]uint8
	)

	scalar.FromMontgomery(&n, &s.S)

	for i := range 256 {
		out[i] = uint8((n[i/64] >> (i % 64)) & 1)
	}

	return out
}

// Pow sets s to s^t modulo the group order in constant time, and returns s.
// If t is nil, Pow panics.
func (s *Scalar) Pow(t *Scalar) *Scalar {
	if t == nil {
		panic(ErrParamNilScalar)
	}

	var (
		base     scalar.MontgomeryDomainFieldElement
		exponent scalar.NonMontgomeryDomainFieldElement
		r0       scalar.MontgomeryDomainFieldElement
		r1       scalar.MontgomeryDomainFieldElement
		prod     scalar.MontgomeryDomainFieldElement
		sq       scalar.MontgomeryDomainFieldElement
	)

	copy(base[:], s.S[:])
	scalar.FromMontgomery(&exponent, &t.S)
	scalar.SetOne(&r0)
	copy(r1[:], base[:])

	for i := 255; i >= 0; i-- {
		bit := (exponent[i/64] >> (i % 64)) & 1

		scalar.CSwap(bit, &r0, &r1)
		scalar.Mul(&prod, &r0, &r1)
		scalar.Square(&sq, &r0)
		copy(r1[:], prod[:])
		copy(r0[:], sq[:])
		scalar.CSwap(bit, &r0, &r1)
	}

	copy(s.S[:], r0[:])

	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(t *Scalar) int {
	if t == nil {
		return 0
	}

	return int(scalar.Equal(&s.S, &t.S))
}

// LessOrEqual returns 1 if s <= t and 0 otherwise, using canonical integer ordering on encoded scalars in [0, n-1].
func (s *Scalar) LessOrEqual(t *Scalar) uint64 {
	return scalar.LessOrEqual(&s.S, &t.S)
}

// IsZero returns whether the Scalar is 0.
func (s *Scalar) IsZero() bool {
	return scalar.IsFEZero(&s.S) == 1
}

// IsOne returns whether s == 1.
func (s *Scalar) IsOne() bool {
	return scalar.Equal(&s.S, scalar.One()) == 1
}

// Copy returns a copy of the receiver.
func (s *Scalar) Copy() *Scalar {
	return newScalar().Set(s)
}

// Set sets the receiver to the value of the argument Scalar, and returns the receiver.
func (s *Scalar) Set(t *Scalar) *Scalar {
	if t == nil {
		return s.Zero()
	}

	return s.set(&t.S)
}

// SetUInt64 sets s to i modulo the group order, and returns it.
func (s *Scalar) SetUInt64(i uint64) *Scalar {
	nm := scalar.NonMontgomeryDomainFieldElement{i, 0, 0, 0}
	scalar.ToMontgomery(&s.S, &nm)

	return s
}

// CSelect sets the receiver to u if cond == 0, and to v otherwise, in constant-time.
func (s *Scalar) CSelect(cond uint64, u, v *Scalar) error {
	if u == nil || v == nil {
		return ErrParamNilScalar
	}

	scalar.CMove(&s.S, cond, &u.S, &v.S)

	return nil
}

// Encode returns the compressed byte encoding of the Scalar.
func (s *Scalar) Encode() []byte {
	var nm scalar.NonMontgomeryDomainFieldElement

	scalar.FromMontgomery(&nm, &s.S)

	return scalar.NonMontgomeryToBytes(&nm)
}

// Decode sets s to a big-endian 32-byte decoding of x.
// If x is not a canonical encoding of s, Decode returns an error.
func (s *Scalar) Decode(x []byte) error {
	t, _, err := decodeScalar(x)
	if err != nil {
		return err
	}

	s.set(t)

	return nil
}

// DecodeWithReduction sets s to x modulo the group order. If x is nil or
// not 32 bytes, DecodeWithReduction returns an error.
func (s *Scalar) DecodeWithReduction(x []byte) error {
	t, reduced, err := decodeScalar(x)
	if err != nil && !reduced {
		return ErrParamInvalidInputLength
	}

	s.set(t)

	return nil
}

// Hex returns the fixed-sized hexadecimal encoding of s.
func (s *Scalar) Hex() string {
	return hex.EncodeToString(s.Encode())
}

// DecodeHex sets s to the decoding of the hex encoded Scalar.
func (s *Scalar) DecodeHex(h string) error {
	encoded, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return s.Decode(encoded)
}

// MarshalBinary returns the compressed byte encoding of the Scalar.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded Scalar.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	return s.Decode(data)
}

func (s *Scalar) set(t *scalar.MontgomeryDomainFieldElement) *Scalar {
	copy(s.S[:], t[:])
	return s
}

// decodeScalar returns x modulo the group order, whether reduction was
// necessary, and an error for invalid or non-canonical inputs.
func decodeScalar(x []byte) (*scalar.MontgomeryDomainFieldElement, bool, error) {
	switch len(x) {
	case 0:
		return nil, false, ErrParamNilScalar
	case scalarLength:
		break
	default:
		return nil, false, ErrParamScalarLength
	}

	var s scalar.MontgomeryDomainFieldElement

	if scalar.ReduceBytes(&s, [scalarLength]byte(x)) == 0 {
		return &s, true, ErrParamScalarTooBig
	}

	return &s, false, nil
}
