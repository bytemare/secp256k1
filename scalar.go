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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/bits"

	"github.com/bytemare/secp256k1/internal/scalar"
)

var (
	// errParamScalarLength indicates an invalid Scalar length.
	errParamScalarLength = errors.New("invalid scalar length")

	// errParamNilScalar indicates a forbidden nil or empty Scalar.
	errParamNilScalar = errors.New("nil or empty scalar")

	// errParamScalarTooBig reports an error when the input Scalar is too big.
	errParamScalarTooBig = errors.New("scalar too big")
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

// Random sets the current Scalar to a new random Scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero Scalar.
func (s *Scalar) Random() *Scalar {
	var (
		buf [32]byte
		m   scalar.MontgomeryDomainFieldElement
	)

	for scalar.IsFEZero(&m) == 1 {
		_, err := io.ReadFull(rand.Reader, buf[:])
		if err != nil {
			panic(err)
		}

		nm := scalar.BytesToNonMontgomery(buf)
		_ = scalar.Reduce(nm)

		scalar.ToMontgomery(&m, nm)
	}

	copy(s.S[:], m[:])

	return s
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

	for i := range 255 {
		out[i] = uint8((n[i/64] >> (i % 64)) & 1)
	}

	return out
}

// Pow sets s to s^t modulo the group order, and returns s. If t is nil or equals 0, s is set to 1.
// Now using variable time big.Int because for some reason I can't get the constant time algorithm to work on Fiat.
func (s *Scalar) Pow(t *Scalar) *Scalar {
	if t == nil || t.IsZero() {
		return s.One()
	}

	if t.IsOne() {
		return s
	}

	order := new(big.Int).SetBytes(Order())
	bigS := big.NewInt(0).SetBytes(s.Encode())
	bigT := big.NewInt(0).SetBytes(t.Encode())
	bigS.Exp(bigS, bigT, order)

	// If necessary, build a buffer of right size, so it gets correctly interpreted.
	bytes := bigS.Bytes()

	if l := scalarLength - len(bytes); l > 0 {
		buf := make([]byte, l, scalarLength)
		buf = append(buf, bytes...)
		bytes = buf
	}

	if err := s.Decode(bytes); err != nil {
		panic(err)
	}

	/*
		The following was an attempt for constant time, but for some reason it doesn't work.

			s1 := new(Scalar).One()
			s2 := s.Copy()
			bits := t.Bits()
			var i int
			for i = 255; bits[i] == 0; i-- {
			}

			for ; i >= 0; i-- {
				if bits[i] == 0 {
					s2.Multiply(s1)
					s1.Square()
				} else {
					s1.Multiply(s2)
					s2.Square()
				}

			}

			s.Set(s1)

			return s

	*/

	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(t *Scalar) int {
	if t == nil {
		return 0
	}

	return int(scalar.Equal(&s.S, &t.S))
}

// LessOrEqual returns 1 if s <= t and 0 otherwise.
func (s *Scalar) LessOrEqual(t *Scalar) uint64 {
	var (
		borrow uint64
		diff   [4]uint64
	)

	diff[0], borrow = bits.Sub64(s.S[0], t.S[0], borrow)
	diff[1], borrow = bits.Sub64(s.S[1], t.S[1], borrow)
	diff[2], borrow = bits.Sub64(s.S[2], t.S[2], borrow)
	diff[3], borrow = bits.Sub64(s.S[3], t.S[3], borrow)

	equal := scalar.IsZero(diff[0] | diff[1] | diff[2] | diff[3])

	return equal | scalar.IsNonZero(borrow)
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
		return errParamNilScalar
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

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(in []byte) error {
	switch len(in) {
	case 0:
		return errParamNilScalar
	case scalarLength:
		break
	default:
		return errParamScalarLength
	}

	if scalar.ReduceBytes(&s.S, [scalarLength]byte(in)) == 0 {
		return errParamScalarTooBig
	}

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
