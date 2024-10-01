// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

var (
	// errParamScalarLength indicates an invalid scalar length.
	errParamScalarLength = errors.New("invalid scalar length")

	// errParamNilScalar indicates a forbidden nil or empty scalar.
	errParamNilScalar = errors.New("nil or empty scalar")

	// errParamNegScalar reports an error when the input scalar is negative.
	// errParamNegScalar = errors.New("negative scalar").

	// errParamScalarTooBig reports an error when the input scalar is too big.
	errParamScalarTooBig = errors.New("scalar too big")
)

type disallowEqual [0]func()

// Scalar implements the Scalar interface for Edwards25519 group scalars.
type Scalar struct {
	_      disallowEqual
	scalar big.Int
}

var (
	scZero = big.NewInt(0)
	scOne  = big.NewInt(1)
)

func newScalar() *Scalar {
	return &Scalar{scalar: big.Int{}}
}

// NewScalar returns a new scalar set to 0.
func NewScalar() *Scalar {
	return newScalar()
}

// Zero sets the scalar to 0, and returns it.
func (s *Scalar) Zero() *Scalar {
	s.scalar.Set(scZero)
	return s
}

// One sets the scalar to 1, and returns it.
func (s *Scalar) One() *Scalar {
	s.scalar.Set(scOne)
	return s
}

// MinusOne sets the scalar to order-1, and returns it.
func (s *Scalar) MinusOne() *Scalar {
	s.scalar.SetBytes(scMinusOne)
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() *Scalar {
	for {
		fn.Random(&s.scalar)

		if !s.IsZero() {
			return s
		}
	}
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (s *Scalar) Add(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s
	}

	fn.Add(&s.scalar, &s.scalar, &scalar.scalar)

	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s
	}

	fn.Sub(&s.scalar, &s.scalar, &scalar.scalar)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s.Zero()
	}

	fn.Mul(&s.scalar, &s.scalar, &scalar.scalar)

	return s
}

// Pow sets s to s**scalar modulo the group order, and returns s. If scalar is nil, it returns 1.
func (s *Scalar) Pow(scalar *Scalar) *Scalar {
	if scalar == nil || scalar.IsZero() {
		return s.One()
	}

	if scalar.Equal(scalar.Copy().One()) == 1 {
		return s
	}

	fn.Exponent(&s.scalar, &s.scalar, &scalar.scalar)

	return s
}

// Invert sets the receiver to its modular inverse ( 1 / s ), and returns it.
func (s *Scalar) Invert() *Scalar {
	fn.Inv(&s.scalar, &s.scalar)
	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(scalar *Scalar) int {
	if scalar == nil {
		return 0
	}

	return subtle.ConstantTimeCompare(s.scalar.Bytes(), scalar.scalar.Bytes())
}

// LessOrEqual returns 1 if s <= scalar and 0 otherwise.
func (s *Scalar) LessOrEqual(scalar *Scalar) int {
	ienc := s.Encode()
	jenc := scalar.Encode()
	var res bool

	for i := range ienc {
		res = res || (ienc[i] > jenc[i])
	}

	if res {
		return 0
	}

	return 1
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return fn.AreEqual(&s.scalar, scZero)
}

// Set sets the receiver to the value of the argument scalar, and returns the receiver.
func (s *Scalar) Set(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s.Zero()
	}

	s.scalar.Set(&scalar.scalar)

	return s
}

// SetUInt64 sets s to i modulo the field order, and returns it.
func (s *Scalar) SetUInt64(i uint64) *Scalar {
	s.scalar.SetUint64(i)
	fn.Mod(&s.scalar)

	return s
}

// Copy returns a copy of the receiver.
func (s *Scalar) Copy() *Scalar {
	cpy := newScalar()
	cpy.scalar.Set(&s.scalar)

	return cpy
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	scalar := make([]byte, scalarLength) // length := (fn.BitLen() + 7) / 8 = 32
	return s.scalar.FillBytes(scalar)
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

	// warning - SetBytes interprets the input as a non-signed integer, so this will always be false
	// 	if tmp.Sign() < 0 {
	//		return errParamNegScalar
	//	}
	tmp := new(big.Int).SetBytes(in)

	if fn.Order().Cmp(tmp) <= 0 {
		return errParamScalarTooBig
	}

	s.scalar.Set(tmp)

	return nil
}

// Hex returns the fixed-sized hexadecimal encoding of s.
func (s *Scalar) Hex() string {
	return hex.EncodeToString(s.Encode())
}

// DecodeHex sets s to the decoding of the hex encoded scalar.
func (s *Scalar) DecodeHex(h string) error {
	encoded, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return s.Decode(encoded)
}

// MarshalBinary returns the compressed byte encoding of the scalar.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded scalar.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	return s.Decode(data)
}
