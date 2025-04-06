// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package secp256k1 allows simple and abstracted operations in the secp256k1 group.
package secp256k1

import (
	"github.com/bytemare/secp256k1/internal/field"
	"github.com/bytemare/secp256k1/internal/scalar"
)

const (
	// H2CSECP256K1 represents the hash-to-curve string identifier for secp256k1.
	H2CSECP256K1 = "secp256k1_XMD:SHA-256_SSWU_RO_"

	// E2CSECP256K1 represents the encode-to-curve string identifier for secp256k1.
	E2CSECP256K1 = "secp256k1_XMD:SHA-256_SSWU_NU_"

	scalarLength              = 32
	elementLengthIdentity     = 1
	elementLengthCompressed   = 33
	elementLengthUncompressed = 65
	secLength                 = 48
)

// Base returns the group's base point a.k.a. canonical generator.
func Base() *Element {
	return newElement().Base()
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalar(input, dst []byte) *Scalar {
	uniform := expandXMD(input, dst, uint(secLength))
	s := NewScalar()

	scalar.HashToFieldElement(&s.S, [48]byte(uniform))

	return s
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToGroup(input, dst []byte) *Element {
	expLength := 2 * 1 * uint(secLength) // elements * ext * security length
	uniform := expandXMD(input, dst, expLength)
	u0 := field.New().HashToFieldElement([secLength]byte(uniform[:secLength]))
	u1 := field.New().HashToFieldElement([secLength]byte(uniform[secLength : 2*secLength]))
	q0 := SSWU(u0)
	q1 := SSWU(u1)

	return IsogenySecp256k13iso(q0.addAffine3Iso2(q1))
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToGroup(input, dst []byte) *Element {
	expLength := 1 * 1 * uint(secLength) // elements * ext * security length
	uniform := expandXMD(input, dst, expLength)
	u0 := field.New().HashToFieldElement([secLength]byte(uniform[:secLength]))

	return IsogenySecp256k13iso(SSWU(u0))
}

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func Ciphersuite() string {
	return H2CSECP256K1
}

// ScalarLength returns the byte size of an encoded Scalar.
func ScalarLength() int {
	return scalarLength
}

// ElementLength returns the byte size of an encoded element.
func ElementLength() int {
	return elementLengthCompressed
}

// Order returns the order of the canonical group of scalars.
func Order() []byte {
	// group order: 2^256 - 432420386565659656852420866394968145599
	// = 115792089237316195423570985008687907852837564279074904382605163141518161494337
	// = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141.
	return []byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254,
		186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
	}
}
