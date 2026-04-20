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
// It returns ErrZeroLenDST if dst is empty. A DST longer than 16 bytes is recommended.
func HashToScalar(input, dst []byte) (*Scalar, error) {
	var uniform [secLength]byte

	err := expandXMDTo(uniform[:], input, dst)
	if err != nil {
		return nil, err
	}

	return &Scalar{
		S: *scalar.ReduceWideBytes(&scalar.MontgomeryDomainFieldElement{}, [secLength]byte(uniform)),
	}, nil
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// It returns ErrZeroLenDST if dst is empty. A DST longer than 16 bytes is recommended.
func HashToGroup(input, dst []byte) (*Element, error) {
	var uniform [2 * secLength]byte // elements * ext * security length

	err := expandXMDTo(uniform[:], input, dst)
	if err != nil {
		return nil, err
	}

	u0 := field.New().ReduceWideBytes([secLength]byte(uniform[:secLength]))
	u1 := field.New().ReduceWideBytes([secLength]byte(uniform[secLength : 2*secLength]))
	p0 := IsogenySecp256k13iso(SSWU(u0))
	p1 := IsogenySecp256k13iso(SSWU(u1))

	// We apply the isogeny on the two mapped elements first, because the
	// addition formula of the ISO curve is not complete and would silently produce
	// undefined behavior when dividing by x2 - x1.

	return p0.Add(p1), nil
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// It returns ErrZeroLenDST if dst is empty. A DST longer than 16 bytes is recommended.
func EncodeToGroup(input, dst []byte) (*Element, error) {
	var uniform [secLength]byte // elements * ext * security length

	err := expandXMDTo(uniform[:], input, dst)
	if err != nil {
		return nil, err
	}

	u0 := field.New().ReduceWideBytes([secLength]byte(uniform[:secLength]))

	return IsogenySecp256k13iso(SSWU(u0)), nil
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
