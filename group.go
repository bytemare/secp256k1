// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package secp256k1 allows simple and abstracted operations in the Secp256k1 group.
package secp256k1

import "slices"

const (
	// H2CSECP256K1 represents the hash-to-curve string identifier for Secp256k1.
	H2CSECP256K1 = "secp256k1_XMD:SHA-256_SSWU_RO_"

	// E2CSECP256K1 represents the encode-to-curve string identifier for Secp256k1.
	E2CSECP256K1 = "secp256k1_XMD:SHA-256_SSWU_NU_"
)

// Base returns the group's base point a.k.a. canonical generator.
func Base() *Element {
	return newElement().Base()
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalar(input, dst []byte) *Scalar {
	return hashToScalar(input, dst)
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToGroup(input, dst []byte) *Element {
	return hashToCurve(input, dst)
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToGroup(input, dst []byte) *Element {
	return encodeToCurve(input, dst)
}

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func Ciphersuite() string {
	return H2CSECP256K1
}

// ScalarLength returns the byte size of an encoded scalar.
func ScalarLength() int {
	return scalarLength
}

// ElementLength returns the byte size of an encoded element.
func ElementLength() int {
	return elementLength
}

// Order returns the order of the canonical group of scalars.
func Order() []byte {
	return slices.Clone(groupOrderBytes)
}
