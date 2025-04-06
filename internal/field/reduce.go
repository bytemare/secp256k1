// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package field

import (
	"encoding/binary"
)

const (
	// ElementSize is the size of a field element in bytes.
	ElementSize = 32
)

func bytesToInts(out *NonMontgomeryDomainFieldElement, input [32]byte) {
	out[3] = binary.BigEndian.Uint64(input[0:8])
	out[2] = binary.BigEndian.Uint64(input[8:16])
	out[1] = binary.BigEndian.Uint64(input[16:24])
	out[0] = binary.BigEndian.Uint64(input[24:32])
}

// bytesToNonMontgomery interprets input as a big-endian encoded integer returns the 64-bit saturated representation.
func bytesToNonMontgomery(input [32]byte) *NonMontgomeryDomainFieldElement {
	var out NonMontgomeryDomainFieldElement

	bytesToInts(&out, input)

	return &out
}

// nonMontgomeryToBytes returns the 32 byte big-endian encoding of the saturated representation of the field element.
func nonMontgomeryToBytes(nm *NonMontgomeryDomainFieldElement) []byte {
	var out [32]byte

	binary.BigEndian.PutUint64(out[0:8], nm[3])
	binary.BigEndian.PutUint64(out[8:16], nm[2])
	binary.BigEndian.PutUint64(out[16:24], nm[1])
	binary.BigEndian.PutUint64(out[24:32], nm[0])

	return out[:]
}
