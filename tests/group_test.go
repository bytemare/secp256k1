// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1_test

import (
	"bytes"
	"testing"

	"github.com/bytemare/secp256k1"
)

const (
	scalarLength              = 32
	elementLengthIdentity     = 1
	elementLengthCompressed   = 33
	elementLengthUncompressed = 65
	h2c                       = "secp256k1_XMD:SHA-256_SSWU_RO_"
	fieldOrder                = "115792089237316195423570985008687907853269984665640564039457584007908834671663"
	errExpectedEquality       = "expected equality"
)

func TestGroup_Ciphersuite(t *testing.T) {
	if secp256k1.Ciphersuite() != h2c {
		t.Fatal(errExpectedEquality)
	}
}

func TestGroup_ScalarLength(t *testing.T) {
	if secp256k1.ScalarLength() != scalarLength {
		t.Fatal(errExpectedEquality)
	}
}

func TestGroup_ElementLength(t *testing.T) {
	if secp256k1.ElementLength() != elementLengthCompressed {
		t.Fatal(errExpectedEquality)
	}
}

func TestGroup_Order(t *testing.T) {
	groupOrderBytes := []byte{
		255,
		255,
		255,
		255,
		255,
		255,
		255,
		255,
		255,
		255,
		255,
		255,
		255,
		255,
		255,
		254,
		186,
		174,
		220,
		230,
		175,
		72,
		160,
		59,
		191,
		210,
		94,
		140,
		208,
		54,
		65,
		65,
	}
	if !bytes.Equal(secp256k1.Order(), groupOrderBytes) {
		t.Fatal(errExpectedEquality)
	}
}
