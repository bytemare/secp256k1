// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1_test

import (
	"testing"

	"github.com/bytemare/secp256k1"
)

const (
	scalarLength        = 32
	elementLength       = 33
	h2c                 = "secp256k1_XMD:SHA-256_SSWU_RO_"
	fieldOrder          = "115792089237316195423570985008687907853269984665640564039457584007908834671663"
	groupOrder          = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
	errExpectedEquality = "expected equality"
)

func TestGroup_Ciphersuite(t *testing.T) {
	if secp256k1.Ciphersuite() != h2c {
		t.Fatal("expected equality")
	}
}

func TestGroup_ScalarLength(t *testing.T) {
	if secp256k1.ScalarLength() != scalarLength {
		t.Fatal("expected equality")
	}
}

func TestGroup_ElementLength(t *testing.T) {
	if secp256k1.ElementLength() != elementLength {
		t.Fatal("expected equality")
	}
}

func TestGroup_Order(t *testing.T) {
	if secp256k1.Order() != groupOrder {
		t.Fatal("expected equality")
	}
}
