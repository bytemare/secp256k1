// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1_test

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"testing"

	"github.com/bytemare/secp256k1"
)

type serde interface {
	Encode() []byte
	Decode(data []byte) error
	Hex() string
	DecodeHex(h string) error
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func testEncoding(t *testing.T, thing1, thing2 serde) {
	encoded := thing1.Encode()
	marshalled, _ := thing1.MarshalBinary()
	hexed := thing1.Hex()

	if !bytes.Equal(encoded, marshalled) {
		t.Fatalf("Encode() and MarshalBinary() are expected to have the same output."+
			"\twant: %v\tgot : %v", encoded, marshalled)
	}

	if hex.EncodeToString(encoded) != hexed {
		t.Fatalf("Failed hex encoding, want %q, got %q", hex.EncodeToString(encoded), hexed)
	}

	if err := thing2.Decode(nil); err == nil {
		t.Fatal("expected error on Decode() with nil input")
	}

	if err := thing2.Decode(encoded); err != nil {
		t.Fatalf("Decode() failed on a valid encoding: %v. Value: %v", err, hex.EncodeToString(encoded))
	}

	if err := thing2.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary() failed on a valid encoding: %v", err)
	}

	if err := thing2.DecodeHex(hexed); err != nil {
		t.Fatalf("DecodeHex() failed on valid hex encoding: %v", err)
	}
}

func TestScalar_Encoding(t *testing.T) {
	scalar := secp256k1.NewScalar().Random()
	testEncoding(t, scalar, secp256k1.NewScalar())
}

func TestElement_Encoding(t *testing.T) {
	scalar := secp256k1.NewScalar().Random()
	element := secp256k1.Base().Multiply(scalar)
	testEncoding(t, element, secp256k1.NewElement())
}
