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
	"crypto/rand"
	"encoding"
	"encoding/hex"
	"errors"
	"io"
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

func testDecodingHexFails(t *testing.T, thing1, thing2 serde) {
	// empty string
	if err := thing2.DecodeHex(""); err == nil {
		t.Fatal("expected error on empty string")
	}

	// malformed string
	hexed := thing1.Hex()
	malformed := []rune(hexed)
	malformed[0] = []rune("_")[0]

	expectedError := "encoding/hex: invalid byte: U+005F '_'"

	if err := thing2.DecodeHex(string(malformed)); err == nil {
		t.Fatal("expected error on malformed string")
	} else if err.Error() != expectedError {
		t.Fatalf("expected error %q, got %q", expectedError, err)
	}
}

func testEncoding(t *testing.T, thing1, thing2 serde) {
	encoded := thing1.Encode()
	marshalled, _ := thing1.MarshalBinary()
	hexed := thing1.Hex()

	// Compressed byte encoding and marshalling yields the same output.
	if !bytes.Equal(encoded, marshalled) {
		t.Fatalf("Encode() and MarshalBinary() are expected to have the same output."+
			"\twant: %v\tgot : %v", encoded, marshalled)
	}

	// Hex encoding is just the compressed encoding in hexadecimal form.
	if hex.EncodeToString(encoded) != hexed {
		t.Fatalf("Failed hex encoding, want %q, got %q", hex.EncodeToString(encoded), hexed)
	}

	// Check that nil input returns an error.
	if err := thing2.Decode(nil); err == nil {
		t.Fatal("expected error on Decode() with nil input")
	}

	// Check that the encoded form does not produce an error when being decoded.
	if err := thing2.Decode(encoded); err != nil {
		t.Fatalf("Decode() failed on a valid encoding: %v. Value: %v", err, hex.EncodeToString(encoded))
	}

	if err := thing2.UnmarshalBinary(marshalled); err != nil {
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

	// Check that the decoded form equals the orginal one.
	res := secp256k1.NewElement()
	if err := res.Decode(element.Encode()); err != nil {
		t.Fatalf("unexpected error on valid encoding: %s", err)
	}

	if res.Equal(element) != 1 {
		t.Fatal(errExpectedEquality)
	}

	xy := res.EncodeUncompressed()
	x := xy[:33]
	x2 := res.XCoordinate()
	x3 := res.Encode()

	// Check prefix
	if xy[0] != 0x04 {
		t.Fatal(errExpectedEquality)
	}

	if !bytes.Equal(x[1:], x2) {
		t.Fatal(errExpectedEquality)
	}

	if !bytes.Equal(x2, x3[1:]) {
		t.Fatal(errExpectedEquality)
	}

	// Re-encode
	res = secp256k1.NewElement()
	if err := res.Decode(xy); err != nil {
		t.Fatal(err)
	}

	if res.Equal(element) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func TestElement_Decode_fails(t *testing.T) {
	scalar := secp256k1.NewScalar().Random()
	element := secp256k1.Base().Multiply(scalar)
	encoded := element.Encode()
	res := secp256k1.NewElement()
	expected := errors.New("invalid point encoding")

	// Identity element encoding length, but not 0.
	if err := res.Decode([]byte{2}); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// Compressed, but wrong length
	if err := res.DecodeCompressed(encoded[:31]); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// Compressed, but wrong prefix
	encoded[0] = 0x05
	if err := res.DecodeCompressed(encoded); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// Uncompressed, but wrong length
	encoded = element.EncodeUncompressed()
	if err := res.DecodeUncompressed(encoded[:64]); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// Uncompressed, but wrong prefix
	encoded[0] = 0x05
	if err := res.DecodeUncompressed(encoded); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// Decode affine coordinates
	ok, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	notOk, _ := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")

	// x not ok
	if err := secp256k1.NewElement().DecodeCoordinates([32]byte(notOk), [32]byte(ok)); err == nil ||
		err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// y not ok
	if err := secp256k1.NewElement().DecodeCoordinates([32]byte(ok), [32]byte(notOk)); err == nil ||
		err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// x and y ok, but point is not on curve
	// Values tried out at random.
	x, _ := hex.DecodeString("2c04458a01fd91dfb94e8c6f17803b206b8f910073120a2e0b65a5090ce2f316")
	y, _ := hex.DecodeString("2d90e1db58b9ad2e69117cbb8fbfd2f48ea1082d6f596656d1f30ddeccf4ffc0")

	if err := secp256k1.NewElement().DecodeCoordinates([32]byte(x), [32]byte(y)); err == nil ||
		err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}
}

func rand32Bytes() [32]byte {
	var buf [32]byte

	_, err := io.ReadFull(rand.Reader, buf[:])
	if err != nil {
		panic(err)
	}

	return buf
}

func TestScalar_DecodeHex_Fails(t *testing.T) {
	scalar := secp256k1.NewScalar().Random()
	testEncoding(t, scalar, secp256k1.NewScalar())
	testDecodingHexFails(t, scalar, secp256k1.NewScalar())

	// Doesn't yield the same decoded result
	res := secp256k1.NewScalar()
	if err := res.DecodeHex(scalar.Hex()); err != nil {
		t.Fatalf("unexpected error on valid encoding: %s", err)
	}

	if res.Equal(scalar) != 1 {
		t.Log(res.Hex())
		t.Log(scalar.Hex())
		t.Fatal(errExpectedEquality)
	}
}

func TestElement_DecodeHex_Fails(t *testing.T) {
	scalar := secp256k1.NewScalar().Random()
	element := secp256k1.Base().Multiply(scalar)
	testEncoding(t, element, secp256k1.NewElement())
	testDecodingHexFails(t, element, secp256k1.NewElement())

	// Doesn't yield the same decoded result
	res := secp256k1.NewElement()
	if err := res.DecodeHex(element.Hex()); err != nil {
		t.Fatalf("unexpected error on valid encoding: %s", err)
	}

	if res.Equal(element) != 1 {
		t.Fatal(errExpectedEquality)
	}
}
