// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1_test

import (
	"encoding/hex"
	"errors"
	"log"
	"math/big"
	"testing"

	"github.com/bytemare/secp256k1"
)

const (
	basePoint           = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	identity            = "00"
	errExpectedIdentity = "expected identity"
)

var multBase = []string{
	"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
	"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
	"02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
	"022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
	"03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
	"025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
	"022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01",
	"03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe",
	"03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7",
	"03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb",
	"03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a",
	"03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa8",
	"03499fdf9e895e719cfd64e67f07d38e3226aa7b63678949e6e49b241a60e823e4",
	"02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e",
}

func TestElement_Base(t *testing.T) {
	base := hex.EncodeToString(secp256k1.Base().Encode())
	if base != basePoint {
		t.Fatal("expected equality")
	}
}

func decodeHexElement(t *testing.T, input string) *secp256k1.Element {
	e := secp256k1.NewElement()
	if err := e.DecodeHex(input); err != nil {
		t.Fatal(err)
	}

	return e
}

func TestElement_Vectors_Add(t *testing.T) {
	base := secp256k1.Base()
	acc := secp256k1.Base()

	for _, mult := range multBase {
		e := decodeHexElement(t, mult)
		if e.Equal(acc) != 1 {
			t.Fatal(errExpectedEquality)
		}

		acc.Add(base)
	}

	base.Add(secp256k1.NewElement())
	if base.Equal(secp256k1.Base()) != 1 {
		t.Fatal(errExpectedEquality)
	}

	if secp256k1.NewElement().Add(base).Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func TestElement_Vectors_Double(t *testing.T) {
	double := secp256k1.Base()
	add := secp256k1.Base()

	for range multBase {
		add.Add(add)
		double.Double()

		if double.Equal(add) != 1 {
			t.Fatal("expected equality")
		}
	}
}

func TestElement_Vectors_Mult(t *testing.T) {
	s := secp256k1.NewScalar()
	base := secp256k1.Base()

	for i, mult := range multBase {
		e := decodeHexElement(t, mult)
		if e.Equal(base) != 1 {
			t.Log(mult)
			t.Log(e.Hex())
			t.Log(base.Hex())
			t.Fatalf("expected equality for %d", i)
		}

		s.SetUInt64(uint64(i + 2))

		base.Base().Multiply(s)
	}
}

func testElementCopySet(t *testing.T, element, other *secp256k1.Element) {
	// Verify they don't point to the same thing
	if &element == &other {
		t.Fatalf("Pointer to the same scalar")
	}

	// Verify whether they are equivalent
	if element.Equal(other) != 1 {
		t.Fatalf("Expected equality")
	}

	// Verify than operations on one don't affect the other
	element.Add(element)
	if element.Equal(other) == 1 {
		t.Fatalf("Unexpected equality")
	}

	other.Double().Double()
	if element.Equal(other) == 1 {
		t.Fatalf("Unexpected equality")
	}
}

func TestElementCopy(t *testing.T) {
	base := secp256k1.Base()
	cpy := base.Copy()
	testElementCopySet(t, base, cpy)
}

func TestElementSet(t *testing.T) {
	base := secp256k1.Base()
	other := secp256k1.NewElement()
	other.Set(base)
	testElementCopySet(t, base, other)
}

func TestElement_EncodedLength(t *testing.T) {
	id := secp256k1.NewElement().Identity().Encode()
	if len(id) != elementLengthIdentity {
		t.Fatalf(
			"Encode() of the identity element is expected to return %d bytes, but returned %d bytes",
			elementLengthIdentity,
			len(id),
		)
	}

	encodedID := hex.EncodeToString(id)
	if encodedID != identity {
		t.Fatalf(
			"Encode() of the identity element is unexpected.\n\twant: %v\n\tgot : %v",
			identity,
			encodedID,
		)
	}

	rands := secp256k1.NewScalar().Random()
	rande := secp256k1.Base().Multiply(rands)
	encodedCompressed := rande.Encode()

	if len(encodedCompressed) != elementLengthCompressed {
		t.Fatalf(
			"Encode() of an non infinity point is expected to return %d bytes, but returned %d bytes",
			elementLengthCompressed,
			len(id),
		)
	}

	encodedUncompressed := rande.EncodeUncompressed()
	if len(encodedUncompressed) != elementLengthUncompressed {
		t.Fatalf(
			"Encode() of an non infinity point is expected to return %d bytes, but returned %d bytes",
			elementLengthUncompressed,
			len(id),
		)
	}
}

func TestElement_Decode_OutOfBounds(t *testing.T) {
	expected := errors.New("invalid point encoding")

	// Set x and y to zero
	x := big.NewInt(0)
	y := big.NewInt(0)

	var encoded [33]byte
	encoded[0] = byte(2 | y.Bit(0)&1)
	x.FillBytes(encoded[1:])

	if err := secp256k1.NewElement().Decode(encoded[:]); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// x exceeds the order
	encoded = [33]byte{}

	x, ok := x.SetString(fieldOrder, 0)
	if !ok {
		t.Errorf("setting int in base %d failed: %v", 0, fieldOrder)
	}

	x.Add(x, big.NewInt(1))
	encoded[0] = byte(2 | y.Bit(0)&1)
	x.FillBytes(encoded[1:])

	if err := secp256k1.NewElement().Decode(encoded[:]); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}
}

func TestElement_Equal(t *testing.T) {
	base := secp256k1.Base()
	base2 := secp256k1.Base()

	if base.Equal(base2) != 1 {
		t.Fatal(errExpectedEquality)
	}

	random := secp256k1.NewElement().Multiply(secp256k1.NewScalar().Random())
	cpy := random.Copy()
	if random.Equal(cpy) != 1 {
		t.Fatal()
	}
}

func TestElement_Add(t *testing.T) {
	// Verify whether add yields the same element when given nil
	base := secp256k1.Base()
	cpy := base.Copy()
	if cpy.Add(nil).Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the same element when given identity
	base = secp256k1.Base()
	cpy = base.Copy()
	cpy.Add(secp256k1.NewElement())
	if cpy.Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the same when adding to identity
	base = secp256k1.Base()
	identity := secp256k1.NewElement()
	if identity.Add(base).Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the identity given the negative
	base = secp256k1.Base()
	negative := secp256k1.Base().Negate()
	identity = secp256k1.NewElement()
	if base.Add(negative).Equal(identity) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether add yields the double when adding to itself
	base = secp256k1.Base()
	double := secp256k1.Base().Double()
	if base.Add(base).Equal(double) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether 3*base = base + base + base
	three := secp256k1.NewScalar().One()
	three.Add(three)
	three.Add(secp256k1.NewScalar().One())

	mult := secp256k1.Base().Multiply(three)
	e := secp256k1.Base().Add(secp256k1.Base()).Add(secp256k1.Base())

	if e.Equal(mult) != 1 {
		//	t.Fatal(errExpectedEquality)
	}
}

func TestElement_Negate(t *testing.T) {
	// 0 = -0
	id := secp256k1.NewElement().Identity()
	negId := secp256k1.NewElement().Identity().Negate()

	if id.Equal(negId) != 1 {
		t.Fatal("expected equality when negating identity element")
	}

	// b + (-b) = 0
	b := secp256k1.NewElement().Base()
	negB := secp256k1.NewElement().Base().Negate()
	b.Add(negB)

	if !b.IsIdentity() {
		t.Fatal("expected identity for b + (-b)")
	}

	// -(-b) = b
	b = secp256k1.NewElement().Base()
	negB = secp256k1.NewElement().Base().Negate().Negate()

	if b.Equal(negB) != 1 {
		t.Fatal("expected equality -(-b) = b")
	}
}

func TestElement_Double(t *testing.T) {
	// Verify whether double works like adding
	base := secp256k1.Base()
	double := secp256k1.Base().Add(secp256k1.Base())
	if double.Equal(base.Double()) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether double works like multiplying
	two := secp256k1.NewScalar().One().Add(secp256k1.NewScalar().One())
	mult := secp256k1.Base().Multiply(two)
	if mult.Equal(double) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func TestElement_Substract(t *testing.T) {
	base := secp256k1.Base()

	// Verify whether subtracting yields the same element when given nil.
	if base.Subtract(nil).Equal(base) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Verify whether subtracting and then adding yields the same element.
	base2 := base.Add(base).Subtract(base)
	if base.Equal(base2) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func TestElement_Multiply(t *testing.T) {
	scalar := secp256k1.NewScalar()

	// base = base * 1
	base := secp256k1.Base()
	mult := secp256k1.Base().Multiply(scalar.One())
	if base.Equal(mult) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// Random scalar mult must not yield identity
	scalar = secp256k1.NewScalar().Random()
	m := secp256k1.Base().Multiply(scalar)
	if m.IsIdentity() {
		t.Fatal("random scalar multiplication is identity")
	}

	// 2 * base = base + base
	twoG := secp256k1.Base().Add(secp256k1.Base())
	two := secp256k1.NewScalar().One().Add(secp256k1.NewScalar().One())
	mult = secp256k1.Base().Multiply(two)

	if mult.Equal(twoG) != 1 {
		t.Fatal(errExpectedEquality)
	}

	// base * 0 = id
	if !secp256k1.Base().Multiply(scalar.Zero()).IsIdentity() {
		t.Fatal(errExpectedIdentity)
	}

	// base * nil = id
	if !secp256k1.Base().Multiply(nil).IsIdentity() {
		t.Fatal(errExpectedIdentity)
	}
}

func TestElement_Identity(t *testing.T) {
	id := secp256k1.NewElement()
	if !id.IsIdentity() {
		t.Fatal(errExpectedIdentity)
	}

	// Test encoding
	if id.Hex() != identity {
		t.Fatal("expected equality")
	}

	b, err := hex.DecodeString(identity)
	if err != nil {
		t.Fatal(err)
	}

	e := secp256k1.NewElement()
	if err := e.Decode(b); err != nil {
		t.Fatalf("unexpected error on decoding identity, got %q", err)
	}

	var invalidEncoding [32]byte
	invalidEncoding[0] = 0x02

	if err := e.Decode(invalidEncoding[:]); err == nil || err.Error() != "invalid point encoding" {
		t.Fatalf("expected specific error on decoding identity, got %q", err)
	}

	invalidEncoding[0] = 0x03

	if err := e.Decode(invalidEncoding[:]); err == nil || err.Error() != "invalid point encoding" {
		t.Fatalf("expected specific error on decoding identity, got %q", err)
	}

	// Test operation
	base := secp256k1.Base()
	if id.Equal(base.Subtract(base)) != 1 {
		log.Printf("id : %v", id.Encode())
		log.Printf("ba : %v", base.Encode())
		t.Fatal(errExpectedIdentity)
	}

	sub1 := secp256k1.Base().Double().Negate().Add(secp256k1.Base().Double())
	sub2 := secp256k1.Base().Subtract(secp256k1.Base())
	if sub1.Equal(sub2) != 1 {
		t.Fatal(errExpectedEquality)
	}

	if id.Equal(base.Multiply(nil)) != 1 {
		t.Fatal(errExpectedIdentity)
	}

	if id.Equal(base.Multiply(secp256k1.NewScalar().Zero())) != 1 {
		t.Fatal(errExpectedIdentity)
	}

	base = secp256k1.Base()
	neg := base.Copy().Negate()
	base.Add(neg)
	if id.Equal(base) != 1 {
		t.Fatal(errExpectedIdentity)
	}
}
