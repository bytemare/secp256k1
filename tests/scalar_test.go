// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1_test

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/bytemare/secp256k1"
)

func testScalarCopySet(t *testing.T, scalar, other *secp256k1.Scalar) {
	// Verify they don't point to the same thing
	if &scalar == &other {
		t.Fatalf("Pointer to the same scalar")
	}

	// Verify whether they are equivalent
	if scalar.Equal(other) != 1 {
		t.Fatalf("Expected equality")
	}

	// Verify that operations on one don't affect the other
	scalar.Add(scalar)
	if scalar.Equal(other) == 1 {
		t.Fatalf("Unexpected equality")
	}

	other.Invert()
	if scalar.Equal(other) == 1 {
		t.Fatalf("Unexpected equality")
	}

	// Verify setting to nil sets to 0
	if scalar.Set(nil).Equal(secp256k1.NewScalar()) != 1 {
		t.Error(errExpectedEquality)
	}
}

func TestScalar_Copy(t *testing.T) {
	random := secp256k1.NewScalar().Random()
	cpy := random.Copy()
	testScalarCopySet(t, random, cpy)
}

func TestScalar_Set(t *testing.T) {
	random := secp256k1.NewScalar().Random()
	other := secp256k1.NewScalar().Set(random)
	testScalarCopySet(t, random, other)
}

func TestScalar_NonComparable(t *testing.T) {
	random1 := secp256k1.NewScalar().Random()
	random2 := secp256k1.NewScalar().Set(random1)
	if random1 == random2 {
		t.Fatal("unexpected comparison")
	}
}

func TestScalar_SetInt(t *testing.T) {
	s := secp256k1.NewScalar().SetUInt64(0)
	if !s.IsZero() {
		t.Fatal("expected 0")
	}

	s.SetUInt64(1)
	if s.Equal(secp256k1.NewScalar().One()) != 1 {
		t.Fatal("expected 1")
	}
}

func TestScalar_EncodedLength(t *testing.T) {
	encodedScalar := secp256k1.NewScalar().Random().Encode()
	if len(encodedScalar) != scalarLength {
		t.Fatalf(
			"Encode() is expected to return %d bytes, but returned %d bytes",
			scalarLength,
			encodedScalar,
		)
	}
}

func TestScalar_Decode_OutOfBounds(t *testing.T) {
	// Decode invalid length
	encoded := make([]byte, scalarLength-1)
	big.NewInt(1).FillBytes(encoded)

	expected := errors.New("invalid scalar length")
	if err := secp256k1.NewScalar().Decode(encoded); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	encoded = make([]byte, scalarLength+1)
	big.NewInt(1).FillBytes(encoded)

	expected = errors.New("invalid scalar length")
	if err := secp256k1.NewScalar().Decode(encoded); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// Decode the order
	encoded = make([]byte, scalarLength)

	order, ok := new(big.Int).SetString(groupOrder, 0)
	if !ok {
		t.Errorf("setting int in base %d failed: %v", 0, groupOrder)
	}

	order.FillBytes(encoded)

	expected = errors.New("scalar too big")
	if err := secp256k1.NewScalar().Decode(encoded); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// Decode a scalar higher than order
	encoded = make([]byte, 32)
	order.Add(order, big.NewInt(1))
	order.FillBytes(encoded)

	expected = errors.New("scalar too big")
	if err := secp256k1.NewScalar().Decode(encoded); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}
}

func TestScalar_Zero(t *testing.T) {
	zero := secp256k1.NewScalar()
	if !zero.IsZero() {
		t.Fatal("expected zero scalar")
	}

	s := secp256k1.NewScalar().Random()
	if !s.Subtract(s).IsZero() {
		t.Fatal("expected zero scalar")
	}

	s = secp256k1.NewScalar().Random()
	if s.Add(zero).Equal(s) != 1 {
		t.Fatal("expected no change in adding zero scalar")
	}

	s = secp256k1.NewScalar().Random()
	if s.Add(zero).Equal(s) != 1 {
		t.Fatal("not equal")
	}
}

func TestScalar_One(t *testing.T) {
	one := secp256k1.NewScalar().One()
	m := one.Copy()
	if one.Equal(m.Multiply(m)) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func TestScalar_Random(t *testing.T) {
	r := secp256k1.NewScalar().Random()
	if r.Equal(secp256k1.NewScalar().Zero()) == 1 {
		t.Fatalf("random scalar is zero: %v", hex.EncodeToString(r.Encode()))
	}
}

func TestScalar_Equal(t *testing.T) {
	zero := secp256k1.NewScalar().Zero()
	zero2 := secp256k1.NewScalar().Zero()

	if zero.Equal(nil) != 0 {
		t.Error("expect difference")
	}

	if zero.Equal(zero2) != 1 {
		t.Fatal(errExpectedEquality)
	}

	random := secp256k1.NewScalar().Random()
	cpy := random.Copy()
	if random.Equal(cpy) != 1 {
		t.Fatal(errExpectedEquality)
	}

	random2 := secp256k1.NewScalar().Random()
	if random.Equal(random2) == 1 {
		t.Fatal("unexpected equality")
	}
}

func TestScalar_LessOrEqual(t *testing.T) {
	zero := secp256k1.NewScalar().Zero()
	one := secp256k1.NewScalar().One()
	two := secp256k1.NewScalar().One().Add(one)

	if zero.LessOrEqual(one) != 1 {
		t.Fatal("expected 0 < 1")
	}

	if one.LessOrEqual(two) != 1 {
		t.Fatal("expected 1 < 2")
	}

	if one.LessOrEqual(zero) == 1 {
		t.Fatal("expected 1 > 0")
	}

	if two.LessOrEqual(one) == 1 {
		t.Fatal("expected 2 > 1")
	}

	if two.LessOrEqual(two) != 1 {
		t.Fatal("expected 2 == 2")
	}

	s := secp256k1.NewScalar().Random()
	r := s.Copy().Add(secp256k1.NewScalar().One())

	if s.LessOrEqual(r) != 1 {
		t.Fatal("expected s < s + 1")
	}
}

func TestScalar_Add(t *testing.T) {
	r := secp256k1.NewScalar().Random()
	cpy := r.Copy()
	if r.Add(nil).Equal(cpy) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func TestScalar_Subtract(t *testing.T) {
	r := secp256k1.NewScalar().Random()
	cpy := r.Copy()
	if r.Subtract(nil).Equal(cpy) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func TestScalar_Multiply(t *testing.T) {
	s := secp256k1.NewScalar().Random()
	if !s.Multiply(nil).IsZero() {
		t.Fatal("expected zero")
	}
}

func TestScalar_Pow(t *testing.T) {
	// s**nil = 1
	s := secp256k1.NewScalar().Random()
	if s.Pow(nil).Equal(secp256k1.NewScalar().One()) != 1 {
		t.Fatal("expected s**nil = 1")
	}

	// s**0 = 1
	s = secp256k1.NewScalar().Random()
	zero := secp256k1.NewScalar().Zero()
	if s.Pow(zero).Equal(secp256k1.NewScalar().One()) != 1 {
		t.Fatal("expected s**0 = 1")
	}

	// s**1 = s
	s = secp256k1.NewScalar().Random()
	exp := secp256k1.NewScalar().One()
	if s.Copy().Pow(exp).Equal(s) != 1 {
		t.Fatal("expected s**1 = s")
	}

	// s**2 = s*s
	s = secp256k1.NewScalar().One()
	s.Add(s.Copy().One())
	s2 := s.Copy().Multiply(s)
	exp.SetUInt64(2)

	if s.Pow(exp).Equal(s2) != 1 {
		t.Fatal("expected s**2 = s*s")
	}

	// s**3 = s*s*s
	s = secp256k1.NewScalar().Random()
	s3 := s.Copy().Multiply(s)
	s3.Multiply(s)
	exp.SetUInt64(3)

	if s.Pow(exp).Equal(s3) != 1 {
		t.Fatal("expected s**3 = s*s*s")
	}

	// 5**7 = 78125 = 00000000 00000001 00110001 00101101 = 1 49 45
	result := secp256k1.NewScalar()
	result.SetUInt64(uint64(math.Pow(5, 7)))

	s.SetUInt64(5)
	exp.SetUInt64(7)
	res := s.Pow(exp)
	if res.Equal(result) != 1 {
		t.Fatal("expected 5**7 = 78125")
	}

	// 3**255 = 11F1B08E87EC42C5D83C3218FC83C41DCFD9F4428F4F92AF1AAA80AA46162B1F71E981273601F4AD1DD4709B5ACA650265A6AB
	iBase := big.NewInt(3)
	iExp := big.NewInt(255)
	order, ok := new(big.Int).SetString(secp256k1.Order(), 0)
	if !ok {
		t.Fatal(ok)
	}
	iResult := new(big.Int).Exp(iBase, iExp, order)
	b := make([]byte, scalarLength)
	iResult.FillBytes(b)

	result = secp256k1.NewScalar()
	//result.SetBigInt(iResult)
	if err := result.Decode(b); err != nil {
		t.Fatal(err)
	}

	s.SetUInt64(3)
	exp.SetUInt64(255)

	res = s.Pow(exp)
	if res.Equal(result) != 1 {
		t.Fatal(
			"expected 3**255 = " +
				"11F1B08E87EC42C5D83C3218FC83C41DCFD9F4428F4F92AF1AAA80AA46162B1F71E981273601F4AD1DD4709B5ACA650265A6AB",
		)
	}

	// 7945232487465**513
	iBase.SetInt64(7945232487465)
	iExp.SetInt64(513)
	iResult = iResult.Exp(iBase, iExp, order)

	b = make([]byte, scalarLength)
	iResult.FillBytes(b)

	if err := result.Decode(b); err != nil {
		t.Fatal(err)
	}

	s.SetUInt64(7945232487465)
	exp.SetUInt64(513)

	res = s.Pow(exp)
	if res.Equal(result) != 1 {
		t.Fatal("expect equality on 7945232487465**513")
	}

	// random**random
	s.Random()
	exp.Random()

	iBase.SetBytes(s.Encode())
	iExp.SetBytes(exp.Encode())
	iResult.Exp(iBase, iExp, order)

	b = make([]byte, scalarLength)
	iResult.FillBytes(b)

	if err := result.Decode(b); err != nil {
		t.Fatal(err)
	}

	if s.Pow(exp).Equal(result) != 1 {
		t.Fatal("expected equality on random numbers")
	}
}

func TestScalar_Invert(t *testing.T) {
	s := secp256k1.NewScalar().Random()
	sqr := s.Copy().Multiply(s)

	i := s.Copy().Invert().Multiply(sqr)
	if i.Equal(s) != 1 {
		t.Fatal(errExpectedEquality)
	}

	s = secp256k1.NewScalar().Random()
	square := s.Copy().Multiply(s)
	inv := square.Copy().Invert()
	if s.One().Equal(square.Multiply(inv)) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

func TestScalar_HashToScalar(t *testing.T) {
	data := []byte("input data")
	dst := []byte("domain separation tag")
	encoded := "782a63d48eace435ac06468208d9a62e3680e4ddc3977c4345b2c6de08258b69"

	b, err := hex.DecodeString(encoded)
	if err != nil {
		t.Error(err)
	}

	ref := secp256k1.NewScalar()
	if err := ref.Decode(b); err != nil {
		t.Error(err)
	}

	s := secp256k1.HashToScalar(data, dst)
	if s.Equal(ref) != 1 {
		t.Error(errExpectedEquality)
	}
}

func TestScalar_HashToScalar_NoDST(t *testing.T) {
	data := []byte("input data")

	// Nil DST
	if panics, err := expectPanic(errors.New("zero-length DST"), func() {
		_ = secp256k1.HashToScalar(data, nil)
	}); !panics {
		t.Error(fmt.Errorf("%s: %w)", errNoPanic, err))
	}

	// Zero length DST
	if panics, err := expectPanic(errors.New("zero-length DST"), func() {
		_ = secp256k1.HashToScalar(data, []byte{})
	}); !panics {
		t.Error(fmt.Errorf("%s: %w)", errNoPanic, err))
	}
}

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
)

func hasPanic(f func()) (has bool, err error) {
	err = nil
	var report interface{}
	func() {
		defer func() {
			if report = recover(); report != nil {
				has = true
			}
		}()

		f()
	}()

	if has {
		err = fmt.Errorf("%v", report)
	}

	return has, err
}

// expectPanic executes the function f with the expectation to recover from a panic. If no panic occurred or if the
// panic message is not the one expected, ExpectPanic returns (false, error).
func expectPanic(expectedError error, f func()) (bool, error) {
	hasPanic, err := hasPanic(f)

	if !hasPanic {
		return false, errNoPanic
	}

	if expectedError == nil {
		return true, nil
	}

	if err == nil {
		return false, errNoPanicMessage
	}

	if err.Error() != expectedError.Error() {
		return false, fmt.Errorf("expected %q, got: %w", expectedError, err)
	}

	return true, nil
}
