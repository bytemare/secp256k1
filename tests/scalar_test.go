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
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/bytemare/secp256k1"
	"github.com/bytemare/secp256k1/internal/scalar"
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

func TestScalar_SetUInt64(t *testing.T) {
	s := secp256k1.NewScalar().SetUInt64(0)
	if !s.IsZero() {
		t.Fatal("expected 0")
	}

	s.SetUInt64(1)
	if s.Equal(secp256k1.NewScalar().One()) != 1 {
		t.Fatal("expected 1")
	}
}

func TestScalar_CSelect(t *testing.T) {
	a, b := secp256k1.NewScalar().Random(), secp256k1.NewScalar().Random()

	// 0: res = a
	res := secp256k1.NewScalar()
	if err := res.CSelect(0, a, b); err != nil {
		t.Fatal(err)
	}

	if res.Equal(a) != 1 {
		t.Fatalf("expected equality")
	}

	// 1: res = b
	res = secp256k1.NewScalar()
	if err := res.CSelect(1, a, b); err != nil {
		t.Fatal(err)
	}

	if res.Equal(b) != 1 {
		t.Fatalf("expected equality")
	}

	// Test errors
	expected := errors.New("nil or empty scalar")

	if err := res.CSelect(0, nil, b); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	if err := res.CSelect(0, a, nil); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
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

func TestScalar_Decode_nil(t *testing.T) {
	expected := errors.New("nil or empty scalar")
	if err := secp256k1.NewScalar().Decode(nil); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	if err := secp256k1.NewScalar().Decode([]byte{}); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
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
	order := secp256k1.Order()

	expected = errors.New("scalar too big")
	if err := secp256k1.NewScalar().Decode(order); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	// Decode a scalar higher than order
	encoded = make([]byte, scalarLength)
	order1 := new(big.Int).SetBytes(order)
	order1.Add(order1, big.NewInt(1)).FillBytes(encoded)

	expected = errors.New("scalar too big")
	if err := secp256k1.NewScalar().Decode(order1.Bytes()); err == nil || err.Error() != expected.Error() {
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

func TestScalar_MinusOne(t *testing.T) {
	expected := secp256k1.NewScalar()
	scalar.Sub(&expected.S, &scalar.Order, &scalar.One)

	pMin1 := secp256k1.NewScalar().MinusOne()

	if expected.Equal(pMin1) != 1 || !bytes.Equal(expected.Encode(), pMin1.Encode()) {
		t.Fatal(errExpectedEquality)
	}
}

func TestScalar_Random(t *testing.T) {
	r := secp256k1.NewScalar().Random()
	if r.IsZero() {
		t.Fatalf("random scalar is zero: %v", r.Hex())
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
	r := s.Copy().Add(one)
	sub := s.Copy().Subtract(one)

	if s.LessOrEqual(r) != 1 {
		t.Fatal("expected s < s + 1")
	}

	if s.LessOrEqual(sub) == 1 {
		t.Fatal("expected s > s - 1")
	}

	min1 := secp256k1.NewScalar().MinusOne()
	min2 := secp256k1.NewScalar().Set(min1).Subtract(min1)

	if min2.LessOrEqual(min1) != 1 {
		t.Fatal("expected -1 < -2")
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

func testModPow(base, exp *secp256k1.Scalar, basei, expi, mod *big.Int) error {
	iResult := new(big.Int).Exp(basei, expi, mod)
	b := make([]byte, scalarLength)
	iResult.FillBytes(b)

	result := secp256k1.NewScalar()
	if err := result.Decode(b); err != nil {
		return err
	}

	power := base.Copy().Pow(exp)
	if power.Equal(result) != 1 {
		return fmt.Errorf("expected scalar equality")
	}

	if !bytes.Equal(power.Encode(), b) {
		return fmt.Errorf("expected %v, got %v", hex.EncodeToString(b), power.Hex())
	}

	return nil
}

func TestScalar_Pow(t *testing.T) {
	// s^nil = 1
	s := secp256k1.NewScalar().Random()
	if s.Pow(nil).Equal(secp256k1.NewScalar().One()) != 1 {
		t.Fatal("expected s**nil = 1")
	}

	// s^0 = 1
	s = secp256k1.NewScalar().Random()
	zero := secp256k1.NewScalar().Zero()
	if s.Pow(zero).Equal(secp256k1.NewScalar().One()) != 1 {
		t.Fatal("expected s**0 = 1")
	}

	// s^1 = s
	s = secp256k1.NewScalar().Random()
	exp := secp256k1.NewScalar().One()
	if s.Copy().Pow(exp).Equal(s) != 1 {
		t.Fatal("expected s**1 = s")
	}

	// s^2 = s*s
	s = secp256k1.NewScalar().SetUInt64(2)
	s2 := s.Copy().Multiply(s) // s2 = 4
	two := secp256k1.NewScalar().SetUInt64(2)

	if s.Pow(two).Equal(s2) != 1 { // 2^2 ?= 4
		t.Fatal("expected s**2 = s*s")
	}

	// s^3 = s*s*s
	s = secp256k1.NewScalar().Random()
	s3 := s.Copy().Multiply(s)
	s3.Multiply(s)
	exp.SetUInt64(3)

	if s.Pow(exp).Equal(s3) != 1 {
		t.Fatal("expected s**3 = s*s*s")
	}

	// random^3
	s = secp256k1.NewScalar().Random()
	s3 = s.Copy().Multiply(s)
	s3.Multiply(s)
	exp.SetUInt64(3)

	if s.Pow(exp).Equal(s3) != 1 {
		t.Fatal("expected s**3 = s*s*s")
	}

	// 5^7 = 78125 = 00000000 00000001 00110001 00101101 = 1 49 45
	result := secp256k1.NewScalar()
	result.SetUInt64(uint64(math.Pow(5, 7)))

	s.SetUInt64(5)
	exp.SetUInt64(7)
	res := s.Pow(exp)
	if res.Equal(result) != 1 {
		t.Fatal("expected 5**7 = 78125")
	}

	// 3^255 =
	// 11F1B08E87EC42C5D83C3218FC83C41DCFD9F4428F4F92AF1AAA80AA46162B1F71E981273601F4AD1DD4709B5ACA650265A6AB
	// fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
	iBase := big.NewInt(3)
	iExp := big.NewInt(255)
	order := new(big.Int).SetBytes(secp256k1.Order())
	s.SetUInt64(3)
	exp.SetUInt64(255)

	if err := testModPow(s, exp, iBase, iExp, order); err != nil {
		t.Fatal(err)
	}

	// 7945232487465^513
	iBase.SetInt64(7945232487465)
	iExp.SetInt64(513)
	s.SetUInt64(7945232487465)
	exp.SetUInt64(513)

	if err := testModPow(s, exp, iBase, iExp, order); err != nil {
		t.Fatal(err)
	}

	// big numbers
	shex := "e3e1cfd05ed144d6be4df974d34bcb8d1858c8d95e9c7da2022a95f4e6f874e7"
	ehex := "a223866418ea560c12ee6baed4062d5307b6f390f621c887e015c3769eba95e5"

	if err := s.DecodeHex(shex); err != nil {
		t.Fatal(err)
	}

	if err := exp.DecodeHex(ehex); err != nil {
		t.Fatal(err)
	}

	iBase = big.NewInt(0).SetBytes(s.Encode())
	iExp = big.NewInt(0).SetBytes(exp.Encode())

	if err := testModPow(s, exp, iBase, iExp, order); err != nil {
		t.Fatal(err)
	}

	// random^random
	s.Random()
	exp.Random()

	iBase.SetBytes(s.Encode())
	iExp.SetBytes(exp.Encode())

	if err := testModPow(s, exp, iBase, iExp, order); err != nil {
		t.Fatal(err)
	}
	/*

					bad
							scalar_test.go:387: e3e1cfd05ed144d6be4df974d34bcb8d1858c8d95e9c7da2022a95f4e6f874e7
							    scalar_test.go:388: a223866418ea560c12ee6baed4062d5307b6f390f621c887e015c3769eba95e5
							    scalar_test.go:389: 141c46ee9029a535aeb7c3ded789c62a9839856e98b5a3e690fcbf46ab0469fd
							    scalar_test.go:390: 24c451d1833a4be5130db3b91b700bb1c6c24db07694f1a4c926ad5fa35afa22

						scalar_test.go:392: acc440048a42c74b137a260e6665500c36736bf9ad2b44903ec91f4e00e7c4ed
						    scalar_test.go:393: d98c112c47ba1fa31d16a3aa8999bbae5ee154b5778118e4c6354de01e3e6693
						    scalar_test.go:394: 3d38f93088bc9359787dc540614c9f51002024473917cdf00c6686154e27d611
						    scalar_test.go:395: a7d0630f9612566c5a1a8c98a2eaad7d6828d9e27ebff1fa9cfd275408570970
					good
					scalar_test.go:377: c1dc969f8e2c57c7bd500c96cf2b75ddbe24ec181a55b88e9097a1e5c24234aa
					    scalar_test.go:378: 77167ac354f5023371848130cd0a7983de8497334c902c9aac8266c442a43be5
					    scalar_test.go:379: aa5fdf621b226987414d2d36e47899bdbd76b56168f5f5903402f31ba0e0aa39
					    scalar_test.go:380: aa5fdf621b226987414d2d36e47899bdbd76b56168f5f5903402f31ba0e0aa39

					scalar_test.go:377: 70dadd1654ecf62e65dcce9d606438f8723defe60edbef38bbad993ce52d5b48
				    scalar_test.go:378: 2244fc2ca53ecfd9a78bd6361eb2d3746f1092384dffd8a3b78a9b203123c703
				    scalar_test.go:379: db8c4b1636ae4b4e2a4527505c8d7eb8c3480fa6374f51308368e59f09e496fc
				    scalar_test.go:380: db8c4b1636ae4b4e2a4527505c8d7eb8c3480fa6374f51308368e59f09e496fc

			scalar_test.go:377: 41d230446a4b86ff933e9acf485591bb030847c7b8400a79cd5eff63438454d2
			    scalar_test.go:378: 3b43aec377712a550f2f65b5f51aeaa853962c985f5aa7c31edb62709cff55ba
			    scalar_test.go:379: 01274da74324bbf4d5046700b4f75ad9c059d77d7d2719e4d4d4b73a96cfccc8
			    scalar_test.go:380: 01274da74324bbf4d5046700b4f75ad9c059d77d7d2719e4d4d4b73a96cfccc8

		scalar_test.go:377: 8d33245e2141894370f6683406dc897d61e7b518147c98c961b0c1da06d03a86
		    scalar_test.go:378: ca52beef809c8071aa3d8194efe4662397ec095a75a662e2fad78f15d2bd3f16
		    scalar_test.go:379: 0f4b9bc88501fde1674b58b78ffa5e87af3ee5f4a5d2ce4caa3824b9b5496c3f
		    scalar_test.go:380: 40cf80e7e6bc0f071608dadd241cc0f1c895a77608c08dad485b0c4db170d067
	*/
}

func TestScalar_Invert(t *testing.T) {
	s := secp256k1.NewScalar().Random()
	sqr := s.Copy().Square()

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
