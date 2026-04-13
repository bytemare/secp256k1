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
	"math/rand"
	"testing"

	"github.com/bytemare/secp256k1"
	"github.com/bytemare/secp256k1/internal/scalar"
)

func scalarOrderInt() *big.Int {
	return new(big.Int).SetBytes(secp256k1.Order())
}

func scalarBytes(i *big.Int) []byte {
	out := make([]byte, scalarLength)
	if i == nil {
		return out
	}

	i.FillBytes(out)

	return out
}

func reducedScalarBytes(input []byte) []byte {
	reduced := new(big.Int).SetBytes(input)
	reduced.Mod(reduced, scalarOrderInt())

	return scalarBytes(reduced)
}

func mustDecodeScalarBytes(t *testing.T, input []byte) *secp256k1.Scalar {
	t.Helper()

	s := secp256k1.NewScalar()
	if err := s.Decode(input); err != nil {
		t.Fatal(err)
	}

	return s
}

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

// TestScalar_Copy verifies Copy returns an equivalent scalar with independent state.
func TestScalar_Copy(t *testing.T) {
	random := secp256k1.NewScalar().Random()
	cpy := random.Copy()
	testScalarCopySet(t, random, cpy)
}

// TestScalar_Set verifies Set copies a scalar value without aliasing state.
func TestScalar_Set(t *testing.T) {
	random := secp256k1.NewScalar().Random()
	other := secp256k1.NewScalar().Set(random)
	testScalarCopySet(t, random, other)
}

// TestScalar_NonComparable verifies scalars cannot be meaningfully compared as Go values.
func TestScalar_NonComparable(t *testing.T) {
	random1 := secp256k1.NewScalar().Random()
	random2 := secp256k1.NewScalar().Set(random1)
	if random1 == random2 {
		t.Fatal("unexpected comparison")
	}
}

// TestScalar_SetUInt64 verifies SetUInt64 maps small integers as expected.
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

// TestScalar_CSelect verifies constant-time selection and nil-input errors.
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

// TestScalar_EncodedLength verifies encoded scalars are always 32 bytes long.
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

// TestScalar_Decode_nil verifies Decode rejects nil and empty input.
func TestScalar_Decode_nil(t *testing.T) {
	expected := errors.New("nil or empty scalar")
	if err := secp256k1.NewScalar().Decode(nil); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}

	if err := secp256k1.NewScalar().Decode([]byte{}); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}
}

// TestScalar_Decode_OutOfBounds verifies Decode rejects wrong lengths and non-canonical values.
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
	orderInt := scalarOrderInt()
	orderInt.Add(orderInt, big.NewInt(1))
	encoded = scalarBytes(orderInt)

	expected = errors.New("scalar too big")
	if err := secp256k1.NewScalar().Decode(orderInt.Bytes()); err == nil || err.Error() != expected.Error() {
		t.Errorf("expected error %q, got %v", expected, err)
	}
}

// TestScalar_Decode_ErrorDoesNotMutateReceiver verifies Decode leaves the receiver unchanged on error.
func TestScalar_Decode_ErrorDoesNotMutateReceiver(t *testing.T) {
	cases := []struct {
		wantErr error
		name    string
		input   []byte
	}{
		{
			name:    "nil",
			input:   nil,
			wantErr: errors.New("nil or empty scalar"),
		},
		{
			name:    "empty",
			input:   []byte{},
			wantErr: errors.New("nil or empty scalar"),
		},
		{
			name:    "short",
			input:   make([]byte, scalarLength-1),
			wantErr: errors.New("invalid scalar length"),
		},
		{
			name:    "long",
			input:   make([]byte, scalarLength+1),
			wantErr: errors.New("invalid scalar length"),
		},
		{
			name:    "order",
			input:   secp256k1.Order(),
			wantErr: errors.New("scalar too big"),
		},
		{
			name:    "order plus one",
			input:   scalarBytes(new(big.Int).Add(scalarOrderInt(), big.NewInt(1))),
			wantErr: errors.New("scalar too big"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := secp256k1.NewScalar().SetUInt64(9)
			before := s.Copy()

			err := s.Decode(tc.input)
			if err == nil || err.Error() != tc.wantErr.Error() {
				t.Fatalf("expected error %q, got %v", tc.wantErr, err)
			}

			if s.Equal(before) != 1 {
				t.Fatal("expected scalar to remain unchanged on Decode() error")
			}
		})
	}
}

// TestScalar_DecodeWithReduction verifies reduction semantics for canonical and non-canonical inputs.
func TestScalar_DecodeWithReduction(t *testing.T) {
	order := scalarOrderInt()
	orderMinusOne := new(big.Int).Sub(new(big.Int).Set(order), big.NewInt(1))
	orderPlusOne := new(big.Int).Add(new(big.Int).Set(order), big.NewInt(1))
	orderPlusFortyTwo := new(big.Int).Add(new(big.Int).Set(order), big.NewInt(42))
	maxUint256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	cases := []struct {
		wantErr   error
		name      string
		input     []byte
		want      []byte
		canonical bool
	}{
		{
			name:    "nil",
			input:   nil,
			wantErr: secp256k1.ErrParamInvalidInputLength,
		},
		{
			name:    "empty",
			input:   []byte{},
			wantErr: secp256k1.ErrParamInvalidInputLength,
		},
		{
			name:    "short",
			input:   make([]byte, scalarLength-1),
			wantErr: secp256k1.ErrParamInvalidInputLength,
		},
		{
			name:    "long",
			input:   make([]byte, scalarLength+1),
			wantErr: secp256k1.ErrParamInvalidInputLength,
		},
		{
			name:      "zero",
			input:     scalarBytes(big.NewInt(0)),
			want:      scalarBytes(big.NewInt(0)),
			canonical: true,
		},
		{
			name:      "one",
			input:     scalarBytes(big.NewInt(1)),
			want:      scalarBytes(big.NewInt(1)),
			canonical: true,
		},
		{
			name:      "leading zeros",
			input:     scalarBytes(big.NewInt(42)),
			want:      scalarBytes(big.NewInt(42)),
			canonical: true,
		},
		{
			name:      "order minus one",
			input:     scalarBytes(orderMinusOne),
			want:      scalarBytes(orderMinusOne),
			canonical: true,
		},
		{
			name:  "order reduces to zero",
			input: scalarBytes(order),
			want:  scalarBytes(big.NewInt(0)),
		},
		{
			name:  "order plus one reduces to one",
			input: scalarBytes(orderPlusOne),
			want:  scalarBytes(big.NewInt(1)),
		},
		{
			name:  "order plus forty two reduces to forty two",
			input: scalarBytes(orderPlusFortyTwo),
			want:  scalarBytes(big.NewInt(42)),
		},
		{
			name:  "max uint256",
			input: scalarBytes(maxUint256),
			want:  reducedScalarBytes(scalarBytes(maxUint256)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := secp256k1.NewScalar().SetUInt64(9)
			before := s.Copy()

			err := s.DecodeWithReduction(tc.input)
			if tc.wantErr != nil {
				if err == nil || err.Error() != tc.wantErr.Error() {
					t.Fatalf("expected error %q, got %v", tc.wantErr, err)
				}

				if s.Equal(before) != 1 {
					t.Fatal("expected scalar to remain unchanged on error")
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(s.Encode(), tc.want) {
				t.Fatalf("unexpected reduced encoding\nwant: %x\ngot:  %s", tc.want, s.Hex())
			}

			expected := mustDecodeScalarBytes(t, tc.want)
			if s.Equal(expected) != 1 {
				t.Fatal(errExpectedEquality)
			}

			if len(tc.input) != scalarLength {
				return
			}

			decoded := secp256k1.NewScalar()
			err = decoded.Decode(tc.input)

			if tc.canonical {
				if err != nil {
					t.Fatalf("Decode() unexpected error: %v", err)
				}

				if decoded.Equal(s) != 1 {
					t.Fatal("expected Decode() and DecodeWithReduction() to match")
				}

				return
			}

			expectedErr := errors.New("scalar too big")
			if err == nil || err.Error() != expectedErr.Error() {
				t.Fatalf("expected error %q, got %v", expectedErr, err)
			}
		})
	}
}

// TestScalar_DecodeWithReduction_RandomizedModOrder verifies reduction matches big.Int modulo arithmetic.
func TestScalar_DecodeWithReduction_RandomizedModOrder(t *testing.T) {
	const iterations = 256

	rng := rand.New(rand.NewSource(1))

	for i := range iterations {
		input := make([]byte, scalarLength)
		if _, err := rng.Read(input); err != nil {
			t.Fatalf("case %d: failed to generate input: %v", i, err)
		}

		got := secp256k1.NewScalar()
		if err := got.DecodeWithReduction(input); err != nil {
			t.Fatalf("case %d: unexpected error: %v", i, err)
		}

		want := reducedScalarBytes(input)
		if !bytes.Equal(got.Encode(), want) {
			t.Fatalf("case %d: unexpected reduction for %x\nwant: %x\ngot:  %s", i, input, want, got.Hex())
		}

		expected := mustDecodeScalarBytes(t, want)
		if got.Equal(expected) != 1 {
			t.Fatalf("case %d: expected scalar equality", i)
		}
	}
}

// TestScalar_DecodeWithReduction_RandomizedOrderOffsets verifies order-plus-delta inputs reduce to delta.
func TestScalar_DecodeWithReduction_RandomizedOrderOffsets(t *testing.T) {
	const iterations = 256

	rng := rand.New(rand.NewSource(2))
	order := scalarOrderInt()
	expectedErr := errors.New("scalar too big")

	for i := range iterations {
		delta := new(big.Int).SetUint64(rng.Uint64())
		input := scalarBytes(new(big.Int).Add(new(big.Int).Set(order), delta))

		got := secp256k1.NewScalar()
		if err := got.DecodeWithReduction(input); err != nil {
			t.Fatalf("case %d: unexpected error: %v", i, err)
		}

		want := scalarBytes(delta)
		if !bytes.Equal(got.Encode(), want) {
			t.Fatalf("case %d: unexpected reduction for delta %x\nwant: %x\ngot:  %s", i, delta, want, got.Hex())
		}

		if err := secp256k1.NewScalar().Decode(input); err == nil || err.Error() != expectedErr.Error() {
			t.Fatalf("case %d: expected Decode() error %q, got %v", i, expectedErr, err)
		}
	}
}

// TestScalar_Zero verifies zero behaves as the additive identity.
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

// TestScalar_One verifies One returns the multiplicative identity.
func TestScalar_One(t *testing.T) {
	one := secp256k1.NewScalar().One()
	m := one.Copy()
	if one.Equal(m.Multiply(m)) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

// TestScalar_MinusOne verifies MinusOne matches order minus one.
func TestScalar_MinusOne(t *testing.T) {
	expected := secp256k1.NewScalar()
	scalar.Sub(&expected.S, scalar.Order(), scalar.One())

	pMin1 := secp256k1.NewScalar().MinusOne()

	if expected.Equal(pMin1) != 1 || !bytes.Equal(expected.Encode(), pMin1.Encode()) {
		t.Fatal(errExpectedEquality)
	}
}

// TestScalar_Random verifies Random never returns zero.
func TestScalar_Random(t *testing.T) {
	r := secp256k1.NewScalar().Random()
	if r.IsZero() {
		t.Fatalf("random scalar is zero: %v", r.Hex())
	}
}

// TestScalar_Equal verifies equality across nil, identical, copied, and random scalars.
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

// TestScalar_LessOrEqual verifies canonical ordering for edge values and adjacent representatives.
func TestScalar_LessOrEqual(t *testing.T) {
	zero := secp256k1.NewScalar().Zero()
	one := secp256k1.NewScalar().One()
	two := secp256k1.NewScalar().One().Add(one)
	order := scalarOrderInt()
	nMinusTwo := mustDecodeScalarBytes(t, scalarBytes(new(big.Int).Sub(order, big.NewInt(2))))
	nMinusOne := mustDecodeScalarBytes(t, scalarBytes(new(big.Int).Sub(order, big.NewInt(1))))

	if zero.LessOrEqual(one) != 1 {
		t.Fatal("expected 0 <= 1")
	}

	if one.LessOrEqual(two) != 1 {
		t.Fatal("expected 1 <= 2")
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

	if nMinusTwo.LessOrEqual(nMinusOne) != 1 {
		t.Fatal("expected n-2 <= n-1")
	}

	if nMinusOne.LessOrEqual(nMinusTwo) == 1 {
		t.Fatal("expected n-1 > n-2")
	}

	if nMinusOne.LessOrEqual(nMinusOne) != 1 {
		t.Fatal("expected n-1 == n-1")
	}

	if zero.LessOrEqual(nMinusOne) != 1 {
		t.Fatal("expected 0 <= n-1")
	}

	if nMinusOne.LessOrEqual(zero) == 1 {
		t.Fatal("expected n-1 > 0")
	}
}

// TestScalar_Add verifies adding nil leaves the scalar unchanged.
func TestScalar_Add(t *testing.T) {
	r := secp256k1.NewScalar().Random()
	cpy := r.Copy()
	if r.Add(nil).Equal(cpy) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

// TestScalar_Subtract verifies subtracting nil leaves the scalar unchanged.
func TestScalar_Subtract(t *testing.T) {
	r := secp256k1.NewScalar().Random()
	cpy := r.Copy()
	if r.Subtract(nil).Equal(cpy) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

// TestScalar_Multiply verifies multiplying by nil yields zero.
func TestScalar_Multiply(t *testing.T) {
	s := secp256k1.NewScalar().Random()
	if !s.Multiply(nil).IsZero() {
		t.Fatal("expected zero")
	}
}

func testModPow(base, exp *secp256k1.Scalar, basei, expi, mod *big.Int) error {
	iResult := new(big.Int).Exp(basei, expi, mod)
	b := scalarBytes(iResult)

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

// TestScalar_Pow verifies exponentiation against algebraic identities and big.Int modular exponentiation.
func TestScalar_Pow(t *testing.T) {
	// s^0 = 1
	s := secp256k1.NewScalar().Random()
	zero := secp256k1.NewScalar().Zero()
	if s.Pow(zero).Equal(secp256k1.NewScalar().One()) != 1 {
		t.Fatal("expected s**0 = 1")
	}

	// 0^0 = 1
	s.Zero()
	if s.Pow(zero).Equal(secp256k1.NewScalar().One()) != 1 {
		t.Fatal("expected 0**0 = 1")
	}

	// 0^5 = 0
	s.Zero()
	exp := secp256k1.NewScalar().SetUInt64(5)
	if !s.Pow(exp).IsZero() {
		t.Fatalf("expected 0**5 = 0. got %v", s.Hex())
	}

	// s^1 = s
	s = secp256k1.NewScalar().Random()
	exp = secp256k1.NewScalar().One()
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
	s3 = s.Copy().Multiply(s).Multiply(s)
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
	order := scalarOrderInt()
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

	// random^(n-1)
	s.Random()
	exp.MinusOne()
	iBase.SetBytes(s.Encode())
	iExp.Sub(new(big.Int).Set(order), big.NewInt(1))

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

	// aliasing: s^s
	s.Random()
	original := s.Copy()
	iBase.SetBytes(original.Encode())
	iExp.SetBytes(original.Encode())
	aliasResult := scalarBytes(new(big.Int).Exp(iBase, iExp, order))
	s.Pow(s)

	if !bytes.Equal(s.Encode(), aliasResult) {
		t.Fatalf("expected %v, got %v", hex.EncodeToString(aliasResult), s.Hex())
	}
}

// TestScalar_Pow_nil verifies Pow panics on nil exponent input.
func TestScalar_Pow_nil(t *testing.T) {
	s := secp256k1.NewScalar().Random()

	if ok, err := expectPanic(secp256k1.ErrParamNilScalar, func() {
		s.Pow(nil)
	}); !ok {
		t.Fatal(err)
	}
}

// TestScalar_Invert verifies inversion is consistent with multiplication and squaring.
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

// TestScalar_HashToScalar verifies HashToScalar matches the expected reference output.
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

// TestScalar_HashToScalar_NoDST verifies HashToScalar panics on a missing DST.
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

// TestScalarBitsMSB verifies Bits exposes the most significant bit at index 255.
func TestScalarBitsMSB(t *testing.T) {
	// Define the scalar with only the MSB set: 0x8000...0000
	scalarBytes := [32]byte{}
	scalarBytes[0] = 0x80 // Set the MSB (bit 255)

	// Initialize the scalar
	s := secp256k1.NewScalar()
	if err := s.Decode(scalarBytes[:]); err != nil {
		t.Fatalf("Failed to set scalar bytes: %v", err)
	}

	// Get the bit representation
	bits := s.Bits()

	// Verify that only the MSB is set
	for i := range 256 {
		expected := uint8(0)
		if i == 255 {
			expected = 1
		}
		if bits[i] != expected {
			t.Errorf("Bit %d: expected %d, got %d", i, expected, bits[i])
		}
	}
}

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
)

func hasPanic(f func()) (has bool, err error) {
	err = nil
	var report any
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
