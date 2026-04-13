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
	"math/big"
	"math/rand"
	"testing"

	"github.com/bytemare/secp256k1"
)

const (
	elementMultiplyIterations = 64
	groupLawIterations        = 64
	roundTripIterations       = 128
	scalarCompareIterations   = 256
	scalarPowIterations       = 128
	scalarRandomRangeSamples  = 256
)

// newDeterministicTestRand returns a reproducible RNG for randomized-but-stable tests.
func newDeterministicTestRand() *rand.Rand {
	return rand.New(rand.NewSource(1))
}

// deterministicReducedScalar decodes a reproducible random scalar reduced modulo the group order.
func deterministicReducedScalar(tb testing.TB, rng *rand.Rand) *secp256k1.Scalar {
	tb.Helper()

	input := make([]byte, scalarLength)
	if _, err := rng.Read(input); err != nil {
		tb.Fatal(err)
	}

	s := secp256k1.NewScalar()
	if err := s.DecodeWithReduction(input); err != nil {
		tb.Fatal(err)
	}

	return s
}

// referenceMultiply provides a variable-time test oracle for scalar multiplication to compare other multiplication methods against.
func referenceMultiply(point *secp256k1.Element, scalar *secp256k1.Scalar) *secp256k1.Element {
	if scalar == nil {
		return secp256k1.NewElement()
	}

	result := secp256k1.NewElement()
	addend := point.Copy()
	bits := scalar.Bits()

	for i := range 256 {
		if bits[i] == 1 {
			result.Add(addend)
		}

		addend.Double()
	}

	return result
}

// TestScalar_Pow_RandomizedAgainstBigInt cross-checks modular exponentiation against big.Int.
func TestScalar_Pow_RandomizedAgainstBigInt(t *testing.T) {
	rng := newDeterministicTestRand()
	order := scalarOrderInt()

	for i := range scalarPowIterations {
		base := deterministicReducedScalar(t, rng)
		exp := deterministicReducedScalar(t, rng)

		want := scalarBytes(new(big.Int).Exp(
			new(big.Int).SetBytes(base.Encode()),
			new(big.Int).SetBytes(exp.Encode()),
			order,
		))
		got := base.Copy().Pow(exp)

		if !bytes.Equal(got.Encode(), want) {
			t.Fatalf("case %d: unexpected Pow output", i)
		}
	}
}

// TestScalar_LessOrEqual_RandomizedAgainstBigInt cross-checks canonical scalar ordering against big.Int.
func TestScalar_LessOrEqual_RandomizedAgainstBigInt(t *testing.T) {
	rng := newDeterministicTestRand()

	for i := range scalarCompareIterations {
		left := deterministicReducedScalar(t, rng)
		right := deterministicReducedScalar(t, rng)

		want := 0
		iLeft := new(big.Int).SetBytes(left.Encode())
		iRight := new(big.Int).SetBytes(right.Encode())

		if iLeft.Cmp(iRight) <= 0 {
			want = 1
		}

		if got := left.LessOrEqual(right); int(got) != want {
			t.Fatalf("case %d: expected %v, got %v", i, want, got)
		}
	}
}

// TestEncoding_RoundTrip_Randomized broadens scalar and element encoding coverage with randomized cases.
func TestEncoding_RoundTrip_Randomized(t *testing.T) {
	rng := newDeterministicTestRand()

	for i := range roundTripIterations {
		s := deterministicReducedScalar(t, rng)
		decodedScalar := secp256k1.NewScalar()
		if err := decodedScalar.Decode(s.Encode()); err != nil {
			t.Fatalf("scalar case %d: unexpected decode error: %v", i, err)
		}

		if decodedScalar.Equal(s) != 1 {
			t.Fatalf("scalar case %d: %s", i, errExpectedEquality)
		}

		e := secp256k1.Base().Multiply(deterministicReducedScalar(t, rng))
		decodedCompressed := secp256k1.NewElement()
		if err := decodedCompressed.Decode(e.Encode()); err != nil {
			t.Fatalf("element compressed case %d: unexpected decode error: %v", i, err)
		}

		if decodedCompressed.Equal(e) != 1 {
			t.Fatalf("element compressed case %d: %s", i, errExpectedEquality)
		}

		decodedUncompressed := secp256k1.NewElement()
		if err := decodedUncompressed.DecodeUncompressed(e.EncodeUncompressed()); err != nil {
			t.Fatalf("element uncompressed case %d: unexpected decode error: %v", i, err)
		}

		if decodedUncompressed.Equal(e) != 1 {
			t.Fatalf("element uncompressed case %d: %s", i, errExpectedEquality)
		}
	}
}

// TestElement_Multiply_RandomizedAgainstReference cross-checks point multiplication against a simple test oracle.
func TestElement_Multiply_RandomizedAgainstReference(t *testing.T) {
	rng := newDeterministicTestRand()
	base := secp256k1.Base()

	for i := range elementMultiplyIterations {
		pointScalar := deterministicReducedScalar(t, rng)
		multiplier := deterministicReducedScalar(t, rng)
		point := referenceMultiply(base, pointScalar)

		if got, want := base.Copy().Multiply(multiplier), referenceMultiply(base, multiplier); got.Equal(want) != 1 {
			t.Fatalf("base case %d: unexpected multiplication result", i)
		}

		if got, want := point.Copy().Multiply(multiplier), referenceMultiply(point, multiplier); got.Equal(want) != 1 {
			t.Fatalf("point case %d: unexpected multiplication result", i)
		}
	}
}

// TestElement_GroupLaw_Randomized checks basic group-law invariants across randomized elements.
func TestElement_GroupLaw_Randomized(t *testing.T) {
	rng := newDeterministicTestRand()
	identity := secp256k1.NewElement()

	for i := range groupLawIterations {
		a := secp256k1.Base().Multiply(deterministicReducedScalar(t, rng))
		b := secp256k1.Base().Multiply(deterministicReducedScalar(t, rng))
		c := secp256k1.Base().Multiply(deterministicReducedScalar(t, rng))

		if a.Copy().Add(b).Equal(b.Copy().Add(a)) != 1 {
			t.Fatalf("case %d: addition is not commutative", i)
		}

		lhs := a.Copy().Add(b).Add(c)
		rhs := a.Copy().Add(b.Copy().Add(c))
		if lhs.Equal(rhs) != 1 {
			t.Fatalf("case %d: addition is not associative", i)
		}

		if a.Copy().Add(identity).Equal(a) != 1 {
			t.Fatalf("case %d: identity add failed", i)
		}

		if !a.Copy().Subtract(a.Copy()).IsIdentity() {
			t.Fatalf("case %d: inverse law failed", i)
		}
	}
}

// TestScalar_Random_RangeGuarantees verifies Random always returns a non-zero scalar below the group order.
func TestScalar_Random_RangeGuarantees(t *testing.T) {
	order := scalarOrderInt()

	for i := range scalarRandomRangeSamples {
		s := secp256k1.NewScalar().Random()
		n := new(big.Int).SetBytes(s.Encode())

		if n.Sign() <= 0 {
			t.Fatalf("sample %d: random scalar is not strictly positive", i)
		}

		if n.Cmp(order) >= 0 {
			t.Fatalf("sample %d: random scalar is not reduced", i)
		}
	}
}
