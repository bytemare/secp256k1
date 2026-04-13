// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1_test

import (
	"testing"

	"github.com/bytemare/secp256k1"
)

var (
	benchmarkHashInput   = []byte("benchmark input for secp256k1 hash-to-curve")
	benchmarkHashDST     = []byte("secp256k1_XMD:SHA-256_SSWU_RO_benchmark")
	benchmarkCompareSink uint64
)

// benchmarkScalarLessOrEqualPair measures scalar ordering on a stable operand pair.
func benchmarkScalarLessOrEqualPair(b *testing.B, left, right *secp256k1.Scalar) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		benchmarkCompareSink = left.LessOrEqual(right)
	}
}

// BenchmarkElementAdd measures complete projective point addition.
func BenchmarkElementAdd(b *testing.B) {
	lhs := secp256k1.Base().Multiply(secp256k1.NewScalar().Random())
	rhs := secp256k1.Base().Multiply(secp256k1.NewScalar().Random())
	result := secp256k1.NewElement()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		result.Set(lhs)
		result.Add(rhs)
	}
}

// BenchmarkElementMultiply measures scalar multiplication on a non-identity point.
func BenchmarkElementMultiply(b *testing.B) {
	base := secp256k1.Base()
	scalar := secp256k1.NewScalar().Random()
	result := secp256k1.NewElement()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		result.Set(base)
		result.Multiply(scalar)
	}
}

// BenchmarkScalarMultiply measures scalar-field multiplication.
func BenchmarkScalarMultiply(b *testing.B) {
	lhs := secp256k1.NewScalar().Random()
	rhs := secp256k1.NewScalar().Random()
	result := secp256k1.NewScalar()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		result.Set(lhs)
		result.Multiply(rhs)
	}
}

// BenchmarkScalarInvert measures scalar inversion modulo the group order.
func BenchmarkScalarInvert(b *testing.B) {
	input := secp256k1.NewScalar().Random()
	result := secp256k1.NewScalar()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		result.Set(input)
		result.Invert()
	}
}

// BenchmarkScalarPow measures scalar modular exponentiation.
func BenchmarkScalarPow(b *testing.B) {
	base := secp256k1.NewScalar().Random()
	exp := secp256k1.NewScalar().Random()
	result := secp256k1.NewScalar()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		result.Set(base)
		result.Pow(exp)
	}
}

// BenchmarkScalarLessOrEqual measures scalar ordering across representative operand classes.
func BenchmarkScalarLessOrEqual(b *testing.B) {
	rng := newDeterministicTestRand()
	equal := deterministicReducedScalar(b, rng)
	randomLeft := deterministicReducedScalar(b, rng)
	randomRight := deterministicReducedScalar(b, rng)

	b.Run("equal", func(b *testing.B) {
		benchmarkScalarLessOrEqualPair(b, equal, equal)
	})

	b.Run("adjacent", func(b *testing.B) {
		benchmarkScalarLessOrEqualPair(b, secp256k1.NewScalar().SetUInt64(1), secp256k1.NewScalar().SetUInt64(2))
	})

	b.Run("far", func(b *testing.B) {
		benchmarkScalarLessOrEqualPair(b, secp256k1.NewScalar().Zero(), secp256k1.NewScalar().MinusOne())
	})

	b.Run("random", func(b *testing.B) {
		benchmarkScalarLessOrEqualPair(b, randomLeft, randomRight)
	})
}

// BenchmarkHashToScalar measures hash-to-scalar expansion and reduction.
func BenchmarkHashToScalar(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	var s *secp256k1.Scalar

	for range b.N {
		var err error
		s, err = secp256k1.HashToScalar(benchmarkHashInput, benchmarkHashDST)
		if err != nil {
			b.Fatal(err)
		}

		_ = s
	}
}

// BenchmarkHashToGroup measures random-oracle hash-to-curve.
func BenchmarkHashToGroup(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		if _, err := secp256k1.HashToGroup(benchmarkHashInput, benchmarkHashDST); err != nil {
			b.Fatal(err)
		}
	}
}
