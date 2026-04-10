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

const (
	maxDecodeFuzzInput = 128
	maxHashFuzzInput   = 1024
	maxHashFuzzDST     = 512
)

// assertScalarRoundTrip checks that an encoded scalar decodes back to the same value.
func assertScalarRoundTrip(t *testing.T, s *secp256k1.Scalar) {
	t.Helper()

	decoded := secp256k1.NewScalar()
	if err := decoded.Decode(s.Encode()); err != nil {
		t.Fatalf("unexpected scalar decode error: %v", err)
	}

	if decoded.Equal(s) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

// assertElementRoundTrip checks that an encoded element decodes back to the same value.
func assertElementRoundTrip(t *testing.T, e *secp256k1.Element) {
	t.Helper()

	decoded := secp256k1.NewElement()
	if err := decoded.Decode(e.Encode()); err != nil {
		t.Fatalf("unexpected element decode error: %v", err)
	}

	if decoded.Equal(e) != 1 {
		t.Fatal(errExpectedEquality)
	}
}

// FuzzElementDecode exercises the generic element decoder over arbitrary inputs.
func FuzzElementDecode(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add(secp256k1.Base().Encode())
	f.Add(secp256k1.Base().EncodeUncompressed())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxDecodeFuzzInput {
			t.Skip()
		}

		e := secp256k1.NewElement()
		if err := e.Decode(data); err != nil {
			return
		}

		assertElementRoundTrip(t, e)
	})
}

// FuzzElementDecodeCompressed exercises compressed point decoding over arbitrary inputs.
func FuzzElementDecodeCompressed(f *testing.F) {
	f.Add(secp256k1.Base().Encode())
	f.Add([]byte{0x02})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxDecodeFuzzInput {
			t.Skip()
		}

		e := secp256k1.NewElement()
		if err := e.DecodeCompressed(data); err != nil {
			return
		}

		decoded := secp256k1.NewElement()
		if err := decoded.DecodeCompressed(e.Encode()); err != nil {
			t.Fatalf("unexpected compressed decode error: %v", err)
		}

		if decoded.Equal(e) != 1 {
			t.Fatal(errExpectedEquality)
		}
	})
}

// FuzzElementDecodeUncompressed exercises uncompressed point decoding over arbitrary inputs.
func FuzzElementDecodeUncompressed(f *testing.F) {
	f.Add(secp256k1.Base().EncodeUncompressed())
	f.Add([]byte{0x04})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxDecodeFuzzInput {
			t.Skip()
		}

		e := secp256k1.NewElement()
		if err := e.DecodeUncompressed(data); err != nil {
			return
		}

		decoded := secp256k1.NewElement()
		if err := decoded.DecodeUncompressed(e.EncodeUncompressed()); err != nil {
			t.Fatalf("unexpected uncompressed decode error: %v", err)
		}

		if decoded.Equal(e) != 1 {
			t.Fatal(errExpectedEquality)
		}
	})
}

func addHashToXCorpus(f *testing.F) {
	f.Helper()
	f.Add([]byte("input data"), []byte("domain separation tag"))
	f.Add([]byte("message"), []byte("H2C"))
}

// FuzzHashToScalar exercises hash-to-scalar over arbitrary inputs and valid non-empty DSTs.
func FuzzHashToScalar(f *testing.F) {
	addHashToXCorpus(f)

	f.Fuzz(func(t *testing.T, input, dst []byte) {
		if len(input) > maxHashFuzzInput || len(dst) == 0 || len(dst) > maxHashFuzzDST {
			return
		}

		assertScalarRoundTrip(t, secp256k1.HashToScalar(input, dst))
	})
}

// FuzzHashToGroup exercises random-oracle hash-to-curve over arbitrary inputs and valid non-empty DSTs.
func FuzzHashToGroup(f *testing.F) {
	addHashToXCorpus(f)

	f.Fuzz(func(t *testing.T, input, dst []byte) {
		if len(input) > maxHashFuzzInput || len(dst) == 0 || len(dst) > maxHashFuzzDST {
			return
		}

		assertElementRoundTrip(t, secp256k1.HashToGroup(input, dst))
	})
}

// FuzzEncodeToGroup exercises non-uniform encode-to-curve over arbitrary inputs and valid non-empty DSTs.
func FuzzEncodeToGroup(f *testing.F) {
	addHashToXCorpus(f)

	f.Fuzz(func(t *testing.T, input, dst []byte) {
		if len(input) > maxHashFuzzInput || len(dst) == 0 || len(dst) > maxHashFuzzDST {
			return
		}

		assertElementRoundTrip(t, secp256k1.EncodeToGroup(input, dst))
	})
}
