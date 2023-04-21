// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group

import (
	"encoding/hex"
	"github.com/bytemare/secp256k1"
	"math/big"
	"testing"
)

const (
	basePoint = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	identity  = "000000000000000000000000000000000000000000000000000000000000000000"
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
	base := hex.EncodeToString(secp256k1.New().Base().Encode())
	if base != basePoint {
		t.Fatal("expected equality")
	}
}

func TestElement_Identity(t *testing.T) {
	id := secp256k1.New().NewElement().Identity()
	enc := hex.EncodeToString(id.Encode())

	if !id.IsIdentity() {
		t.Fatal("expected identity")
	}

	if enc != identity {
		t.Fatal("expected equality")
	}

	b, err := hex.DecodeString(identity)
	if err != nil {
		t.Fatal(err)
	}

	e := secp256k1.New().NewElement()
	if err := e.Decode(b); err == nil || err.Error() != "invalid point encoding" {
		t.Fatalf("expected specific error on decoding identity, got %q", err)
	}
}

func decodeHexElement(t *testing.T, input string) *secp256k1.Element {
	b, err := hex.DecodeString(input)
	if err != nil {
		t.Fatal(err)
	}

	e := secp256k1.New().NewElement()
	if err := e.Decode(b); err != nil {
		t.Fatal(err)
	}

	return e
}

func TestElement_Add(t *testing.T) {
	group := secp256k1.New()
	base := group.Base()
	acc := group.Base()

	for _, mult := range multBase {
		e := decodeHexElement(t, mult)
		if e.Equal(acc) != 1 {
			t.Fatal("expected equality")
		}

		acc.Add(base)
	}
}

func TestElement_Double(t *testing.T) {
	group := secp256k1.New()
	acc := group.Base()
	add := group.Base()

	for range multBase {
		add.Add(add)
		acc.Double()

		if acc.Equal(add) != 1 {
			t.Fatal("expected equality")
		}
	}
}

func TestElement_Mult(t *testing.T) {
	group := secp256k1.New()
	s := group.NewScalar()
	base := group.Base()

	for i, mult := range multBase {
		e := decodeHexElement(t, mult)
		if e.Equal(base) != 1 {
			t.Fatalf("expected equality for %d", i)
		}

		if err := s.SetInt(big.NewInt(int64(i + 2))); err != nil {
			t.Fatal(err)
		}

		base.Base().Multiply(s)
	}
}
