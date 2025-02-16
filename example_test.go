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
	"fmt"

	"github.com/bytemare/secp256k1"
)

// Example_ScalarMult shows how to do a scalar multiplication.
func Example_scalarMult() {
	// Get an element. Here, we're taking the group generator.
	g := secp256k1.Base()

	// Get a scalar, e.g. a random one.
	s := secp256k1.NewScalar().Random()

	// Multiply. Boom.
	g.Multiply(s)

	// Output:
}

// ExampleElement_Decode shows how to decode data into elements.
func ExampleElement_Decode() {
	// Let's say we have this element.
	g := secp256k1.Base()

	// Let's have a look at it.
	fmt.Println(g.Hex())

	// Which yields the following:
	out := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

	// Let's get its byte representation.
	b, _ := hex.DecodeString(out)

	// And decode it into another element.
	e := secp256k1.NewElement()
	if err := e.Decode(b); err != nil {
		fmt.Println(err.Error())
	}

	// Let's check for completeness.
	if e.Equal(g) != 1 {
		fmt.Println("something went wrong")
	}

	// Output: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
}
