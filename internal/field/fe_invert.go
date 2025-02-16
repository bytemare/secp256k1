// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html
//
// Code generated by addchain. DO NOT EDIT.

package field

// Invert computes z = 1/x (mod p) and returns it, by computing z = x^(p-2) mod p.
// For some reason, addchain outputs something different than from the examples, using the receiver in the computation,
// which doesn't work if the receiver and the argument point to the same element. Dereferencing and thus using a local
// copy of the original does the trick.
func (z *Element) Invert(x Element) *Element {
	// Inversion computation is derived from the addition chain:
	//
	//	_10     = 2*1
	//	_100    = 2*_10
	//	_101    = 1 + _100
	//	_111    = _10 + _101
	//	_1110   = 2*_111
	//	_111000 = _1110 << 2
	//	_111111 = _111 + _111000
	//	i13     = _111111 << 4 + _1110
	//	x12     = i13 << 2 + _111
	//	x22     = x12 << 10 + i13 + 1
	//	i29     = 2*x22
	//	i31     = i29 << 2
	//	i54     = i31 << 22 + i31
	//	i122    = (i54 << 20 + i29) << 46 + i54
	//	x223    = i122 << 110 + i122 + _111
	//	i269    = ((x223 << 23 + x22) << 7 + _101) << 3
	//	return    _101 + i269
	//
	// Operations: 255 squares 15 multiplies
	//
	// Generated by github.com/mmcloughlin/addchain v0.4.0.

	// Allocate Temporaries.
	var (
		t0 = New()
		t1 = New()
		t2 = New()
		t3 = New()
		t4 = New()
	)

	// Step 1: t0 = x^0x2
	t0.Square(&x)

	// Step 2: z = x^0x4
	z.Square(t0)

	// Step 3: z = x^0x5
	z.Multiply(&x, z)

	// Step 4: t1 = x^0x7
	t1.Multiply(t0, z)

	// Step 5: t0 = x^0xe
	t0.Square(t1)

	// Step 7: t2 = x^0x38
	t2.Square(t0)
	for s := 1; s < 2; s++ {
		t2.Square(t2)
	}

	// Step 8: t2 = x^0x3f
	t2.Multiply(t1, t2)

	// Step 12: t2 = x^0x3f0
	for s := 0; s < 4; s++ {
		t2.Square(t2)
	}

	// Step 13: t0 = x^0x3fe
	t0.Multiply(t0, t2)

	// Step 15: t2 = x^0xff8
	t2.Square(t0)
	for s := 1; s < 2; s++ {
		t2.Square(t2)
	}

	// Step 16: t2 = x^0xfff
	t2.Multiply(t1, t2)

	// Step 26: t2 = x^0x3ffc00
	for s := 0; s < 10; s++ {
		t2.Square(t2)
	}

	// Step 27: t0 = x^0x3ffffe
	t0.Multiply(t0, t2)

	// Step 28: t0 = x^0x3fffff
	t0.Multiply(&x, t0)

	// Step 29: t3 = x^0x7ffffe
	t3.Square(t0)

	// Step 31: t2 = x^0x1fffff8
	t2.Square(t3)
	for s := 1; s < 2; s++ {
		t2.Square(t2)
	}

	// Step 53: t4 = x^0x7ffffe000000
	t4.Square(t2)
	for s := 1; s < 22; s++ {
		t4.Square(t4)
	}

	// Step 54: t2 = x^0x7ffffffffff8
	t2.Multiply(t2, t4)

	// Step 74: t4 = x^0x7ffffffffff800000
	t4.Square(t2)
	for s := 1; s < 20; s++ {
		t4.Square(t4)
	}

	// Step 75: t3 = x^0x7fffffffffffffffe
	t3.Multiply(t3, t4)

	// Step 121: t3 = x^0x1ffffffffffffffff800000000000
	for s := 0; s < 46; s++ {
		t3.Square(t3)
	}

	// Step 122: t2 = x^0x1fffffffffffffffffffffffffff8
	t2.Multiply(t2, t3)

	// Step 232: t3 = x^0x7ffffffffffffffffffffffffffe0000000000000000000000000000
	t3.Square(t2)
	for s := 1; s < 110; s++ {
		t3.Square(t3)
	}

	// Step 233: t2 = x^0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffff8
	t2.Multiply(t2, t3)

	// Step 234: t1 = x^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffff
	t1.Multiply(t1, t2)

	// Step 257: t1 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff800000
	for s := 0; s < 23; s++ {
		t1.Square(t1)
	}

	// Step 258: t0 = x^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff
	t0.Multiply(t0, t1)

	// Step 265: t0 = x^0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffff80
	for s := 0; s < 7; s++ {
		t0.Square(t0)
	}

	// Step 266: t0 = x^0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffff85
	t0.Multiply(z, t0)

	// Step 269: t0 = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc28
	for s := 0; s < 3; s++ {
		t0.Square(t0)
	}

	// Step 270: z = x^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d
	z.Multiply(z, t0)

	return z
}
