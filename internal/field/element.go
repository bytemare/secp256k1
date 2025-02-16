// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package field implements the base field for elements on the curve SECP256k1 building on Fiat-Crypto.
package field

import (
	"math/bits"
)

const (
	// SecLength is the security length dictating the input length for HashToFieldElement.
	SecLength = 48
)

var (
	// One is the element 1.
	One = New().One()

	// Zero is the element 0.
	Zero = &Element{}

	// c2 = sqrt(-z), z == 11.
	c2 = &Element{
		MontgomeryDomainFieldElement{
			10660218062043021626,
			12685808213265501903,
			5194980534593283555,
			4353995932822220413,
		},
	}

	// field order: 2^256 - 2^32 - 977.
	// = 115792089237316195423570985008687907853269984665640564039457584007908834671663.
	// = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f.
	order = MontgomeryDomainFieldElement{0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}
)

// An Element on the field.
type Element struct {
	E MontgomeryDomainFieldElement
}

// New returns a new, unset Element.
func New() *Element {
	return &Element{}
}

// One sets the receiver to 1.
func (e *Element) One() *Element {
	SetOne(&e.E)
	return e
}

// Add sets e = u + v.
func (e *Element) Add(u, v *Element) *Element {
	Add(&e.E, &u.E, &v.E)
	return e
}

// Subtract sets e = u - v.
func (e *Element) Subtract(u, v *Element) *Element {
	Sub(&e.E, &u.E, &v.E)
	return e
}

// Multiply sets e = u * v.
func (e *Element) Multiply(u, v *Element) *Element {
	Mul(&e.E, &u.E, &v.E)
	return e
}

// Negate sets e = -u.
func (e *Element) Negate(u *Element) *Element {
	Opp(&e.E, &u.E)
	return e
}

// Square sets e = u^2.
func (e *Element) Square(u *Element) *Element {
	Square(&e.E, &u.E)
	return e
}

// SqrtRatio sets e to the square root of (u/v) if a quadratic residue (the square root) exists, in which case it also
// returns 1. In all other cases
// and returns 1 if there's a quadratic residue (i.e. if a square root
// actually exists), and 0 otherwise.
// This uses an optimized implementation sqrt_ratio_3mod4 RFC 9380 section F.2.1.2.
func (e *Element) SqrtRatio(u, v *Element) (*Element, uint64) {
	tv1 := New().Square(v)        // 1. tv1 = v^2
	tv2 := New().Multiply(u, v)   // 2. tv2 = u * v
	tv1.Multiply(tv1, tv2)        // 3. tv1 = tv1 * tv2
	y1 := New().expPMin3Div4(tv1) // 4. y1 = tv1^c1; c1 = (q - 3) / 4, q = p^m = 3 mod 4.
	y1.Multiply(y1, tv2)          // 5. y1 = y1 * tv2
	y2 := New().Multiply(y1, c2)  // 6. y2 = y1 * c2
	tv3 := New().Square(y1)       // 7. tv3 = y1^2
	tv3.Multiply(tv3, v)          // 8. tv3 = tv3 * v
	isQR := tv3.Equals(u)         // 9. isQR = tv3 == u
	e.CMove(isQR, y2, y1)         // 10. y = CMOV(y2, y1, isQR)

	return e, isQR // 11. return (isQR, y)
}

/*
// Sqrt sets e to the square root of u if a quadratic residue (the square root) exists, in which case it also returns 1.
// In all other cases, `fe = 0`, and 0 is returned.
func (e *Element) Sqrt(u *Element) (*Element, uint64) {
	root, isQR := New().SqrtRatio(u, One)
	e.CMove(isQR, Zero, root)

	return e, isQR
}

*/

// Sgn0 returns the parity of e, 0 if e is even, and 1 otherwise.
func (e *Element) Sgn0() uint64 {
	var n NonMontgomeryDomainFieldElement
	FromMontgomery(&n, &e.E)

	return IsNonZero(n[0] & 1)
}

// CMove sets e to u if c == 0, and to v otherwise.
func (e *Element) CMove(c uint64, u, v *Element) *Element {
	Selectznz((*[4]uint64)(&e.E), uint1(c), (*[4]uint64)(&u.E), (*[4]uint64)(&v.E))
	return e
}

// IsZero returns 1 if e == 0, and 0 otherwise.
func (e *Element) IsZero() uint64 {
	var nonZero uint64
	Nonzero(&nonZero, (*[4]uint64)(&e.E))

	return IsZero(nonZero)
}

// Set sets e to u.
func (e *Element) Set(u *Element) *Element {
	copy(e.E[:], u.E[:])
	return e
}

// Bytes returns the byte representation of e.
func (e *Element) Bytes() []byte {
	var nm NonMontgomeryDomainFieldElement
	FromMontgomery(&nm, &e.E)

	return nonMontgomeryToBytes(&nm)
}

// Equals returns 1 if e == u, and 0 otherwise. e and u are considered to be reduced.
func (e *Element) Equals(u *Element) uint64 {
	res := e.E[0] ^ u.E[0]
	res |= e.E[1] ^ u.E[1]
	res |= e.E[2] ^ u.E[2]
	res |= e.E[3] ^ u.E[3]

	return IsZero(res)
}

// FromBytesWithReduce sets e to a reduction of u (if necessary), or u otherwise, and return e and whether a reduction
// was necessary (in which case 0, and 1 otherwise).
func (e *Element) FromBytesWithReduce(input [ElementSize]byte) (*Element, uint64) {
	nm := bytesToNonMontgomery(input)
	reduced := Reduce(nm)
	ToMontgomery(&e.E, nm)

	return e, reduced
}

// FromBytesNoReduce set e to input.
func (e *Element) FromBytesNoReduce(input []byte) *Element {
	// pad to 256 bits: input will always be smaller than the modulo, so no reduction needed.
	var pad [ElementSize]byte
	copy(pad[ElementSize-len(input):], input)

	ToMontgomery(&e.E, bytesToNonMontgomery(pad))

	return e
}

var (
	// 2^192 mod (2^256 - 2^32 - 977) in the Montgomery domain.
	two192 = &MontgomeryDomainFieldElement{0, 0, 0, 4294968273}

	// 2^384 mod (2^256 - 2^32 - 977) in the Montgomery domain.
	two384 = &MontgomeryDomainFieldElement{0, 0, 8392367050913, 1}
)

// HashToFieldElement sets e to a field element from a 48-byte string obtained by ExpandXMD.
// We use Frank Denis' trick, c.f. blog from Filippo: https://words.filippo.io/dispatches/wide-reduction
// i.e. represent the value as a+b*2^192+c*2^384.
func (e *Element) HashToFieldElement(input [SecLength]byte) *Element {
	// We're dealing with a non-canonical form, so let's package it properly by extending to 64 bytes.
	// 64 - secLength = 26
	// var in [64]byte
	// copy(in[64-len(input):], input[:])
	in := make([]byte, 16, 64)
	in = append(in, input[:]...)

	e.FromBytesNoReduce(in[40:])
	_b := New().FromBytesNoReduce(in[16:40])
	_c := New().FromBytesNoReduce(in[:16])

	Mul(&_b.E, &_b.E, two192) // b*2^192
	Mul(&_c.E, &_c.E, two384) // c*2^384
	Add(&e.E, &e.E, &_b.E)
	Add(&e.E, &e.E, &_c.E)

	return e
}

// IsEqual returns 1 if u == v, and 0 otherwise.
func IsEqual(u, v uint64) uint64 {
	return IsZero(u ^ v)
}

// IsZero returns 1 if i == 0, and otherwise.
func IsZero(u uint64) uint64 {
	return (^IsNonZero(u)) & 1
}

// IsNonZero returns 1 if u != 0, and 0 otherwise.
func IsNonZero(u uint64) uint64 {
	// Simplified bits.Sub64().
	return ((^uint64(0) & u) | (^(0 ^ u) & -u)) >> 63
}

// Reduce will set x to x mod p, and return 0 if a reduction was necessary and 1 otherwise.
func Reduce(x *NonMontgomeryDomainFieldElement) uint64 {
	// Thanks to the high prime, the input will always be < 2p, so to Reduce we can simply do 'x = x - p'.
	var (
		borrow uint64
		xMinP  [4]uint64
	)
	xMinP[0], borrow = bits.Sub64(x[0], order[0], borrow)
	xMinP[1], borrow = bits.Sub64(x[1], order[1], borrow)
	xMinP[2], borrow = bits.Sub64(x[2], order[2], borrow)
	xMinP[3], borrow = bits.Sub64(x[3], order[3], borrow)

	// If borrow == 0, x >= order, reduction needed
	//	- mask is all zeros: select x - p
	// If borrow == 1, x < order, no reduction needed
	// 	- mask is all ones: select x
	mask := -borrow
	x[0] = (xMinP[0] & ^mask) | (x[0] & mask)
	x[1] = (xMinP[1] & ^mask) | (x[1] & mask)
	x[2] = (xMinP[2] & ^mask) | (x[2] & mask)
	x[3] = (xMinP[3] & ^mask) | (x[3] & mask)

	return borrow
}

/*
// CSelect sets out to u if cond is 0, and v otherwise.
func CSelect(out *Element, cond uint64, u, v *Element) {
	cond *= 0xffffffffffffffff
	out.E[0] = (u.E[0] & ^cond) | (v.E[0] & cond)
	out.E[1] = (u.E[1] & ^cond) | (v.E[1] & cond)
	out.E[2] = (u.E[2] & ^cond) | (v.E[2] & cond)
	out.E[3] = (u.E[3] & ^cond) | (v.E[3] & cond)
}

*/
