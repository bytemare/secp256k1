// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package scalar implements prime-order scalar operations in the SECP256k1 group building on Fiat-Crypto.
package scalar

import (
	"encoding/binary"
	"math/bits"
)

const (
	// SecLength is the security length dictating the input length for HashToFieldElement.
	SecLength = 48

	scalarSize = 32
)

var (
	// One is the scalar 1.
	One = MontgomeryDomainFieldElement{4624529908474429119, 4994812053365940164, uint64(0x1), uint64(0x0)}

	// Order of the group: 2^256 - 432420386565659656852420866394968145599
	// = 115792089237316195423570985008687907852837564279074904382605163141518161494337
	// = xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141.
	Order = MontgomeryDomainFieldElement{
		13822214165235122497,
		13451932020343611451,
		18446744073709551614,
		18446744073709551615,
	}

	// OrderMinus1 is -1 = p-1.
	OrderMinus1 = MontgomeryDomainFieldElement{
		9197684256760693378,
		8457119966977671287,
		18446744073709551613,
		18446744073709551615,
	}

	// 2^192 mod (2^256 - 432420386565659656852420866394968145599) in the Montgomery domain.
	two192 = &MontgomeryDomainFieldElement{
		10328527898029845308,
		10739309058364017386,
		11342065889886772165,
		4624529908474429120,
	}

	// 2^384 mod (2^256 - 432420386565659656852420866394968145599) in the Montgomery domain.
	two384 = &MontgomeryDomainFieldElement{
		2161815027462274937,
		647662477280039658,
		2865435121925625427,
		4330881270917637700,
	}
)

// Invert sets out = 1 / in.
func Invert(out *MontgomeryDomainFieldElement, in MontgomeryDomainFieldElement) {
	s := scalar{out}
	s.Invert(&scalar{s: &in})
}

type scalar struct {
	s *MontgomeryDomainFieldElement
}

func newScalar() *scalar {
	return &scalar{new(MontgomeryDomainFieldElement)}
}

func (s *scalar) Multiply(t, u *scalar) {
	Mul(s.s, t.s, u.s)
}

func (s *scalar) Square(t *scalar) {
	Square(s.s, t.s)
}

/*
// passing a pointer, as 256 bytes is otherwise heavy.
func getMSB(b *[256]uint8) uint {
	for i := 255; i > 0; i-- {
		if b[i] == 1 {
			return uint(i)
		}
	}

	if b[0] == 0 {
		panic("no bit set")
	}

	return 0
}


// Pow is a failed attempt to return a^b. It fails for big numbers.
func Pow(a, b *MontgomeryDomainFieldElement) *MontgomeryDomainFieldElement {
	var s0, s1 MontgomeryDomainFieldElement
	SetOne(&s0)
	copy(s1[:], a[:])

	nonMontgomeryBits := toNonMontgomeryBits(b)
	// msb := getMSB(&nonMontgomeryBits)
	// fmt.Printf("\nMSB is %d\n", msb)
	// fmt.Printf("\nBits %v\n", nonMontgomeryBits)

	for i := 255; i >= 0; i-- {
		if nonMontgomeryBits[i] == 0 {
			Mul(&s1, &s0, &s1)
			Square(&s0, &s0)
		} else {
			Mul(&s0, &s0, &s1)
			Square(&s1, &s1)
		}
	}

	var nm1, nm2 NonMontgomeryDomainFieldElement
	FromMontgomery(&nm1, &s0)
	FromMontgomery(&nm2, &s1)

	// fmt.Println(hex.EncodeToString(NonMontgomeryToBytes(&nm1)))
	// fmt.Println(hex.EncodeToString(NonMontgomeryToBytes(&nm2)))
	// fmt.Println(s0)
	// fmt.Println(s1)

	return &s0
}

func toNonMontgomeryBits(a *MontgomeryDomainFieldElement) [256]uint8 {
	var (
		n   NonMontgomeryDomainFieldElement
		out [256]uint8
	)
	FromMontgomery(&n, a)

	for i := range 255 {
		out[i] = uint8((n[i/64] >> (i % 64)) & 1)
	}

	return out
}
*/

// IsFEZero returns 1 if u == 0, and 0 otherwise.
func IsFEZero(u *MontgomeryDomainFieldElement) uint64 {
	return IsZero(u[0] | u[1] | u[2] | u[3])
}

// Equal returns 1 if u == v, and 0 otherwise. u and v are considered to be reduced.
func Equal(u, v *MontgomeryDomainFieldElement) uint64 {
	res := u[0] ^ v[0]
	res |= u[1] ^ v[1]
	res |= u[2] ^ v[2]
	res |= u[3] ^ v[3]

	return IsZero(res)
}

/*
// Sqrt sets e to the square root of u if a quadratic residue (the square root) exists, in which case it also returns 1.
// In all other cases, `fe = 0`, and 0 is returned.
func (e *scalar) Sqrt(u *scalar) (*scalar, uint64) {
	root, isQR := New().SqrtRatio(u, One)
	e.CMove(isQR, Zero, root)

	return e, isQR
}

*/

// CMove sets out to u if c == 0, and to v otherwise.
func CMove(out *MontgomeryDomainFieldElement, c uint64, u, v *MontgomeryDomainFieldElement) {
	Selectznz((*[4]uint64)(out), uint1(c), (*[4]uint64)(u), (*[4]uint64)(v))
}

// ReduceBytes sets out to a reduction of input.
func ReduceBytes(out *MontgomeryDomainFieldElement, input [scalarSize]byte) uint64 {
	nm := BytesToNonMontgomery(input)
	reduced := Reduce(nm)
	ToMontgomery(out, nm)

	return reduced
}

// FromBytesNoReduce sets out to input, without redcution.
func FromBytesNoReduce(out *MontgomeryDomainFieldElement, input []byte) {
	// pad to 256 bits: input will always be smaller than the modulo, so no reduction needed.
	var pad [scalarSize]byte
	copy(pad[scalarSize-len(input):], input)

	ToMontgomery(out, BytesToNonMontgomery(pad))
}

// HashToFieldElement sets out to a field element from a byte string obtained by ExpandXMD, of length 48. It will always
// be below the order, so no reduction of the input is needed.
// We use Frank Denis' trick, c.f. blog from Filippo: https://words.filippo.io/dispatches/wide-reduction
// i.e. represent the value as a+b*2^192+c*2^384.
func HashToFieldElement(out *MontgomeryDomainFieldElement, input [SecLength]byte) {
	// We're dealing with a non-canonical form, so let's package it as such properly by extending to 64 bytes.
	// 64 - secLength = 16
	in := make([]byte, 16, 64)
	in = append(in, input[:]...)

	var _b, _c MontgomeryDomainFieldElement
	FromBytesNoReduce(out, in[40:])
	FromBytesNoReduce(&_b, in[16:40])
	FromBytesNoReduce(&_c, in[:16])

	Mul(&_b, &_b, two192) // b*2^192
	Mul(&_c, &_c, two384) // c*2^384
	Add(out, out, &_b)
	Add(out, out, &_c)
}

// IsZero returns 1 if i == 0, and 0 otherwise.
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
	xMinP[0], borrow = bits.Sub64(x[0], Order[0], borrow)
	xMinP[1], borrow = bits.Sub64(x[1], Order[1], borrow)
	xMinP[2], borrow = bits.Sub64(x[2], Order[2], borrow)
	xMinP[3], borrow = bits.Sub64(x[3], Order[3], borrow)

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

// BytesToNonMontgomery interprets input as a big-endian encoded integer returns the 64-bit saturated representation.
func BytesToNonMontgomery(input [32]byte) *NonMontgomeryDomainFieldElement {
	fe := new(NonMontgomeryDomainFieldElement)
	fe[3] = binary.BigEndian.Uint64(input[0:8])
	fe[2] = binary.BigEndian.Uint64(input[8:16])
	fe[1] = binary.BigEndian.Uint64(input[16:24])
	fe[0] = binary.BigEndian.Uint64(input[24:32])

	return fe
}

// NonMontgomeryToBytes returns the 32 byte big-endian encoding of the saturated representation of the field element.
func NonMontgomeryToBytes(nm *NonMontgomeryDomainFieldElement) []byte {
	var out [32]byte
	binary.BigEndian.PutUint64(out[0:8], nm[3])
	binary.BigEndian.PutUint64(out[8:16], nm[2])
	binary.BigEndian.PutUint64(out[16:24], nm[1])
	binary.BigEndian.PutUint64(out[24:32], nm[0])

	return out[:]
}
