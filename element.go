// SPDX-License-Identifier: MIT
//
// Copyright (C) 2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in theg
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bytemare/secp256k1/internal/field"
)

const (
	encodingPrefixIdentity     = 0x00
	encodingPrefixEven         = 0x02
	encodingPrefixOdd          = 0x03
	encodingPrefixUncompressed = 0x04
)

// errParamInvalidPointEncoding indicates an invalid point encoding has been provided.
var errParamInvalidPointEncoding = errors.New("invalid point encoding")

// Element implements the Element interface for the secp256k1 group element.
type Element struct {
	_       disallowEqual
	x, y, z field.Element
}

var identity = Element{ //nolint:gochecknoglobals // that's actually ok
	x: *field.New(),
	y: *field.New().One(),
	z: *field.New(), // The Identity element is the only with z == 0
}

// newEmptyElement returns a new but invalid element, that is not the point at infinity.
func newEmptyElement() *Element {
	return &Element{
		x: *field.New(),
		y: *field.New(),
		z: *field.New(),
	}
}

// newElement returns a new element set to the point at infinity.
func newElement() *Element {
	return newEmptyElement().set(&identity)
}

// NewElement returns a new element set to the identity point.
func NewElement() *Element {
	return newElement()
}

// Base sets the element to the group's base point a.k.a. canonical generator.
func (e *Element) Base() *Element {
	// 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798.
	baseX := field.MontgomeryDomainFieldElement{
		15507633332195041431,
		2530505477788034779,
		10925531211367256732,
		11061375339145502536,
	}

	// 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8.
	baseY := field.MontgomeryDomainFieldElement{
		12780836216951778274,
		10231155108014310989,
		8121878653926228278,
		14933801261141951190,
	}

	copy(e.x.E[:], baseX[:])
	copy(e.y.E[:], baseY[:])
	e.z.Set(field.New().One())

	return e
}

// Identity sets the element to the point at infinity of the Group's underlying curve.
func (e *Element) Identity() *Element {
	return e.set(&identity)
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (e *Element) Add(element *Element) *Element {
	return e.add(element)
}

// Double sets the receiver to its double, and returns it.
func (e *Element) Double() *Element {
	return e.doubleProjectiveComplete(e)
}

// Negate sets the receiver to its negation, and returns it.
func (e *Element) Negate() *Element {
	if e.IsIdentity() {
		return e
	}

	return e.negate()
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (e *Element) Subtract(element *Element) *Element {
	if element == nil {
		return e
	}

	q := element.copy().negate()

	return e.add(q)
}

// Multiply sets the receiver to the Scalar multiplication of the receiver with the given Scalar, and returns it.
func (e *Element) Multiply(scalar *Scalar) *Element {
	if scalar == nil {
		return e.Identity()
	}

	if scalar.IsOne() {
		return e
	}

	r0 := newElement()
	r1 := e.copy()
	bits := scalar.Bits()

	for i := 255; i >= 0; i-- {
		if bits[i] == 0 {
			r1.Add(r0)
			r0.Double()
		} else {
			r0.Add(r1)
			r1.Double()
		}
	}

	e.set(r0)

	return e
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element) Equal(element *Element) int {
	return e.isEqual(element)
}

// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
func (e *Element) IsIdentity() bool {
	return e.z.IsZero() != 0
}

// Set sets the receiver to the value of the argument, and returns the receiver.
func (e *Element) Set(element *Element) *Element {
	return e.set(element)
}

// Copy returns a copy of the receiver.
func (e *Element) Copy() *Element {
	return e.copy()
}

// Encode returns the compressed byte encoding of the element.
func (e *Element) Encode() []byte {
	var out [elementLengthCompressed]byte
	isIdentity := e.z.IsZero()
	affine := e.affine()
	ySign := subtle.ConstantTimeSelect(int(affine.y.Sgn0()), encodingPrefixOdd, encodingPrefixEven)
	out[0] = byte(subtle.ConstantTimeSelect(int(isIdentity), encodingPrefixIdentity, ySign))
	subtle.ConstantTimeCopy(int(field.IsZero(isIdentity)), out[1:], affine.x.Bytes())
	del := subtle.ConstantTimeSelect(int(isIdentity), 1, elementLengthCompressed) // if identity, return only two bytes

	return out[:del]
}

// EncodeUncompressed returns the uncompressed byte encoding of the element.
func (e *Element) EncodeUncompressed() []byte {
	var out [elementLengthUncompressed]byte
	return e.fillUncompressed(&out)
}

// XCoordinate returns the encoded x coordinate of the element, which is the same as Encode() without the header.
func (e *Element) XCoordinate() []byte {
	return e.Encode()[1:]
}

// Secp256Polynomial applies y^2=x^3+ax+b (with a = 0) to recover y^2 from x.
func Secp256Polynomial(y, x *field.Element) {
	// b is 7 in Montgomery form.
	b := field.Element{E: field.MontgomeryDomainFieldElement{30064777911, 0, 0, 0}}

	y.Square(x)
	y.Multiply(y, x)
	y.Add(y, &b)
}

// DecodeCoordinates set the receiver to the decoding of the affine coordinates given by x and y, and returns an error
// on failure.
func (e *Element) DecodeCoordinates(x, y [32]byte) error {
	fex, reduced := field.New().FromBytesWithReduce(x)
	if reduced == 0 {
		return errParamInvalidPointEncoding
	}

	fey, reduced := field.New().FromBytesWithReduce(y)
	if reduced == 0 {
		return errParamInvalidPointEncoding
	}

	var y2 field.Element
	Secp256Polynomial(&y2, fex)

	if y2.Equals(field.New().Square(fey)) != 1 {
		return errParamInvalidPointEncoding
	}

	e.x.Set(fex)
	e.y.Set(fey)
	e.z.One()

	return nil
}

// DecodeCompressed sets the receiver to a decoding of the input data in compressed form, and returns an error
// on failure.
func (e *Element) DecodeCompressed(data []byte) error {
	if len(data) != elementLengthCompressed {
		return errParamInvalidPointEncoding
	}

	if data[0] != encodingPrefixEven && data[0] != encodingPrefixOdd {
		return errParamInvalidPointEncoding
	}

	/*
		- check coordinates are in the correct range
		- check point is on the curve / not infinity
		- point order validation is not necessary since the cofactor is 1
	*/

	// Set x in the field, and return an error if it's not reduced.
	x := field.New()
	if _, reduced := x.FromBytesWithReduce([32]byte(data[1:])); reduced == 0 {
		return errParamInvalidPointEncoding
	}

	var y2 field.Element
	Secp256Polynomial(&y2, x)

	y, isSquare := field.New().SqrtRatio(&y2, field.New().One())
	if isSquare != 1 {
		// Point is not on curve
		return errParamInvalidPointEncoding
	}

	cond := y.Sgn0() ^ uint64(data[0]&1)
	e.y.Negate(y)

	e.x.Set(x)
	e.y.CMove(cond, y, &e.y)
	e.z.One()

	return nil
}

// DecodeUncompressed sets the receiver to a decoding of the input data in uncompressed form, and returns an error
// on failure.
func (e *Element) DecodeUncompressed(data []byte) error {
	if len(data) != elementLengthUncompressed {
		return errParamInvalidPointEncoding
	}

	if data[0] != encodingPrefixUncompressed {
		return errParamInvalidPointEncoding
	}

	return e.DecodeCoordinates([32]byte(data[1:33]), [32]byte(data[33:]))
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element) Decode(data []byte) error {
	switch len(data) {
	case elementLengthIdentity:
		if data[0] != encodingPrefixIdentity {
			return errParamInvalidPointEncoding
		}

		e.Identity()

		return nil
	case elementLengthCompressed:
		return e.DecodeCompressed(data)
	case elementLengthUncompressed:
		return e.DecodeUncompressed(data)
	default:
		return errParamInvalidPointEncoding
	}
}

// Hex returns the fixed-sized hexadecimal encoding of e.
func (e *Element) Hex() string {
	return hex.EncodeToString(e.Encode())
}

// DecodeHex sets e to the decoding of the hex encoded element.
func (e *Element) DecodeHex(h string) error {
	encoded, err := hex.DecodeString(h)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return e.Decode(encoded)
}

// MarshalBinary returns the compressed byte encoding of the element.
func (e *Element) MarshalBinary() ([]byte, error) {
	return e.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (e *Element) UnmarshalBinary(data []byte) error {
	return e.Decode(data)
}

func (e *Element) negate() *Element {
	e.y.Negate(&e.y)
	return e
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
//
// We verify whether the scales provided by the Zs represent the same point.
func (e *Element) isEqual(u *Element) int {
	// x
	x1z2 := field.New().Multiply(&e.x, &u.z)
	x2z1 := field.New().Multiply(&u.x, &e.z)

	// y
	y1z2 := field.New().Multiply(&e.y, &u.z)
	y2z1 := field.New().Multiply(&u.y, &e.z)

	return int(x1z2.Equals(x2z1) & y1z2.Equals(y2z1))
}

func (e *Element) copy() *Element {
	return &Element{
		x: *field.New().Set(&e.x),
		y: *field.New().Set(&e.y),
		z: *field.New().Set(&e.z),
	}
}

func (e *Element) set(element *Element) *Element {
	e.x.Set(&element.x)
	e.y.Set(&element.y)
	e.z.Set(&element.z)

	return e
}

// using this outlining saves an allocation...
func (e *Element) fillUncompressed(in *[elementLengthUncompressed]byte) []byte {
	affine := e.affine()
	out := append(in[:0], encodingPrefixUncompressed) //nolint:gocritic
	out = append(out, affine.x.Bytes()...)
	out = append(out, affine.y.Bytes()...)

	return out
}

func (e *Element) doubleProjectiveComplete(u *Element) *Element {
	// b3 is 3*b = 3*7 = 21, in the Montgomery form.
	b3 := field.Element{E: field.MontgomeryDomainFieldElement{90194333733, 0, 0, 0}}

	t0 := field.New().Square(&u.y) // t0 := Y ^2
	z3 := field.New().Add(t0, t0)  // Z3 := t0 + t0
	z3.Add(z3, z3)                 // Z3 := Z3 + Z3

	z3.Add(z3, z3)                         // Z3 := Z3 + Z3
	t1 := field.New().Multiply(&u.y, &u.z) // t1 := Y * Z
	t2 := field.New().Square(&u.z)         // t2 := Z ^2

	t2.Multiply(&b3, t2)               // t2 := b3 * t2
	x3 := field.New().Multiply(t2, z3) // X3 := t2 * Z3
	y3 := field.New().Add(t0, t2)      // Y3 := t0 + t2

	z3.Multiply(t1, z3) // Z3 := t1 * Z3
	t1.Add(t2, t2)      // t1 := t2 + t2
	t2.Add(t1, t2)      // t2 := t1 + t2

	t0.Subtract(t0, t2) // t0 := t0 - t2
	y3.Multiply(t0, y3) // Y3 := t0 * Y3
	y3.Add(x3, y3)      // Y3 := X3 + Y3

	t1.Multiply(&u.x, &u.y) // t1 := X * Y
	x3.Multiply(t0, t1)     // X3 := t0 * t1
	x3.Add(x3, x3)          // X3 := X3 + X3

	e.x.Set(x3)
	e.y.Set(y3)
	e.z.Set(z3)

	return e
}

// affine returns the affine (x,y) coordinates from the inner standard projective representation.
func (e *Element) affine() *Element {
	isZero := e.z.IsZero()
	n := newEmptyElement()

	n.z.Invert(e.z) // we can use n's z since we won't use it otherwise
	n.x.Multiply(&n.z, &e.x)
	n.y.Multiply(&n.z, &e.y)
	n.x.CMove(isZero, &n.x, &identity.x)
	n.y.CMove(isZero, &n.y, &identity.y)

	return n
}

// addAffine3Iso sets e = v + e and returns p, using affine coordinates on secp256k1 3-ISO, useful to optimize the point
// addition in map-to-curve. We use the generic add because the others are tailored for a = 0 and b = 7.
// Setting e = v + e allows small optimisations using fewer variables and fewer copies.
func (e *Element) addAffine3Iso2(v *Element) *Element {
	t0 := field.New().Subtract(&e.y, &v.y) // (y2-y1)
	l := field.New().Subtract(&e.x, &v.x)  // (x2-x1)
	l.Invert(*l)                           // 1/(x2-x1)
	l.Multiply(t0, l)                      // l = (y2-y1)/(x2-x1)

	t0.Square(l)           // l^2
	t0.Subtract(t0, &v.x)  // l^2-x1
	e.x.Subtract(t0, &e.x) // x3 = l^2-x1-x2

	t0.Subtract(&v.x, &e.x) // x1-x3
	t0.Multiply(t0, l)      // l(x1-x3)
	e.y.Subtract(t0, &v.y)  // y3 = l(x1-x3)-y1

	// No need to set Z to 1 here because it won't be used before being set in IsogenySecp256k13iso anyway.

	return e
}

// addProjectiveComplete implements algorithm 7 from "Complete addition formulas for prime order elliptic curve"
// by Joost Renes, Craig Costello, and Lejla Batina (https://eprint.iacr.org/2015/1060.pdf), for a cost of 12M+2m3b+19a.
func (e *Element) addProjectiveComplete(u, v *Element) *Element {
	// b3 is 3*b = 3*7 = 21, in the Montgomery form.
	b3 := field.Element{E: field.MontgomeryDomainFieldElement{90194333733, 0, 0, 0}}

	t0 := field.New().Multiply(&u.x, &v.x) // t0 := X1 * X2
	t1 := field.New().Multiply(&u.y, &v.y) // t1 := Y1 * Y2
	t2 := field.New().Multiply(&u.z, &v.z) // t2 := Z1 * Z2

	t3 := field.New().Add(&u.x, &u.y) // t3 := X1 + Y1
	t4 := field.New().Add(&v.x, &v.y) // t4 := X2 + Y2
	t3.Multiply(t3, t4)               // t3 := t3 * t4

	t4.Add(t0, t1)      // t4 := t0 + t1
	t3.Subtract(t3, t4) // t3 := t3 - t4
	t4.Add(&u.y, &u.z)  // t4 := Y1 + Z1

	x3 := field.New().Add(&v.y, &v.z) // X3 := Y2 + Z2
	t4.Multiply(t4, x3)               // t4 := t4 * X3
	x3.Add(t1, t2)                    // X3 := t1 + t2

	t4.Subtract(t4, x3)               // t4 := t4 - X3
	x3.Add(&u.x, &u.z)                // X3 := X1 + Z1
	y3 := field.New().Add(&v.x, &v.z) // Y3 := X2 + Z2

	x3.Multiply(x3, y3) // X3 := X3 * Y3
	y3.Add(t0, t2)      // Y3 := t0 + t2
	y3.Subtract(x3, y3) // Y3 := X3 - Y3

	x3.Add(t0, t0)       // X3 := t0 + t0
	t0.Add(x3, t0)       // t0 := X3 + t0
	t2.Multiply(&b3, t2) // t2 := b3 * t2

	z3 := field.New().Add(t1, t2) // Z3 := t1 + t2
	t1.Subtract(t1, t2)           // t1 := t1 - t2
	y3.Multiply(&b3, y3)          // Y3 := b3 * Y3

	x3.Multiply(t4, y3) // X3 := t4 * Y3
	t2.Multiply(t3, t1) // t2 := t3 * t1
	x3.Subtract(t2, x3) // X3 := t2 - X3

	y3.Multiply(y3, t0) // Y3 := Y3 * t0
	t1.Multiply(t1, z3) // t1 := t1 * Z3
	y3.Add(t1, y3)      // Y3 := t1 + Y3

	t0.Multiply(t0, t3) // t0 := t0 * t3
	z3.Multiply(z3, t4) // Z3 := Z3 * t4
	z3.Add(z3, t0)      // Z3 := Z3 + t0

	e.x.Set(x3)
	e.y.Set(y3)
	e.z.Set(z3)

	return e
}

func (e *Element) add(element *Element) *Element {
	if element == nil {
		return e
	}

	return e.addProjectiveComplete(e, element)
}
