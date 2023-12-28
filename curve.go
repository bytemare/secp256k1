// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"crypto"
	"fmt"
	"math/big"

	"github.com/bytemare/hash2curve"

	"github.com/bytemare/secp256k1/internal/field"
)

const (
	scalarLength  = 32
	elementLength = 33
	secLength     = 48
	hash          = crypto.SHA256
	fieldOrder    = "115792089237316195423570985008687907853269984665640564039457584007908834671663"
	groupOrder    = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
)

var (
	fp             = field.NewField(setString(fieldOrder, 10))
	fn             = field.NewField(setString(groupOrder, 0))
	b              = big.NewInt(7)
	b3             = big.NewInt(21)
	mapZ           = new(big.Int).Mod(big.NewInt(-11), fp.Order())
	baseX          = setString("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 0)
	baseY          = setString("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 0)
	secp256k13ISOA = setString("0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533", 0)
	secp256k13ISOB = setString("1771", 0)
)

func init() {
	if fn.IsEqual(&fp) {
		panic("scalar field order and group order are the same")
	}
}

func setString(s string, base int) *big.Int {
	i := new(big.Int)
	if _, ok := i.SetString(s, base); !ok {
		panic(fmt.Sprintf("setting int in base %d failed: %v", base, s))
	}

	return i
}

func hashToScalar(input, dst []byte) *Scalar {
	s := hash2curve.HashToFieldXMD(hash, input, dst, 1, 1, secLength, fn.Order())[0]

	// If necessary, build a buffer of right size, so it gets correctly interpreted.
	bytes := s.Bytes()

	length := scalarLength
	if l := length - len(bytes); l > 0 {
		buf := make([]byte, l, length)
		buf = append(buf, bytes...)
		bytes = buf
	}

	res := newScalar()
	res.scalar.SetBytes(bytes)

	return res
}

func map2IsoCurve(fe *big.Int) *Element {
	x, y := hash2curve.MapToCurveSSWU(secp256k13ISOA, secp256k13ISOB, mapZ, fe, fp.Order())
	return newElementWithAffine(x, y)
}

func isogeny3iso(e *Element) *Element {
	x, y, isIdentity := hash2curve.IsogenySecp256k13iso(&e.x, &e.y)

	if isIdentity {
		return newElement()
	}

	// We can save cofactor clearing because it is 1.
	return newElementWithAffine(x, y)
}

func hashToCurve(input, dst []byte) *Element {
	u := hash2curve.HashToFieldXMD(hash, input, dst, 2, 1, secLength, fp.Order())
	q0 := map2IsoCurve(u[0])
	q1 := map2IsoCurve(u[1])
	q0.addAffine(q1) // we use a generic affine add here because the others are tailored for a = 0 and b = 7.

	return isogeny3iso(q0)
}

func encodeToCurve(input, dst []byte) *Element {
	u := hash2curve.HashToFieldXMD(hash, input, dst, 1, 1, secLength, fp.Order())
	q0 := map2IsoCurve(u[0])

	return isogeny3iso(q0)
}
