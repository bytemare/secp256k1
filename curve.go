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
	"math/big"

	"github.com/bytemare/hash2curve"

	"github.com/bytemare/secp256k1/internal/field"
)

const (
	scalarLength  = 32
	elementLength = 33
	secLength     = 48
	hash          = crypto.SHA256
)

var (
	// field order: 2^256 - 2^32 - 977
	// = 115792089237316195423570985008687907853269984665640564039457584007908834671663
	// = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f.
	fieldOrderBytes = []byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47,
	}

	// group order: 2^256 - 432420386565659656852420866394968145599
	// = 115792089237316195423570985008687907852837564279074904382605163141518161494337
	// = xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141.
	groupOrderBytes = []byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254,
		186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
	}

	// scMinusOne = groupOrderBytes - 1.
	scMinusOne = []byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254,
		186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 64,
	}

	// 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798.
	baseXBytes = []byte{
		121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7,
		2, 155, 252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
	}

	// 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8.
	baseYBytes = []byte{
		72, 58, 218, 119, 38, 163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168,
		253, 23, 180, 72, 166, 133, 84, 25, 156, 71, 208, 143, 251, 16, 212, 184,
	}

	// 0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533.
	isoA = []byte{
		63, 135, 49, 171, 221, 102, 26, 220, 160, 138, 85, 88, 240, 245, 210, 114,
		233, 83, 211, 99, 203, 111, 14, 93, 64, 84, 71, 192, 26, 68, 69, 51,
	}

	// 1771.
	isoB = []byte{6, 235}

	fp             = field.NewField(new(big.Int).SetBytes(fieldOrderBytes))
	fn             = field.NewField(new(big.Int).SetBytes(groupOrderBytes))
	b              = big.NewInt(7)
	b3             = big.NewInt(21)
	mapZ           = new(big.Int).Mod(big.NewInt(-11), fp.Order())
	baseX          = new(big.Int).SetBytes(baseXBytes)
	baseY          = new(big.Int).SetBytes(baseYBytes)
	secp256k13ISOA = new(big.Int).SetBytes(isoA)
	secp256k13ISOB = new(big.Int).SetBytes(isoB)
)

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
