// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"crypto"
	"encoding/binary"
	"errors"
	"hash"
	"math"
	"slices"
)

const (
	dstMaxLength         = 255
	dstLongPrefix        = "H2C-OVERSIZE-DST-"
	minLength            = 0
	recommendedMinLength = 16
)

var (
	errLengthTooLarge = errors.New("requested byte length is too high")
	errZeroLenDST     = errors.New("zero-length DST")
)

func checkDST(dst []byte) {
	if len(dst) < recommendedMinLength {
		if len(dst) == minLength {
			panic(errZeroLenDST)
		}
	} // We could panic here as well, but let's not enforce the recommended minimum length, yet.
}

func i2osp1(value uint) []byte {
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], uint16(value))

	return out[1:2]
}

func i2osp2(value uint) []byte {
	var out [2]byte
	binary.BigEndian.PutUint16(out[:], uint16(value))

	return out[:]
}

// expandXMD implements expand_message_xmd as specified in RFC 9380 section 5.3.1.
func expandXMD(input, dst []byte, length uint) []byte {
	checkDST(dst)

	h := crypto.SHA256.New()
	dst = vetDSTXMD(h, dst)

	ell := math.Ceil(float64(length) / float64(crypto.SHA256.Size()))
	if ell > 255 || length > math.MaxUint16 {
		panic(errLengthTooLarge)
	}

	var zPad [64]byte // 64 is SHA256's block size
	lib := i2osp2(length)

	// Hash to b0
	b0 := hashAll(h, zPad[:], input, lib, []byte{0}, dst)

	// Hash to b1
	b1 := hashAll(h, b0, []byte{1}, dst)

	// ell < 2 means the hash function's output length is sufficient
	if ell < 2 {
		return b1[0:length]
	}

	// Only if we need to expand the hash output, we keep on hashing
	return xmd(h, b0, b1, dst, uint(ell), length)
}

// xmd expands the message digest until it reaches the desirable length.
func xmd(h hash.Hash, b0, b1, dstPrime []byte, ell, length uint) []byte {
	uniformBytes := make([]byte, 0, length)
	uniformBytes = append(uniformBytes, b1...)
	bi := make([]byte, len(b1))
	copy(bi, b1)

	for i := uint(2); i <= ell; i++ {
		xor := xorSlices(bi, b0)
		bi = hashAll(h, xor, []byte{byte(i)}, dstPrime)
		uniformBytes = append(uniformBytes, bi...)
	}

	return uniformBytes[0:length]
}

// xorSlices xors the two byte slices byte by byte into bi, and returns bi.
// Both slices must be of same length.
func xorSlices(bi, b0 []byte) []byte {
	for i := range bi {
		bi[i] ^= b0[i]
	}

	return bi
}

// vetDSTXMD computes a shorter tag for dst if the tag length exceeds 255 bytes. Since we use SHA256, the hash output is
// 32 bytes and so does not exceed the maximum output length of 255. In any case, dst is returned length suffixed.
func vetDSTXMD(h hash.Hash, dst []byte) []byte {
	// If the tag length exceeds 255 bytes, compute a shorter tag by hashing it
	if len(dst) > dstMaxLength {
		dst = hashAll(h, []byte(dstLongPrefix), dst)
	}

	// DST prime = length suffixed DST
	dst = slices.Grow(dst, 1)

	return append(dst, i2osp1(uint(len(dst)))[0])
}

func hashAll(h hash.Hash, input ...[]byte) []byte {
	h.Reset()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	return h.Sum(nil)
}
