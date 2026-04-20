// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

const (
	minLength      = 0
	dstMaxLength   = math.MaxUint8
	xmdMaxDSTPrime = dstMaxLength + 1
	dstLongPrefix  = "H2C-OVERSIZE-DST-"
)

var (
	// ErrZeroLengthDST is returned when a group could not be decoded.
	ErrZeroLengthDST = errors.New("the provided domain separation tag is empty")

	dstLongPrefixBytes = []byte(dstLongPrefix) //nolint:gochecknoglobals // shared XMD constant
)

func checkDST(dst []byte) error {
	if len(dst) == minLength {
		return ErrZeroLengthDST
	}

	return nil
}

// expandXMDTo expands the input and dst using the given fixed length hash function and writes to out.
// It implements expand_message_xmd as specified in RFC 9380 section 5.3.1. and is optimized for SHA-256.
// dst MUST be non-nil, longer than 0 and lower than 256. It's recommended that DST is at least 16 bytes long.
func expandXMDTo(out, input, dst []byte) error {
	if err := checkDST(dst); err != nil {
		return err
	}

	h := sha256.New()
	var shortenedDST [sha256.Size]byte
	if len(dst) > dstMaxLength {
		h.Reset()
		h.Write(dstLongPrefixBytes)
		h.Write(dst)
		h.Sum(shortenedDST[:0])
		dst = shortenedDST[:]
	}

	var dstPrimeArray [xmdMaxDSTPrime]byte
	dstPrimeLen := copy(dstPrimeArray[:], dst)
	dstPrimeArray[dstPrimeLen] = byte(len(dst))
	dstPrime := dstPrimeArray[:dstPrimeLen+1]

	// ell indicates how many hash chunks we need.
	length := len(out)

	ell := (length + sha256.Size - 1) / sha256.Size // equivalent to math.Ceil(float64(length) / float64(sha256Size))
	if ell > math.MaxUint8 || length > math.MaxUint16 {
		return nil
	}

	var lib [2]byte
	var zeroByte [1]byte
	var zPad [sha256.BlockSize]byte
	var b0 [sha256.Size]byte
	var bi [sha256.Size]byte
	var biInput [sha256.Size + 1 + xmdMaxDSTPrime]byte // buffer for hashing.

	binary.BigEndian.PutUint16(lib[:], uint16(length))

	h.Reset()
	h.Write(zPad[:])
	h.Write(input)
	h.Write(lib[:])
	h.Write(zeroByte[:])
	h.Write(dstPrime)
	h.Sum(b0[:0])

	biInputLen := sha256.Size + 1 + len(dstPrime)
	copy(biInput[sha256.Size+1:], dstPrime)
	copy(biInput[:sha256.Size], b0[:])
	biInput[sha256.Size] = 1
	hashToBuffer(bi[:], biInput[:biInputLen])
	offset := copy(out, bi[:sha256.Size])

	// xmd: expand the message digest until it reaches the desirable length.
	for i := 2; i <= ell; i++ {
		for j := 0; j < sha256.Size; j++ {
			biInput[j] = bi[j] ^ b0[j]
		}

		biInput[sha256.Size] = byte(i)
		hashToBuffer(bi[:], biInput[:biInputLen])
		offset += copy(out[offset:], bi[:sha256.Size])
	}

	return nil
}

func hashToBuffer(out, input []byte) {
	sum := sha256.Sum256(input)
	copy(out, sum[:])
}
