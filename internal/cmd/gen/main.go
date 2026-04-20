package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
)

func run() error {
	for _, spec := range hashSpecs {
		if err := writeHashFile(spec); err != nil {
			return err
		}
	}

	return nil
}

func writeHashFile(spec hashSpec) error {
	var buf bytes.Buffer

	writeHeader(&buf)
	buf.WriteString("package xmd\n\n")
	buf.WriteString("import (\n")

	if _, err := fmt.Fprintf(&buf, "\t%q\n", spec.importPath); err != nil {
		return err
	}

	buf.WriteString("\t\"encoding/binary\"\n")
	buf.WriteString(")\n\n")

	for i, length := range spec.lengths {
		if i > 0 {
			buf.WriteString("\n")
		}

		writeFunction(&buf, spec, length)
	}

	if len(spec.lengths) > 0 {
		buf.WriteString("\n")
	}

	if _, err := fmt.Fprintf(&buf, "func hashTo%sBuffer(out, input []byte) {\n", spec.name); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(&buf, "\tsum := %s.%s(input)\n", spec.packageName, spec.sumFunc); err != nil {
		return err
	}

	buf.WriteString("\tcopy(out, sum[:])\n")
	buf.WriteString("}\n")

	return writeFormatted(spec.file, buf.Bytes())
}

func writeFunction(buf *bytes.Buffer, spec hashSpec, length int) {
	name := fmt.Sprintf("ExpandXMDTo%sLen%d", spec.name, length)
	digestSize := spec.digestSize
	ell := (length + digestSize - 1) / digestSize

	if _, err := fmt.Fprintf(buf, "// %s expands input and dst to exactly %d bytes using %s.\n", name, length, spec.label); err != nil {
		panic(err)
	}

	if _, err := fmt.Fprintf(buf, "func %s(out *[%d]byte, input, dst []byte) error {\n", name, length); err != nil {
		panic(err)
	}

	buf.WriteString("\tif err := checkDST(dst); err != nil {\n")
	buf.WriteString("\t\treturn err\n")
	buf.WriteString("\t}\n\n")

	if _, err := fmt.Fprintf(buf, "\th := %s.%s()\n", spec.packageName, spec.newFunc); err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintf(buf, "\tvar shortenedDST [%s]byte\n", spec.sizeExpr); err != nil {
		panic(err)
	}
	buf.WriteString("\tif len(dst) > dstMaxLength {\n")
	buf.WriteString("\t\th.Reset()\n")
	buf.WriteString("\t\t_, _ = h.Write(dstLongPrefixBytes)\n")
	buf.WriteString("\t\t_, _ = h.Write(dst)\n")
	buf.WriteString("\t\th.Sum(shortenedDST[:0])\n")
	buf.WriteString("\t\tdst = shortenedDST[:]\n")
	buf.WriteString("\t}\n\n")

	buf.WriteString("\tvar dstPrimeArray [xmdMaxDSTPrime]byte\n")
	buf.WriteString("\tdstPrimeLen := copy(dstPrimeArray[:], dst)\n")
	buf.WriteString("\tdstPrimeArray[dstPrimeLen] = byte(len(dst))\n")
	buf.WriteString("\tdstPrime := dstPrimeArray[:dstPrimeLen+1]\n\n")

	buf.WriteString("\tvar lib [2]byte\n")
	buf.WriteString("\tvar zeroByte [1]byte\n")
	if _, err := fmt.Fprintf(buf, "\tvar zPad [%s]byte\n", spec.blockSizeExpr); err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintf(buf, "\tvar b0 [%s]byte\n", spec.sizeExpr); err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintf(buf, "\tvar bi [%s]byte\n", spec.sizeExpr); err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintf(buf, "\tvar biInput [%s + 1 + xmdMaxDSTPrime]byte\n\n", spec.sizeExpr); err != nil {
		panic(err)
	}

	if _, err := fmt.Fprintf(buf, "\tbinary.BigEndian.PutUint16(lib[:], uint16(%d))\n\n", length); err != nil {
		panic(err)
	}

	buf.WriteString("\th.Reset()\n")
	buf.WriteString("\t_, _ = h.Write(zPad[:])\n")
	buf.WriteString("\t_, _ = h.Write(input)\n")
	buf.WriteString("\t_, _ = h.Write(lib[:])\n")
	buf.WriteString("\t_, _ = h.Write(zeroByte[:])\n")
	buf.WriteString("\t_, _ = h.Write(dstPrime)\n")
	buf.WriteString("\th.Sum(b0[:0])\n\n")

	if _, err := fmt.Fprintf(buf, "\tbiInputLen := %s + 1 + len(dstPrime)\n", spec.sizeExpr); err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintf(buf, "\tcopy(biInput[%s+1:], dstPrime)\n", spec.sizeExpr); err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintf(buf, "\tcopy(biInput[:%s], b0[:])\n", spec.sizeExpr); err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintf(buf, "\tbiInput[%s] = 1\n", spec.sizeExpr); err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintf(buf, "\thashTo%sBuffer(bi[:], biInput[:biInputLen])\n", spec.name); err != nil {
		panic(err)
	}
	writeCopy(buf, 0, minimum(digestSize, length), length)

	for round := 2; round <= ell; round++ {
		buf.WriteString("\n")
		if _, err := fmt.Fprintf(buf, "\tfor j := 0; j < %s; j++ {\n", spec.sizeExpr); err != nil {
			panic(err)
		}

		buf.WriteString("\t\tbiInput[j] = bi[j] ^ b0[j]\n")
		buf.WriteString("\t}\n")
		if _, err := fmt.Fprintf(buf, "\tbiInput[%s] = %d\n", spec.sizeExpr, round); err != nil {
			panic(err)
		}

		if _, err := fmt.Fprintf(buf, "\thashTo%sBuffer(bi[:], biInput[:biInputLen])\n", spec.name); err != nil {
			panic(err)
		}

		offset := (round - 1) * digestSize
		chunk := minimum(digestSize, length-offset)
		writeCopy(buf, offset, chunk, length)
	}

	buf.WriteString("\n\treturn nil\n")
	buf.WriteString("}\n")
}

func writeCopy(buf *bytes.Buffer, offset, length, total int) {
	switch {
	case offset == 0 && length == total:
		buf.WriteString("\tcopy((*out)[:], bi[:])\n")
	case length == 0:
		return
	case length == total-offset:
		if _, err := fmt.Fprintf(buf, "\tcopy((*out)[%d:], bi[:%d])\n", offset, length); err != nil {
			panic(err)
		}
	default:
		if _, err := fmt.Fprintf(buf, "\tcopy((*out)[%d:%d], bi[:%d])\n", offset, offset+length, length); err != nil {
			panic(err)
		}
	}
}

func writeHeader(buf *bytes.Buffer) {
	buf.WriteString("// Code generated by go generate ./internal/xmd; DO NOT EDIT.\n")
	buf.WriteString("// SPDX-License-Identifier: MIT\n")
	buf.WriteString("//\n")
	buf.WriteString("// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.\n")
	buf.WriteString("//\n")
	buf.WriteString("// This source code is licensed under the MIT license found in the\n")
	buf.WriteString("// LICENSE file in the root directory of this source tree or at\n")
	buf.WriteString("// https://spdx.org/licenses/MIT.html\n")
	buf.WriteString("\n")
}

func writeFormatted(path string, src []byte) error {
	formatted, err := format.Source(src)
	if err != nil {
		return fmt.Errorf("format %s: %w", path, err)
	}

	return os.WriteFile(path, formatted, 0o644)
}

func minimum(a, b int) int {
	if a < b {
		return a
	}

	return b
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
