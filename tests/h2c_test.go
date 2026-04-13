// SPDX-License-Group: MIT
//
// Copyright (C) 2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1_test

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytemare/secp256k1"
)

const (
	hashToCurveVectorsFileLocation = "h2c"
	suiteNuName                    = "secp256k1_XMD:SHA-256_SSWU_NU_"
	suiteRoName                    = "secp256k1_XMD:SHA-256_SSWU_RO_"
)

type h2cVectors struct {
	Ciphersuite string      `json:"ciphersuite"`
	Dst         string      `json:"dst"`
	Vectors     []h2cVector `json:"vectors"`
}

type h2cVector struct {
	*h2cVectors
	P struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"P"`
	Q0 struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"Q0"`
	Q1 struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"Q1"`
	Msg string   `json:"msg"`
	U   []string `json:"u"`
}

func vectorToPoint(t *testing.T, x, y string) *secp256k1.Element {
	yb, _ := hex.DecodeString(y[2:])
	xb, _ := hex.DecodeString(x[2:])

	e := secp256k1.NewElement()
	if err := e.DecodeCoordinates([32]byte(xb), [32]byte(yb)); err != nil {
		t.Fatal(err)
	}

	return e
}

func (v *h2cVector) run(t *testing.T) {
	var expected *secp256k1.Element

	switch v.Ciphersuite {
	case suiteNuName, suiteRoName:
		expected = vectorToPoint(t, v.P.X, v.P.Y)
	default:
		t.Fatal("invalid Group")
	}

	switch v.Ciphersuite[len(v.Ciphersuite)-3:] {
	case "RO_":
		p := secp256k1.HashToGroup([]byte(v.Msg), []byte(v.Dst))

		if p.Equal(expected) != 1 {
			t.Log(v.P)
			t.Logf("v.U: %v", v.U)
			t.Logf("v.Q0: %v", v.Q0)
			t.Logf("v.Q1: %v", v.Q1)
			t.Fatalf("Unexpected HashToGroup output.\n\twant: %q\n\tgot : %q", expected.Hex(), p.Hex())
		}
	case "NU_":
		p := secp256k1.EncodeToGroup([]byte(v.Msg), []byte(v.Dst))

		if p.Equal(expected) != 1 {
			t.Fatalf("Unexpected EncodeToGroup output.\n\twant: %q\n\tgot : %q", expected.Hex(), p.Hex())
		}
	default:
		t.Fatal("ciphersuite not recognized")
	}
}

func (v *h2cVectors) runCiphersuite(t *testing.T) {
	for _, vector := range v.Vectors {
		vector.h2cVectors = v
		t.Run(v.Ciphersuite, vector.run)
	}
}

// TestHashToGroup_Regression verifies representative RO outputs without going through the JSON vector loader.
func TestHashToGroup_Regression(t *testing.T) {
	const dst = "QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_"

	tests := []struct {
		name string
		msg  string
		want string
	}{
		{
			name: "empty message",
			msg:  "",
			want: "03c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346",
		},
		{
			name: "short ascii",
			msg:  "abc",
			want: "023377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b",
		},
		{
			name: "hex-like ascii",
			msg:  "abcdef0123456789",
			want: "02bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := secp256k1.HashToGroup([]byte(test.msg), []byte(dst))
			if got.Hex() != test.want {
				t.Fatalf("unexpected HashToGroup output.\n\twant: %q\n\tgot : %q", test.want, got.Hex())
			}
		})
	}
}

// TestHashToGroupVectors verifies HashToGroup and EncodeToGroup against the bundled vectors.
func TestHashToGroupVectors(t *testing.T) {
	if err := filepath.Walk(hashToCurveVectorsFileLocation,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}
			file, errOpen := os.Open(path)
			if errOpen != nil {
				t.Fatal(errOpen)
			}

			defer func(file *os.File) {
				err := file.Close()
				if err != nil {
					t.Logf("error closing file: %v", err)
				}
			}(file)

			val, errRead := io.ReadAll(file)
			if errRead != nil {
				t.Fatal(errRead)
			}

			var v h2cVectors
			errJSON := json.Unmarshal(val, &v)
			if errJSON != nil {
				t.Fatal(errJSON)
			}

			t.Run(v.Ciphersuite, v.runCiphersuite)

			return nil
		}); err != nil {
		t.Fatalf("error opening vector files: %v", err)
	}
}
