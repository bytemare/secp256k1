package group

import (
	"github.com/bytemare/secp256k1"
	"testing"
)

const (
	h2c           = "secp256k1_XMD:SHA-256_SSWU_RO_"
	elementLength = 33
	scalarLength  = 32
	order         = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
)

func TestGroup_Ciphersuite(t *testing.T) {
	if secp256k1.New().Ciphersuite() != h2c {
		t.Fatal("expected equality")
	}
}

func TestGroup_ScalarLength(t *testing.T) {
	if secp256k1.New().ScalarLength() != scalarLength {
		t.Fatal("expected equality")
	}
}

func TestGroup_ElementLength(t *testing.T) {
	if secp256k1.New().ElementLength() != elementLength {
		t.Fatal("expected equality")
	}
}

func TestGroup_Order(t *testing.T) {
	if secp256k1.New().Order() != order {
		t.Fatal("expected equality")
	}
}
