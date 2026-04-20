package main

type hashSpec struct {
	name          string
	label         string
	file          string
	importPath    string
	packageName   string
	newFunc       string
	sumFunc       string
	sizeExpr      string
	blockSizeExpr string
	digestSize    int
	lengths       []int
}

var hashSpecs = []hashSpec{
	{
		name:          "SHA256",
		label:         "SHA-256",
		file:          "xmd_sha256_gen.go",
		importPath:    "crypto/sha256",
		packageName:   "sha256",
		newFunc:       "New",
		sumFunc:       "Sum256",
		sizeExpr:      "sha256.Size",
		blockSizeExpr: "sha256.BlockSize",
		digestSize:    32,
		lengths:       []int{48, 96},
	},
	{
		name:          "SHA384",
		label:         "SHA-384",
		file:          "xmd_sha384_gen.go",
		importPath:    "crypto/sha512",
		packageName:   "sha512",
		newFunc:       "New384",
		sumFunc:       "Sum384",
		sizeExpr:      "sha512.Size384",
		blockSizeExpr: "sha512.BlockSize",
		digestSize:    48,
		lengths:       []int{72, 144},
	},
	{
		name:          "SHA512",
		label:         "SHA-512",
		file:          "xmd_sha512_gen.go",
		importPath:    "crypto/sha512",
		packageName:   "sha512",
		newFunc:       "New",
		sumFunc:       "Sum512",
		sizeExpr:      "sha512.Size",
		blockSizeExpr: "sha512.BlockSize",
		digestSize:    64,
		lengths:       []int{48, 64, 96, 98, 196},
	},
}
