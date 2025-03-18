# secp256k1
[![secp256k1](https://github.com/bytemare/secp256k1/actions/workflows/wf-analysis.yml/badge.svg)](https://github.com/bytemare/secp256k1/actions/workflows/wf-analysis.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/secp256k1.svg)](https://pkg.go.dev/github.com/bytemare/secp256k1)
[![codecov](https://codecov.io/gh/bytemare/secp256k1/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/secp256k1)

```
  import "github.com/bytemare/secp256k1"
```

This package implements the secp256k1 prime-order elliptic curve group with
- [RFC9380](https://datatracker.ietf.org/doc/rfc9380/) hash-to-curve capabilities
- [complete addition formulas](https://eprint.iacr.org/2015/1060.pdf)
- formally verified scalar and field arithmetics provided by [Fiat-Crypto](https://github.com/mit-plv/fiat-crypto)
- square root in the field and inversions generated by [addchain](https://github.com/mmcloughlin/addchain)
- great effort for constant-time operations where possible
- no external dependencies outside the standard go library

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/secp256k1.svg)](https://pkg.go.dev/github.com/bytemare/secp256k1)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/secp256k1).

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/secp256k1/tags).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
