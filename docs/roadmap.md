# Roadmap

## Achieved key objectives

- Implemented a Go `secp256k1` group library with public `Scalar` and `Element` APIs and canonical encoding/decoding support.
- Added RFC 9380 hash-to-curve / encode-to-curve support with JSON test vectors under `tests/h2c/`.
- Committed generated field/scalar arithmetic backends (Fiat-Crypto and addchain-generated routines) and maintained a stdlib-only runtime dependency model.
- Added repository-defined CI, analysis, release, and release-verification workflows.

## Next steps

### Critical

- Add `Fuzz*` targets for public decode/hash-to-curve APIs and high-risk edge cases, then enable the existing `.github/Makefile` `fuzz` target in regular validation.
- Evaluate and document safe usage guidance for `Scalar.Pow()` (currently variable-time) and consider a safer alternative for secret-exponent use cases.
- Validate we have constant time behavior where expected and document any exceptions or limitations clearly in the API docs

### High

- Add property-based tests for group-law invariants, encoding round trips, and scalar/element interoperability invariants.

### Medium

- Review panic/error contracts for consistency and document any intentional deviations as APIs evolve.
- GLV, wNAF, and other arithmetic optimizations
- Multi-scalar multiplication APIs and optimizations
- Add explicit benchmark scenarios and lightweight performance regression tracking for common operations.

### Low

