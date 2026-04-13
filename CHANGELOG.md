# Changelog

All notable changes to this project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/). Contributors should add user-facing changes under the `Unreleased` section as described in [`.github/CONTRIBUTING.md`](.github/CONTRIBUTING.md).

## [Unreleased]

### Added

- Initialized `CHANGELOG.md` and documented the requirement to record user-facing changes.

### Changed

- Fixed Multiply with better constant-time conditional swaps.
- Fixed HashToGroup with pull SSWU output from the ISO group before adding to avoid super-rare edge case of x2 == x1.
- Added some more tests.
- Changed `HashToScalar`, `HashToGroup`, and `EncodeToGroup` to return errors for empty DST inputs instead of panicking.
- Standardized public nil-input handling for element and scalar mutators/comparators to panic consistently.
