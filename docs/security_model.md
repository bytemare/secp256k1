# Threat Model and Assurance Case

This document defines the security model for `github.com/bytemare/secp256k1`.
It focuses on misuse resistance, trust boundaries, and assurance evidence for the current implementation.

## 1. Threat Model

### 1.1 Assets

- **Message and key material supplied by callers**: message inputs, HMAC keys, HKDF secret/salt/info, and derived outputs.
- **Algorithm selection integrity**: callers must not be silently routed to unsupported or downgraded algorithms.
- **Hasher state correctness**: running hash and XOF state must not be mixed across independent operations unintentionally.
- **Release and dependency integrity**: published module artifacts, SBOM, and provenance must remain verifiable.

### 1.2 Trust Boundaries

1. **Caller -> Public API (`hash.Hash`, `Hasher`, `Fixed`, `ExtendableHash`)**:
Untrusted inputs cross this boundary: algorithm identifiers, message bytes,
lengths, and keying material.
2. **Public API -> Internal registry and algorithm wrappers**: The package maps
IDs to constructors and metadata tables, then dispatches to fixed or XOF
implementations.
3. **Internal wrappers -> Cryptographic backends and platform/runtime**:
Cryptographic operations are delegated to Go standard library and
`golang.org/x/crypto` implementations.

### 1.3 STRIDE Analysis

| Component                         | Threat                                           | Mechanism                                                              | Likelihood | Impact | Risk   | Mitigations                                                                                                |
|-----------------------------------|--------------------------------------------------|------------------------------------------------------------------------|------------|--------|--------|------------------------------------------------------------------------------------------------------------|
| API boundary                      | Spoofing                                         | Passing invalid `Hash` IDs to trigger unsupported code paths or panics | Medium     | Medium | Medium | `Available()` gate, fixed registration table, tests for unavailable IDs.                                   |
| Registry/dispatch                 | Tampering                                        | Runtime mutation of algorithm mapping                                  | Low        | High   | Medium | Tables are initialized at package init and not exposed for mutation.                                       |
| API usage                         | Repudiation                                      | Inability to attribute misuse vs library failure                       | Medium     | Low    | Low    | Panics reserved for programmer misuse; operational errors returned as `error` where applicable.            |
| HMAC/HKDF and XOF length handling | Information disclosure                           | Truncation or misuse reducing effective security                       | Medium     | High   | High   | Minimum XOF read enforcement, oversized HMAC key rejection, HKDF length validation through backend errors. |
| API boundary                      | Denial of service                                | Panic-triggering misuse in unguarded caller contexts                   | Medium     | Medium | Medium | Panic conditions are explicit and deterministic; callers can pre-validate inputs.                          |
| Dependency and release chain      | Elevation of privilege / supply-chain compromise | Malicious dependency or artifact substitution                          | Low        | High   | Medium | Pinned workflows, CI analysis, SBOM + provenance generation, signed release artifacts.                     |

## 2. Assurance Case

### 2.1 Assurance Target

The project targets **CA-2 or higher** assurance as an engineering objective, with emphasis on secure defaults, test rigor, and release integrity evidence.
This is an internal engineering target and not a third-party certification claim.

### 2.2 Claims and Evidence

| Claim                                                              | Evidence                                                                                                                                                           |
|--------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Supported algorithms and metadata are deterministic and consistent | Registration and metadata tests in `tests/hash_test.go` and `tests/table_test.go`.                                                                                 |
| Misuse-sensitive conditions are enforced                           | Panic-path tests for HMAC key length and XOF sizing in `tests/fixed_test.go` and `tests/hash_test.go`.                                                             |
| Core API behavior is regression-tested across all supported hashes | Table-driven coverage in `tests/hash_test.go` and `tests/fixed_test.go`.                                                                                           |
| Unexpected input combinations are stress tested                    | Fuzz target in `tests/fuzz_test.go`.                                                                                                                               |
| CI and supply-chain controls are codified                          | Workflows in `.github/workflows/wf-analysis.yaml`, `.github/workflows/wf-tests.yaml`, `.github/workflows/wf-release.yaml`, and `.github/workflows/wf-verify.yaml`. |
| Release artifacts are verifiable                                   | Release process and SLSA verification guidance in `docs/releasing.md` and `README.md`.                                                                             |

### 2.3 Secure Pipeline Properties

- Repository history is version-controlled in GitHub with documented commit and review requirements.
- Automated analysis, testing, and governance checks run in CI workflows.
- Release workflow is defined as code and produces signed evidence artifacts, including provenance attestations and SBOM outputs.
- Verification workflow allows independent post-release validation.

## 3. Secure Design Principles

| Principle            | Applied | Notes                                                                                                 |
|----------------------|---------|-------------------------------------------------------------------------------------------------------|
| Fail-safe defaults   | Yes     | Default output sizes are conservative and deterministic; unsupported algorithms are not registered.   |
| Input validation     | Yes     | Misuse-sensitive size and key checks are enforced through panic/error paths.                          |
| Least privilege      | Partial | Library has no privileged operations, but dependency and CI permissions must remain tightly reviewed. |
| Defense in depth     | Partial | Runtime checks, tests, fuzzing, and CI gates are present; formal verification is out of scope.        |
| Separation of duties | Partial | Governance and review process exists but is maintainer-centric today.                                 |
| Economy of mechanism | Yes     | Small API surface and minimal dependency set reduce attack surface.                                   |
| Secure defaults      | Yes     | Standard hash sizes and safe algorithm registry defaults are used.                                    |
| Auditability         | Yes     | Workflows, changelog, and test suite provide traceable change and verification evidence.              |

Governance hardening opportunities remain tracked in [roadmap.md](roadmap.md).

## 4. Common Weakness Coverage

| Weakness                         | Countermeasures                                                                             |
|----------------------------------|---------------------------------------------------------------------------------------------|
| Invalid or malformed input usage | Strict algorithm registration and explicit misuse handling in panic/error paths.            |
| Weak output length selection     | XOF `Read` rejects undersized output requests to avoid security-strength downgrades.        |
| HKDF length misuse               | HKDF APIs propagate backend length-limit errors.                                            |
| Oversized HMAC key usage         | `Hmac` rejects keys larger than digest size to enforce a constrained secure usage profile.  |
| Dependency vulnerabilities       | CI includes vulnerability and supply-chain analysis gates; dependency updates are reviewed. |

## 5. Residual Risks and Assumptions

- Callers can still misuse cryptographic primitives semantically (for example, weak protocol design) outside this package's scope.
- Panic-based misuse signaling can still terminate an application if callers do not recover or pre-validate.
- Side-channel resistance depends on underlying cryptographic backends and runtime environment, not only this wrapper layer.
- Supply-chain assurances depend on maintainers preserving workflow hardening and key-management hygiene.

## 6. Security Reporting

For vulnerability reporting and coordinated disclosure, use [.github/SECURITY.md](../.github/SECURITY.md).

## Related Documents

- [architecture_and_guidelines.md](architecture_and_guidelines.md)
- [releasing.md](releasing.md)
- [governance.md](governance.md)
- [roadmap.md](roadmap.md)
