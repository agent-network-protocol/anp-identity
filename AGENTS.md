# Repository Guidelines

- Scope v1 to E1 identities. Do not add K1, PlainLegacy, P-256 legacy E2EE,
  private-key export, backup, root-provider rekey, or root-control rotation.
- Keep all comments, documentation comments, errors, and logs in English.
- Private key material must never appear in a public Rust API, FFI export,
  serialized DTO, debug output, or error message.
- Keep secret-bearing types crate-private and backed by zeroizing memory. Do not
  use ordinary `String` values to hold private PEM material.
- All mutating storage paths must take the store's cross-process exclusive lock
  and use generation/CAS checks. Recovery and orphan cleanup follow the same rule.
- `PublicationUncertain` may only transition through reconcile. It must never
  expose a direct abort path.
- Add or update tests in the same task as every behavior change. Keep tests in
  dedicated test files unless private helper access requires a small unit test.
- Prefer the existing `anp` crate and the referenced im-core vault code over
  duplicate cryptographic or storage implementations.
