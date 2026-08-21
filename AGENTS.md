# Repository Guidelines

- Scope v1 to E1 identities. Do not add K1, PlainLegacy, P-256 legacy E2EE,
  plaintext private-key export, backup, root-provider rekey, or root-control
  rotation. The only approved egress exception is target-bound wrapped-root
  ciphertext; it is not a plaintext export or backup API.
- Keep all comments, documentation comments, errors, and logs in English.
- Private key material must never appear in a public API output, FFI export,
  serialized DTO, debug output, or error message. The opt-in Rust-only
  `key-import` feature may accept private bytes as a one-way input; it must not
  expose them again.
- Keep secret-bearing implementation types crate-private and backed by
  zeroizing memory. Public Rust import inputs must own zeroizing raw/DER bytes,
  be non-serializable and non-`Debug`, and never accept ordinary `String` PEM.
- All mutating storage paths must take the store's cross-process exclusive lock
  and use generation/CAS checks. Recovery and orphan cleanup follow the same rule.
- `PublicationUncertain` may only transition through reconcile. It must never
  expose a direct abort path.
- Add or update tests in the same task as every behavior change. Keep tests in
  dedicated test files unless private helper access requires a small unit test.
- Prefer the existing `anp` crate and the referenced im-core vault code over
  duplicate cryptographic or storage implementations.
- Keep `key-import` as a permanent, default-off feature and exclude it from the
  default Node binding. General migration import is allowed only while the
  target identity does not exist and must verify every private key against the
  DID document public method before committing.
- Root transfer senders must emit only the current wrapped-root ciphertext
  format. Never add legacy plaintext sending, format negotiation, or fallback
  from a failed wrapped transfer to a legacy transfer.
- A Rust host may receive an authenticated legacy `RootKeyEnvelopeV1` and pass
  its root key through the dedicated zeroizing legacy-root ingress. That path is
  receive-only, requires an existing rootless identity with the same pinned
  root fingerprint and verified transfer evidence, and must never persist the
  plaintext in a DTO, journal, log, or temporary file. A malformed or unknown
  wrapped envelope must never be retried through the legacy parser.
