# anp-did v1 boundary

## Security boundary

Private keys never cross the public Rust API or FFI boundary. Public APIs may
return DID documents, public keys, metadata, signatures, verification results,
and ECDH results, but never private bytes, private PEM, or private JWK members.

This is a logical API boundary, not process isolation. A Node native addon shares
an address space with its host. A compromised host process, malicious native
addon, debugger, core dump, or local process-memory reader is outside the v1
threat model. This module is not an HSM, Secure Enclave, or independent KMS.

The local-file root-key fallback protects file permissions and accidental
disclosure. An attacker who obtains both that root-key file and the encrypted
records can decrypt them offline.

Injected and environment-provided root keys are raw cryptographic keys. They
must contain 32 uniformly random bytes; password-based derivation is outside the
v1 API. The manifest fingerprint detects a wrong key but does not make a
low-entropy caller-provided value resistant to offline guessing.

Internally, private material uses fixed-size values or DER held in zeroizing
containers. Private PEM is not stored in ordinary `String` values. Secret debug
output and errors are redacted.

## Inputs and outputs

Creation accepts an E1 domain, non-empty path segments, capabilities, typed
managed-key requests, typed external public keys, typed services, and registered
typed extensions. Unknown extensions and arbitrary top-level JSON are rejected.

Managed root-control is exactly one key. Enabling DID-WBA requires at least one
managed request-signing key. External root-control keys are forbidden.

Outputs contain the DID document, public key metadata, KIDs, signatures,
verification results, and ECDH results. An ECDH result is not a session key; the
caller must immediately derive a scoped key through HKDF with domain separation.
JavaScript Buffer copies are outside Rust zeroize coverage.

## Ownership

The module owns managed key generation, encrypted storage, role authorization,
identity metadata, and local document revisions. The caller owns DID document
hosting/publication and all E2EE session/message state.

Document updates use prepare/publication/commit reconciliation. A publication
with an unknown result enters `PublicationUncertain` and can only be reconciled
against the observed remote document.

Generation conflicts preserve the caller's stale snapshot. Callers explicitly
reload the store or identity, inspect the newly committed snapshot, and then
decide whether to retry. Reload also runs the same lock-protected crash recovery
used when reopening a store.

Revocation and crypto-erasure are distinct. A revoked key remains represented in
metadata and the DID document for historical verification and audit. Explicit
local deletion sets `material_erased`; v1 does not compact historical
verification methods from a published DID document.

Multiple identities share no global singleton. Every operation is scoped to a
store, identity, and KID. Cross-identity KID use fails closed.
