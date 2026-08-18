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

Multiple identities share no global singleton. Every operation is scoped to a
store, identity, and KID. Cross-identity KID use fails closed.
