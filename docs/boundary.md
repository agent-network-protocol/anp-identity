# anp-identity v1 boundary

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

## Controlled private-key ingress

The no-export boundary does not prohibit one-way key import. The permanent
`key-import` Cargo feature is default-off and is not included in the default
Node binding. Its Rust API accepts owned zeroizing raw or DER bytes, never PEM
in an ordinary `String`. Import inputs are not serializable or printable.

General migration import is allowed only when the target identity does not yet
exist. Every imported private key is derived to its public key and compared
with the exact DID document verification method before any identity record is
committed. A failure leaves no usable partial identity. Importing a key that was
historically stored outside this module cannot retroactively remove that prior
exposure; identities created natively by this module do not have that history.

Legacy root-transfer reception is a separate, narrower ingress for an existing
rootless identity. A Rust host may pass root bytes from a fully authenticated
legacy `RootKeyEnvelopeV1` only with verified source, target, session, device,
and document-checkpoint evidence. The identity must have no active or pending
root, the derived public key must match its pinned root fingerprint and current
document, and the operation enters the same pending promotion state used by a
wrapped-root import. The plaintext is held only in zeroizing memory and is never
written to a host DTO, journal, log, temporary file, or FFI value.

No other plaintext private-key ingress is part of the boundary.

## Wrapped root transfer and protocol compatibility

`export_wrapped_root` is the only private-key egress exception. It returns
recipient-bound, single-use ciphertext and public metadata, never root bytes.
It is not a general export or backup mechanism. Encryption uses an ephemeral
agreement key and a transcript that binds both identities, both devices, the
recipient agreement KID, root KID, document/registry checkpoint, nonce, and
expiry. The active root-control key signs the complete envelope. Decryption and
root-key comparison remain inside the module.

New senders emit only the wrapped-root format. There is no negotiation flag,
legacy-send option, or automatic downgrade. Consequently a new sender talking
to an old receiver fails with an explicit upgrade requirement.

New receivers support both explicitly typed formats: wrapped-root ciphertext
and the legacy `RootKeyEnvelopeV1`. An old sender to a new receiver succeeds
through the controlled legacy ingress above. Type dispatch is exact and
disjoint: a damaged, unknown-version, or authentication-failing wrapped
envelope is never reinterpreted as legacy input. Supporting the legacy reader
does not authorize this module or its hosts to emit a legacy plaintext root.

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
used when reopening a store. Both store and identity reload take the store-wide
exclusive lock, so callers should use them after a conflict rather than in a
tight polling loop.

Revocation and crypto-erasure are distinct. A revoked key remains represented in
metadata and the DID document for historical verification and audit. Explicit
local deletion sets `material_erased`; v1 does not compact historical
verification methods from a published DID document.

Multiple identities share no global singleton. Every operation is scoped to a
store, identity, and KID. Cross-identity KID use fails closed.
