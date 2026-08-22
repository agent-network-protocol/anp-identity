# anp-identity v1 boundary

## Security boundary

Private keys normally remain behind the Rust/FFI boundary. Public APIs may
return DID documents, public keys, metadata, signatures, verification results,
and ECDH results. The single plaintext egress exception is the default-off
`root-export` Rust API used by an existing, user-confirmed
`RootKeyEnvelopeV1` transfer. It does not apply to any other key role and is
not exposed by the default Node binding.

This is a logical API boundary, not process isolation. A Node native addon shares
an address space with its host. A compromised host process, malicious native
addon, debugger, core dump, or local process-memory reader is outside the v1
threat model. This module is not an HSM, Secure Enclave, or independent KMS.

The default Node entry point exposes only `IdentityManager`, `ManagedIdentity`,
and `DocumentChangeSession`. Host workflows are available from the separate
`./provider` entry point. That entry point is intended for a trusted DSH host,
not ordinary plugins, Browser/Remote APIs, or model tools. Every operation is
authorized by a bounded provider lease; Root Transfer, key import, provider
adoption, and ECDH additionally use a one-time token bound to the store,
identity, KID, request digest, request ID, recipient public key, provider
instance, and parent lease.

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

In External Provider mode, legacy root and migration imports use a reverse
sealed handoff. ANP Identity generates a one-time X25519 recipient inside Rust,
returns only its public key plus authenticated AAD, and consumes the resulting
HPKE ciphertext exactly once. Pending enrollment ECDH uses the same rule as
active-identity ECDH: TypeScript receives an HPKE envelope, never the shared
secret.

## Root-key export and protocol compatibility

The default-off `root-export` feature exposes `export_root_private_key` to Rust
hosts. It returns the active managed root-control key as PKCS#8 DER in a
zeroizing, non-serializable, non-`Debug` container. The host owns the mandatory
user-confirmation interaction and must call the API only after that confirmation
in the existing Root Transfer flow. The output is intended only for immediate
construction of a canonical `RootKeyEnvelopeV1` inside an end-to-end encrypted
P5 message. It must not be written to a DTO, pending journal, log, error,
temporary file, or backup.

Senders emit only `RootKeyEnvelopeV1`. There is no negotiation flag, wrapped
send branch, or automatic fallback. New and old senders therefore use the same
wire contract.

Receivers support `RootKeyEnvelopeV1` through the controlled legacy ingress
above. The already implemented wrapped-root reader may remain for compatibility,
but type dispatch is exact and disjoint: a damaged, unknown-version, or
authentication-failing wrapped envelope is never reinterpreted as legacy input.
`export_wrapped_root` also remains available, but AWiki's sender does not call it.

The Host-only Node provider never returns the exported Root key in plaintext.
It seals the user-confirmed PKCS#8 bytes directly to a native recipient public
key. The calling AWiki IM Core opens that envelope inside its native boundary
before constructing the existing P5-protected `RootKeyEnvelopeV1` payload.

## Inputs and outputs

Creation accepts an E1 domain, non-empty path segments, capabilities, typed
managed-key requests, typed external public keys, typed services, and registered
typed extensions. Unknown extensions and arbitrary top-level JSON are rejected.

Managed root-control is exactly one key. Enabling DID-WBA requires at least one
managed request-signing key. External root-control keys are forbidden.

Outputs contain the DID document, public key metadata, KIDs, signatures,
verification results, Rust Host ECDH results, sealed Node Provider envelopes,
and the explicit Rust-only root export described above. A Rust ECDH result is
not a session key; the caller must immediately derive a scoped key through HKDF
with domain separation. The default Node Facade has no raw ECDH method. The
Host-only Provider returns ECDH material only as HPKE ciphertext. JavaScript
Buffer copies supplied as inputs are outside Rust zeroize coverage.

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

## Store provider adoption

Provider adoption moves custody of the same Store root key from an injected
host provider to a supported DSH-owned provider. It is not root-key rotation or
re-encryption: record ciphertexts and `root_key_fingerprint` remain byte-for-byte
unchanged. The operation verifies the supplied key against the current manifest,
imports it into the target provider, records a recovery journal, atomically
switches the manifest binding, and converges safely after interruption at every
persistent phase.

During an authorized adoption, both the old provider and the new provider may
temporarily possess the same key. The old provider must be retired by the host
only after the new binding opens successfully and the adoption report has been
persisted. DSH External mode passes the key into adoption only through the
reverse sealed handoff; it is never placed in a TypeScript DTO, log, catalog, or
journal.
