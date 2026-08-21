# Wrapped root transfer v1

## Compatibility contract

New senders emit only `anp.identity.root-transfer.wrapped` version `1`. They do
not negotiate a plaintext format and never retry a failed wrapped transfer as a
legacy transfer.

New receivers dispatch by an exact, disjoint type. They accept this wrapped
format and may also accept an authenticated legacy `RootKeyEnvelopeV1` through
the Rust-only controlled legacy ingress described in `boundary.md`. A malformed,
unknown-version, expired, or authentication-failing wrapped envelope is never
reinterpreted as legacy input.

Therefore the supported mixed-version behavior is:

| Sender | Receiver | Result |
|---|---|---|
| new | new | wrapped transfer succeeds |
| new | old | old receiver rejects the new type; the product requests an upgrade |
| old | new | strict legacy reader imports into the same pending-root state |
| old | old | historical behavior outside this module |

## Envelope

The JSON object is closed and canonicalized with RFC 8785/JCS where stated:

```text
type                         = "anp.identity.root-transfer.wrapped"
version                      = 1
context.source_did           = root-owner DID
context.target_did           = recipient identity DID (the same root-bound DID)
context.sender_device_id     = exporting local device
context.recipient_device_id  = the exact manifest target
context.recipient_agreement_kid = exact active X25519 KID
context.root_kid             = exact active root-control KID
context.checkpoint           = document version, registry version, and sha256 digest
context.created_at           = UTC RFC 3339, whole seconds
context.expires_at           = UTC RFC 3339, whole seconds
ephemeral_public_b64u        = raw 32-byte X25519 public key, base64url without padding
nonce_b64u                   = 12 CSPRNG bytes, base64url without padding
ciphertext_b64u              = ChaCha20-Poly1305 ciphertext and tag
signature_b64u               = 64-byte Ed25519 signature
```

The maximum lifetime is 600 seconds. Receivers allow 120 seconds of clock skew
on either side. The source and target DID, both device IDs, recipient agreement
KID and public key, root KID, and checkpoint must match the current typed local
state. X25519 low-order inputs and an all-zero shared secret are rejected.

## Encryption transcript

`AAD` is JCS over the envelope fields `type`, `version`, `context`,
`ephemeral_public_b64u`, and `nonce_b64u`. The root plaintext is exactly the
32-byte Ed25519 root seed held in zeroizing module memory.

The ephemeral X25519 private key is generated per envelope and zeroized after
use. Let `Z` be its ECDH result with the recipient agreement public key:

```text
salt = SHA-256("anp-identity:root-transfer:salt:v1\0" || AAD)
info = "anp-identity:root-transfer:aead:v1\0" || AAD
key  = HKDF-SHA256(salt, Z, info, 32)
```

ChaCha20-Poly1305 encrypts the root seed with `key`, the decoded 12-byte nonce,
and `AAD`.

## Root authorization signature

The signature object is JCS over `type`, `version`, `context`,
`ephemeral_public_b64u`, `nonce_b64u`, and `ciphertext_b64u`. The exact bytes
signed by the active root-control key are:

```text
"anp-identity:root-transfer:signature:v1\0" || JCS(unsigned_envelope)
```

The receiver verifies this signature against the pinned root method before
decrypting.

## Replay and promotion

The recipient stores `(nonce_b64u, SHA-256(JCS(envelope)))` in its encrypted
identity record. The same envelope is idempotent; reusing a nonce for different
bytes fails closed. The ledger is bounded to the newest 256 entries.

A successful import stores the matching root as `pending`; it does not grant
active root authority. Remote promotion uncertainty leaves this pending record
intact. `confirm_root_promotion` requires monotonic verified checkpoint evidence
and the same pinned root fingerprint, then atomically activates the root.

## Fixed vector

[`root-transfer-v1-vector.json`](root-transfer-v1-vector.json) is generated from:

- root Ed25519 seed: 32 bytes of `0x01`;
- device Ed25519 seed: 32 bytes of `0x02`;
- recipient X25519 seed: 32 bytes of `0x03`;
- ephemeral X25519 seed: 32 bytes of `0x16`;
- nonce: 12 bytes of `0x17`;
- created: `2026-08-21T00:00:00Z`; expiry: 300 seconds;
- document and registry version: `1`.

The Rust test compares the complete serialized envelope with this reviewed
fixture, including ciphertext and signature.
