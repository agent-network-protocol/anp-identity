# Security and ownership boundary

The DSH package is a policy and lifecycle layer around ANP Identity. It does not replace the native custody boundary.

The v7 ordinary-plugin creation/authorization UI and Host-bound `UserIdentityClient`
are documented in [V7-MANAGEMENT.md](./V7-MANAGEMENT.md). The legacy
`IdentityClientLease` below remains a separate compatibility contract. Ordinary
user consumers cannot acquire it or supply an HTTP transport callback; their
approved dispatch uses Host-owned transport.

## Trust zones

- ANP Identity Rust and its Node binding hold Store Root Keys, managed private keys, and decrypted signing material.
- The DSH Host process is trusted to load the native Provider and configure consumer policy.
- Ordinary `IdentityClientLease` consumers receive public identity data, signatures, verification outcomes, high-level document sessions, and complete HTTP responses.
- `HostProviderLease` consumers are explicitly listed in `allowProviderConsumers`. They may use sealed secret handoffs and exact HTTP Header patches for a native bridge. They must never forward those values to Browser, Remote, tools, or model APIs.

Consumer identifiers are soft same-process identities. The allowlists prevent accidental cross-plugin use and provide an auditable policy, but JavaScript in the same process is not a sandbox.

The publication extension closes the documented public manager-entry bypass
(review F2): acquisition requires both the actual live installed manager Context and its
matching contextual service proxy,
root/no-context/ordinary callers are rejected, and each management operation
rechecks its installation. When ordinary consumers are configured, public legacy
lease acquisition also requires the installed matching Host consumer/provider
Context; a raw root service cannot launder another consumer name. This remains a
same-process policy, not protection against code that steals another plugin's
Context or accesses internal/private implementation objects.

## Secret rules

- The default client surface has no raw ECDH, private-key import, Root Key export, sealed envelope, or Header patch method.
- ECDH shared secrets, Root Keys, and imported identity material cross the JavaScript bridge only as `anp-sealed-secret/1` envelopes on the Host Provider surface.
- Injected Store Root Keys are a Host bootstrap exception. Supply them only programmatically; never serialize them into Loader configuration. The Provider copies each 32-byte input for one native call and clears that copy afterward.
- Payloads and HTTP bodies may be application-sensitive even though they are not key material. The plugin does not log them or place them in errors.
- The Node binding owns native temporary zeroization. JavaScript Buffers cannot be promised equivalent zeroization because the runtime may copy them.

## Catalog rules

`catalog-v1` contains no cryptographic secrets. It records labels, handles, consumer grants, and Store identity references. The native Store is always identity truth.

- A create intent is durable before native creation. A separate cross-process create lock makes the Store delta recoverable without holding the catalog lock across a native await.
- A deletion tombstone blocks new grants, handles, and client signing before native deletion starts.
- Catalog writes use a generation check, an exclusive cross-process lock, a same-directory temporary file, `fsync`, atomic rename, and directory `fsync`.
- Corruption never falls back to guessed grants. Explicit rebuild produces only `Unclaimed` identities.
- Deleting an identity with another consumer grant is rejected.

## HTTP dispatcher

The legacy client API exposes `dispatch(Request, transport)`:

- exact HTTPS origins must be authorized by Host configuration and requested by the lease;
- caller-supplied `Authorization`, `Signature-Input`, `Signature`, and `Content-Digest` are rejected;
- replayable request bytes are buffered up to 4 MiB;
- the authenticated Request uses `redirect: 'manual'`;
- only `Content-Digest`, `Signature-Input`, and `Signature` may be applied from the native patch;
- transport failures propagate unchanged, while provider failures use stable codes without request or path detail.

AWiki's Bearer Token cache, challenge processing, and retry policy remain in `dsh-awiki` and AWiki IM Core. This package signs one exact request and does not duplicate that authentication state.

## Out of scope

This package does not provide OS sandboxing, malicious-plugin isolation, DID resolution or publication, remote backup, Store rekey, or Root Key rotation. Its ordinary-plugin approval UI does not replace Root Transfer user-presence confirmation, which remains an AWiki workflow above the Host Provider lease.


## Public client publication

Catalog schema v3 records public client URLs, exact metadata/JWKS bytes, version,
operation IDs and safe status; it never stores credentials or assertions. Old
writers must stop for upgrade and matching catalog/native/authorization backups
must be restored together on rollback. A fresh v1/v2 upgrade writes an exact
`.before-v3` backup before switching the live schema; v1 also preserves its
historical `.before-v2` backup behavior. Old v2 readers reject the v3 schema.

A trusted Host explicitly supplies the existing authenticated management channel
and DID document publication/reconcile driver. The publisher cannot substitute an
unchecked DID update. Default configuration has no credentials or fabricated
callback; component test drivers are not production authorization evidence.

OAuth-enabled ordinary consumers receive purpose- and audience-restricted grants.
Client URLs/keys come from the published record. Native key and current DID binding
are checked before signing, and grant validity is checked again before returning
an assertion. Public readback mismatch disables the known publication. Full
remote grant revocation and adversarial process isolation remain later work.
