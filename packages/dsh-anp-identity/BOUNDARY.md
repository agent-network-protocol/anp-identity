# Security and ownership boundary

The DSH package is a policy and lifecycle layer around ANP Identity. It does not replace the native custody boundary.

## Trust zones

- ANP Identity Rust and its Node binding hold Store Root Keys, managed private keys, and decrypted signing material.
- The DSH Host process is trusted to load the native Provider and configure consumer policy.
- Ordinary `IdentityClientLease` consumers receive public identity data, signatures, verification outcomes, high-level document sessions, and complete HTTP responses.
- `HostProviderLease` consumers are explicitly listed in `allowProviderConsumers`. They may use sealed secret handoffs and exact HTTP Header patches for a native bridge. They must never forward those values to Browser, Remote, tools, or model APIs.

Consumer identifiers are soft same-process identities. The allowlists prevent accidental cross-plugin use and provide an auditable policy, but JavaScript in the same process is not a sandbox.

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

The default client API exposes only `dispatch(Request, transport)`:

- exact HTTPS origins must be authorized by Host configuration and requested by the lease;
- caller-supplied `Authorization`, `Signature-Input`, `Signature`, and `Content-Digest` are rejected;
- replayable request bytes are buffered up to 4 MiB;
- the authenticated Request uses `redirect: 'manual'`;
- only `Content-Digest`, `Signature-Input`, and `Signature` may be applied from the native patch;
- transport failures propagate unchanged, while provider failures use stable codes without request or path detail.

AWiki's Bearer Token cache, challenge processing, and retry policy remain in `dsh-awiki` and AWiki IM Core. This package signs one exact request and does not duplicate that authentication state.

## Out of scope

This package does not provide OS sandboxing, malicious-plugin isolation, DID resolution or publication, remote backup, Store rekey, Root Key rotation, or an end-user approval UI. Root Transfer user-presence confirmation remains an AWiki workflow above the Host Provider lease.
