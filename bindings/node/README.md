# @agent-network-protocol/anp-identity

Node.js bindings for ANP Identity, an E1 DID identity manager that keeps managed
keys behind a native Rust boundary. A single Store can own multiple DIDs. All
filesystem, keyring, and cryptographic operations are asynchronous so they do
not block the JavaScript main thread.

## Public Facade

The default package entry exports only:

- `IdentityManager` for Store initialization, recovery, and multi-DID lifecycle;
- `ManagedIdentity` for public snapshots, purpose-scoped signing, verification,
  Origin Proofs, and document-change preparation;
- `DocumentChangeSession` for publication, commit, and uncertain-result
  reconciliation.

It does not export Engine types, raw ECDH, HTTP Header patches, key import,
wrapped Root Transfer, or Root key export.

```js
const { IdentityManager } = require('@agent-network-protocol/anp-identity')

const manager = await IdentityManager.open({
  stateRoot: '/var/lib/example/identity',
  rootKeyKind: 'local_private_file',
})

const [descriptor] = await manager.list()
const identity = await manager.get(descriptor.reference)
const signature = await identity.sign({
  purpose: 'authentication',
  payload: Buffer.from('request bytes'),
})
```

## Trusted DSH Provider entry

`@agent-network-protocol/anp-identity/provider` is a separate Host-only entry
for a trusted DSH identity plugin and AWiki IM Core adapter. It requires a
bounded capability lease. High-risk ECDH, Root Transfer, and migration import
operations additionally consume request-bound one-time tokens.

Root keys, imported key material, and ECDH shared secrets never return as
plaintext from this entry. They cross the TypeScript bridge only in fixed-suite
HPKE envelopes. Ordinary DSH consumers must use the plugin's narrower client
lease instead of importing this Host entry.

## Root key sources

The bindings support OS keyring, local private file, named environment variable,
and an injected 32-byte key. An injected key `Buffer` is consumed and
overwritten, including validation-error paths. Pass a disposable buffer
containing uniformly random bytes, not a password, and do not reuse it.

Environment-backed keys are unpadded base64url values read from the explicitly
configured variable. Local private files protect against accidental disclosure,
but copying both that file and the encrypted Store permits offline decryption.

## Security boundary

This is a logical API/FFI boundary, not process isolation. The native addon
shares an address space with Node.js and is not an HSM, Secure Enclave, or
independent KMS. JavaScript input-buffer copies are outside Rust zeroization.
See the repository's `docs/boundary.md` for the full trust model,
sealed-handoff rules, Root Transfer exception, and first-release Store
ownership.

The package is supported on a platform only after its native build and tests
pass there. Declaring a target in the build configuration alone is not a support
guarantee.
