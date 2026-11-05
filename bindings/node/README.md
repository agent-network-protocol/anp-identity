# @agent-network-protocol/anp-identity

Node.js bindings for ANP Identity, an E1 and Web DID identity manager that keeps managed
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

## Local OAuth and PAP signing

`oauthPublicJwk(kid?)` exports an Ed25519/EdDSA `request_signing` key or a
P-256/ES256 `oauth_authentication` key. EC JWKs contain canonical 32-byte x/y
coordinates. With multiple eligible keys, pass an explicit kid. Existing ANP,
root/device and E2EE keys retain their existing purpose restrictions.
`signOAuthClientAssertion` accepts `{ client_id, audience, key }`, where key is
`'default'` or `{ kid }`. HTTPS identifiers are exact; the native layer fixes
`iss=sub=client_id`, a 60-second lifetime and fresh 256-bit jti. ES256 output is
64-byte R||S, never DER. Arbitrary claims/headers/lifetimes are rejected.

`prepareOAuthKeyChange({fragment,operation_id,expected_revision})` returns an
existing publication/reconcile session. `exportCandidateOAuthPublicJwk(kid)`
reads pending material only. Every session candidate carries `baseEvidence`
(documentVersion, registryVersion, documentDigest) frozen from the same local
verified checkpoint when prepared; resume preserves that baseline, and later
commit does not change the candidate field. Host publishers must use this evidence
for CAS and reject a conflicting live Registry instead of assigning its newest
checkpoint to an older candidate. `oauthPublicJwk` and signing reject the key until
verified DID publication commits it. The Host separately confirms CIMD/JWKS and
ANPCIMD publication before granting external OAuth use. E1 rootless instances
return `capability_unavailable`; no private-key export/import is initiated.

Only the Host-only `./provider` entry exposes local PAP custody. Call
`lease.providerCapabilities()` and require `api_version:2` plus needed features.
`createDelegatedKey` / `createDpopKey` use `{operation_id,scope}` and return
`{handle,purpose,generation,public_jwk,thumbprint}`. Scope contains owner,
company_id, user_id and optional account_slot; owner must equal the lease consumer.
Company identifiers are exact HTTPS identifiers. Purpose and scope are bound into
the encrypted key reference. Retries of one operation return the same active key;
reusing it with a different scope/purpose fails. Keys never enter identity JWKS.
The current limit is 1024 records per identity, including retired tombstones.
Tombstones preserve operation replay safety; no garbage-collection policy is
implemented. At capacity, creation returns `key_unavailable`. This bounded first
implementation does not establish indefinite high-frequency rotation capacity.

`issuePapDelegation` accepts client_id, the selected identity key, delegated_key
(handle/generation), scope and ttl_seconds (1..86400). It signs ES256
`poppy-delegation+jwt` with only iss/cnf.jwk/iat/exp/jti. Session signing accepts a
local delegated handle and generation, scope, complete delegation, client_id,
sid, sub, optional agent_id and exact http_method/http_uri/access_token. Native
verification checks the delegation signature, active identity key, lifetime and
matching cnf before signing `poppy-session+jwt`; sub must equal scope.user_id.
The input Delegation is expected to be the output of this local typed issuer,
signed by the current identity OAuth key. The verifier uses serde JSON value
parsing and does not independently reject duplicate JSON members in an otherwise
validly signed external Delegation; it is not a general untrusted JOSE decoder.
URI query/fragment are omitted from htu. Without access_token, ath is omitted.
`signDpopProof` uses the separate DPoP handle and optional nonce/access_token.

`describeTemporaryKey` revalidates purpose, scope, generation and encrypted
material for restart recovery. It grants no permission. `retireTemporaryKey`
requires lifecycle capability; old generations cannot sign after retirement.
Provider calls recheck leases before returning. `IDENTITY_PAP_SESSION` and
`IDENTITY_PAP_DPOP` are distinct capabilities; Delegation additionally requires
`IDENTITY_SIGN`. C/Host owns approved caller/target/publication/permission policy.
A low-level handle or public JWK never replaces that policy.

`signManagementProof(reference,{key,method,params,audience?})` uses an active
Ed25519 device key and the existing AWiki DeviceProof JCS format. The method is
allowlisted; purpose, type, timestamps, TTL and nonce are constructed internally.
CIMD device actions require exact server path and target DID in params. Web
requires the configured opaque, exact audience; E1 omits it. This is distinct
from ANP Data Integrity object proof. `signWebRegistrationProof` separately binds
the complete `awiki.register.web.v1` business_projection to the current local
Web document, its unique device Manifest, document hash and selected device key.
The native layer hashes that projection and creates the fixed register transcript;
it never accepts an arbitrary request hash. Bootstrap requires only the managed
device signing/agreement pair; enroll OAuth later through its restricted path.
Exact types are in `provider.d.ts`.

The public fixture `test/fixtures/local-signer-v2-vector.json` contains no secrets.
Regenerate it with `node ../../scripts/generate-local-signer-vector.cjs <output>`;
its request.now freezes the intended verification time. The generator removes its
temporary encrypted Store. Node/OpenSSL independently verifies all four JWT forms
in `test/local-signer-v2.test.cjs`.

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

Choose `profile: 'web'` to create a Web identity without a DID `root_control`
key. Managed device signing/agreement keys and the encrypted Store are reused.
Host status and enrollment proposals expose `rootKeyFingerprint: null` and
`rootCapability: 'absent'`. WBA retains its existing fingerprint and root flows.
Web HTTP authentication uses RFC 9421; legacy DID-WBA, Root Transfer and Root
Import are unavailable. The default entry still exposes no private keys.

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


For DID-backed publication, `prepareDocumentChange` accepts
`{ change: 'bind_oauth_client', clientId, kid, metadataSha256 }`. This prepares a
signed candidate containing one `ANPCIMD` service, preserves unrelated services,
and uses the existing publication/reconcile session. The key must be an active
managed authentication runtime key and the digest must be 64 lowercase hex
characters. Once bound, the exact main client URL cannot silently change through
this operation. Publication uncertainty still requires reconciliation; this
operation does not publish anything by itself or bypass remote device/root proof.
