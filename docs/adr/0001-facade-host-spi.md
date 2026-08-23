# ADR 0001: Stable Facade and Host SPI

- Status: accepted for the 0.2.0 implementation
- Date: 2026-08-22
- Scope: `anp-identity`, AWiki IM Core, the Node binding, and DSH providers

## Context

The 0.1 API exposes the storage engine directly. Applications currently see
provider-specific constructors, manifest and generation state, publication
transitions, enrollment internals, key retirement mechanics, raw ECDH output,
and root-transfer wire types. Those operations are necessary inside the
implementation, but they are not one coherent application SDK.

AWiki also needs two custody modes. Mobile, the standalone CLI, and the daemon
can call Rust directly. A DSH deployment must obtain custody through a
TypeScript plugin and must not statically link `anp-identity` into the AWiki
consumer build.

## Decision

The 0.2 API has three layers.

1. The default Stable Facade contains `IdentityManager`, `ManagedIdentity`,
   public snapshots, purpose-scoped signing and verification, and
   `DocumentChangeSession`.
2. The capability-gated Host SPI contains exact HTTP request signing,
   enrollment, verified convergence, zeroizing Rust key agreement, sealed DSH
   key agreement, migration, and the existing legacy root-transfer workflow.
3. The existing store, identity, manifest, registry, publication, enrollment,
   recovery, and key-lifecycle implementation becomes the crate-internal
   Engine.

The following decisions are normative:

- A store continues to manage multiple DIDs.
- `IdentityRef` binds `store_id`, `identity_id`, and DID; all three values are
  checked when a handle is acquired.
- Ordinary signing is selected by purpose. An explicit KID is only a selector
  and never bypasses role, relationship, origin, or state validation.
- Origin Proof remains one semantic call and one Native/Provider round trip.
- `PublicationUncertain` remains observable and can only leave that state by
  reconciliation.
- The default Node API returns neither raw ECDH shared secrets nor reusable
  authentication header patches.
- A trusted provider lease may return a header patch for one exact request;
  an ordinary consumer lease exposes only authenticated dispatch.
- AWiki continues to own Bearer tokens, challenges, response interpretation,
  and retry policy. ANP Identity signs one exact attempt.
- Rust `key-import` and `root-export` remain default-off. Root export is limited
  to the user-confirmed `RootKeyEnvelopeV1` workflow.
- Direct and External implementations satisfy the same contract tests.
- The DSH consumer build has a dependency-tree gate proving that it does not
  statically link `anp-identity`.
- Store schema, DID documents, persisted keys, and the root-transfer wire do
  not change as part of the API refactor.

## Async boundary

External custody is asynchronous. IM Core uses an internal async custody
session and splits stateful work into prepare, await, and complete phases. A
store lock, identity mutex, SQLite transaction, or other business lock must
never be held while awaiting TypeScript. Cancellation, timeout, provider
shutdown, and late callback completion are explicit outcomes.

## Secret boundary

Plaintext Root Keys, imported private keys, and ECDH shared secrets never enter
JavaScript. The external flow uses RFC 9180 HPKE Base mode with X25519,
HKDF-SHA256, and ChaCha20-Poly1305 in both directions. Ciphertext is bound to
the provider instance, lease, consumer, capability, store, identity, key,
operation, recipient public-key digest, canonical input digest, and expiry.
One-time operation tokens are replay checked.

ANP Identity has not shipped a Store format, so the first DSH release creates
and owns its canonical Store from first use. It does not adopt the root key or
provider binding of a development Store. Migration from released AWiki legacy
custody imports identity keys through the sealed Host SPI into that new Store.

## Consequences

- The 0.2 release is intentionally API-breaking while preserving data and wire
  compatibility.
- The Engine can evolve without extending the default SDK surface.
- Host workflows remain available without turning the ordinary API into a
  signing, ECDH, or key-export oracle.
- DSH introduces an asynchronous boundary on the signing hot path, so public
  identity snapshots are cached per lease and Origin Proof is completed in one
  provider call.

## Step 0 validation

The decision is accepted after executable spikes, not solely by design review.
The N-API ThreadsafeFunction spike completes a real Origin Proof across the
Rust/TypeScript boundary with bounded revoke, cancellation, timeout, provider
failure, and Host shutdown behavior. No business lock crosses the await. The
shared RFC 9180 implementation passes a fixed reviewed vector, bidirectional
sealed transfer, AAD substitution, tamper, length, and prototype one-time-token
tests. Production capability-token state is delivered in Step 2; the spike
does not expose it as a compatibility API.
