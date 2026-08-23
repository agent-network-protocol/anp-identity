# ANP Identity

[![CI](https://github.com/agent-network-protocol/anp-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/agent-network-protocol/anp-identity/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/anp-identity.svg)](https://crates.io/crates/anp-identity)
[![docs.rs](https://docs.rs/anp-identity/badge.svg)](https://docs.rs/anp-identity)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)

ANP Identity is a multi-DID identity manager for applications built on the
[Agent Network Protocol](https://github.com/agent-network-protocol/anp). It
stores DID documents and managed private keys together, enforces what each key
may do, and makes document publication and recovery explicit.

Applications use a small, purpose-oriented API:

- manage one or more DIDs through `IdentityManager`;
- read public identity snapshots through `ManagedIdentity`;
- request authentication, device, application, or Origin Proof signatures;
- coordinate DID document changes through `DocumentChangeSession`;
- use privileged Host SPI capabilities for HTTP signing, device enrollment,
  key agreement, migration, and Root Transfer.

The ordinary API does not expose private keys, raw ECDH results, storage
records, generations, journals, or the internal Store engine. The one explicit
plaintext exception is the default-off Rust `root-export` feature required by
the existing, user-confirmed `RootKeyEnvelopeV1` transfer protocol.

> **Release status:** `0.2.0` is the first public API release candidate. The
> Rust crate and Node package have not been published yet; build them from this
> repository until release artifacts are available.

## Why this project exists

Generating a DID document is easy. Operating a DID safely over time is not.
A production host must also answer questions such as:

- Where are private keys stored, and which code is allowed to use them?
- Which key may authenticate an HTTP request, sign an application object, or
  perform X25519 agreement?
- How can one Store manage several DIDs without crossing identity boundaries?
- What happens when two processes update the same identity concurrently?
- How does a key rotation survive a crash between local preparation and remote
  publication?
- What should happen when publication times out and the host cannot tell which
  document is live?
- How can native mobile code and a DSH TypeScript plugin share one identity
  contract without passing secret material through JavaScript?

ANP Identity provides those operational guarantees as one reusable component,
instead of requiring each application to invent its own keystore, role checks,
update journal, recovery protocol, and FFI boundary.

## How it works

```text
Application or DSH plugin
          │
          ├── IdentityManager ── Store lifecycle and multi-DID lookup
          │          │
          │          ├── ManagedIdentity (DID A)
          │          └── ManagedIdentity (DID B)
          │
          ├── DocumentChangeSession ── prepare / publish / reconcile
          │
          └── Host SPI ── narrowly authorized privileged workflows
                         HTTP signing, sealed ECDH, enrollment,
                         migration, Root Transfer

Encrypted Store
  ├── public DID documents and metadata
  ├── encrypted private-key records
  ├── transaction journals
  └── root-key provider binding
```

The implementation combines five responsibilities:

1. **Typed ANP E1 identity creation.** Managed keys and external public keys
   are validated against a fixed role matrix before a DID is created.
2. **Encrypted key custody.** Managed private keys are encrypted with
   ChaCha20-Poly1305. Record keys are derived with HKDF and authenticated
   metadata binds ciphertext to its Store, identity, KID, and key role.
3. **Purpose-scoped cryptography.** Callers ask to authenticate, sign a device
   assertion, sign a domain-separated application payload, or create an Origin
   Proof. ANP Identity selects or validates an eligible active key.
4. **Transactional lifecycle management.** Store-wide locking, generation
   checks, journals, and recovery protect creation, enrollment, rotation,
   revocation, deletion, and migration from lost updates and partial writes.
5. **Explicit publication reconciliation.** A DID update is not committed
   merely because an HTTP call returned. Unknown publication outcomes must be
   reconciled against a verified remote document.

The lower-level `anp 0.9.5` crate supplies stateless document, proof, and
authentication primitives. ANP Identity adds custody, durable state,
multi-identity isolation, lifecycle policy, and application-facing APIs.

## What it provides

| Area | Capability |
|---|---|
| Multi-DID management | One Store can create, list, open, recover, and delete multiple isolated identities |
| DID documents | ANP E1 creation, public snapshots, external public keys, services, and device manifests |
| Private-key custody | Encrypted managed-key records tied to a pinned root-key provider |
| Signing | Purpose-scoped Ed25519 authentication, device assertion, application assertion, and Origin Proof signing |
| Verification | Purpose and DID-relationship checks before signature verification |
| HTTP authentication | Host-only exact-request signing for DID-WBA and RFC 9421-style HTTP Message Signatures |
| Key agreement | Host-only X25519 agreement; external mode transports only sealed results through TypeScript |
| DID updates | Prepare, publish, complete, abort-before-acceptance, uncertain-result reconciliation, and recovery |
| Enrollment | Rootless device or request-signing enrollment with verified remote-document activation |
| Root Transfer | Wrapped transfer support plus a feature-gated legacy `RootKeyEnvelopeV1` export/import path |
| Migration | Feature-gated, one-way key import for trusted hosts |
| Concurrency | Cross-process Store lock and optimistic generation conflict detection |
| Language support | Rust Facade, asynchronous Node.js bindings, and a separate trusted Provider entry |

## What it deliberately does not provide

ANP Identity is not:

- a DID registry, resolver, hosting service, or publication transport;
- an instant-messaging ratchet or per-message encryption engine;
- an OAuth/Bearer-token cache or a general HTTP client;
- an HSM, Secure Enclave, process sandbox, or remote KMS;
- a password-to-key derivation system;
- a policy engine that grants arbitrary plugins unrestricted signing access.

The host remains responsible for verifying remote registry evidence, obtaining
user confirmation for sensitive Root Transfer, choosing authorization policy,
dispatching network requests, and deriving protocol-specific session keys.

## Public API and Host SPI

The API is split by trust level.

### Public Facade

The default Rust and Node entry points expose:

- `IdentityManager` — initialize/open a Store, inspect it, list identities,
  create/get/delete identities, and run recovery;
- `ManagedIdentity` — obtain a public snapshot, sign or verify by purpose,
  generate an Origin Proof, and start or resume a document change;
- `DocumentChangeSession` — bind publication attempts to the exact candidate
  document and reconcile ambiguous results.

Internal Engine types such as `DidStore`, `DidIdentity`, raw lifecycle states,
manifest structures, and journal records are not public API.

### Trusted Host SPI

`anp_identity::host` and the Node `./provider` entry contain capabilities that
ordinary application code should not receive directly:

- exact HTTP request signing;
- device enrollment and remote-document convergence;
- key agreement;
- one-way migration import;
- wrapped and legacy Root Transfer workflows.

In DSH External mode, Root keys, imported private keys, and ECDH shared secrets
cross the TypeScript bridge only as fixed-suite HPKE ciphertext. A bounded,
request-specific capability token authorizes each privileged operation.

## Installation

Until `0.2.0` is published, clone this repository and use a local dependency:

```toml
[dependencies]
anp-identity = { path = "../anp-identity/crates/anp-identity" }
```

Optional Rust features are default-off:

| Feature | Intended caller |
|---|---|
| `key-import` | A trusted one-way migration host |
| `root-export` | A trusted, user-confirmed legacy `RootKeyEnvelopeV1` sender |

Rust 1.88 or newer is required. The Node package requires Node.js 18 or newer.

## Quick start: Rust

This example initializes a local Store, creates an E1 DID, and signs a payload
with an authentication-capable key:

```rust
use std::path::PathBuf;

use anp_identity::{
    CreateIdentityCapabilities, CreateIdentityProfile, CreateIdentityRequest,
    IdentityError, IdentityManager, IdentityManagerConfig, IdentityResult,
    KeySelector, ManagedKeyInput, ManagedKeyRole, RootKeySource, SignRequest,
    SigningPurpose, VerifyRequest, VerificationOutcome,
};

fn config() -> IdentityManagerConfig {
    IdentityManagerConfig {
        state_root: PathBuf::from("./identity-store"),
        root_key: RootKeySource::LocalPrivateFile,
    }
}

fn open_or_initialize() -> IdentityResult<IdentityManager> {
    match IdentityManager::open(config()) {
        Ok(manager) => Ok(manager),
        Err(IdentityError::StoreNotFound) => IdentityManager::initialize(config()),
        Err(error) => Err(error),
    }
}

fn main() -> IdentityResult<()> {
    let mut manager = open_or_initialize()?;
    let identity = match manager.list()?.into_iter().next() {
        Some(descriptor) => manager.get(&descriptor.reference)?,
        None => manager.create(CreateIdentityRequest {
            profile: CreateIdentityProfile::E1,
            domain: "example.com".to_owned(),
            port: None,
            path_segments: vec!["agents".to_owned(), "alice".to_owned()],
            capabilities: CreateIdentityCapabilities { did_wba: true },
            managed_keys: vec![
                ManagedKeyInput {
                    fragment: "root".to_owned(),
                    role: ManagedKeyRole::RootControl,
                },
                ManagedKeyInput {
                    fragment: "request".to_owned(),
                    role: ManagedKeyRole::RequestSigning,
                },
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        })?,
    };

    let payload = b"hello ANP".to_vec();
    let signature = identity.sign(SignRequest {
        purpose: SigningPurpose::Authentication,
        key: KeySelector::Default,
        payload: payload.clone(),
    })?;
    let outcome = identity.verify(VerifyRequest {
        purpose: SigningPurpose::Authentication,
        kid: signature.kid.clone(),
        payload,
        signature: signature.bytes,
    })?;
    assert_eq!(outcome, VerificationOutcome::Valid);

    let public = identity.public_identity()?;
    println!("DID: {}", public.reference.did);
    println!("revision: {}", public.revision);
    Ok(())
}
```

`LocalPrivateFile` creates a random 32-byte Store root key in a private local
file. Hosts that already manage a root key can use `Injected`, `Environment`,
or `Keyring` instead.

## Quick start: Node.js

The default Node entry mirrors the same Facade and performs filesystem,
keyring, lock, and cryptographic work outside the JavaScript event loop:

```js
const {
  IdentityManager,
} = require('@agent-network-protocol/anp-identity')

async function main() {
  const manager = await IdentityManager.initialize({
    stateRoot: './identity-store',
    rootKeyKind: 'local_private_file',
  })

  const identity = await manager.create({
    profile: 'e1',
    domain: 'example.com',
    pathSegments: ['agents', 'alice'],
    capabilities: { didWba: true },
    managedKeys: [
      { fragment: 'root', role: 'root_control' },
      { fragment: 'request', role: 'request_signing' },
    ],
  })

  const publicIdentity = await identity.publicIdentity()
  console.log(publicIdentity.reference.did)

  const signature = await identity.sign({
    purpose: 'authentication',
    payload: Buffer.from('hello ANP'),
  })
  console.log(signature.kid, signature.bytes.length)
}

main().catch(console.error)
```

Use `IdentityManager.open(...)` after the Store has been initialized. Keep the
manager and active identity handles for the lifetime of the host instead of
reopening files for every signature.

## Signing model

The Facade does not expose a generic “use any KID for any bytes” oracle. A
signature request declares its purpose:

| Purpose | Eligible managed key | Additional binding |
|---|---|---|
| `authentication` | request-signing or device-signing | DID `authentication` relationship |
| `device_assertion` | device-signing | DID assertion authorization |
| `application_assertion` | request-signing or E2EE-signing | caller-provided domain separator |
| Origin Proof | request-signing | canonical method, metadata, body, and proof options |

The selected key must be active, managed by the identity, authorized by the DID
document, and compatible with the requested purpose. A caller may select an
exact KID or request the unique eligible default.

For message-oriented applications, Origin Proof signing is usually the hot
path. Public identity snapshots and active KIDs should be cached in memory and
refreshed after a document change, recovery, or conflict.

## HTTP request signing

HTTP authentication belongs to the Host SPI because reusable signature headers
would turn an ordinary consumer lease into a signing oracle. A trusted host
provides the exact method, URL, selected headers, and optional body, then sends
the returned patch only with that request.

A DSH dispatcher should preserve these invariants:

- reject bodies above its configured limit before signing (the AWiki plugin
  uses a 4 MiB ceiling);
- use `redirect: 'manual'` and re-authorize every redirect target;
- bind an explicitly empty body as a body and include `Content-Digest`;
- never reuse a header patch for another URL, method, body, or attempt;
- keep Bearer-token caching and network transport outside ANP Identity.

The `anp` verifier checks the signature against the DID document and requires
the selected KID to be authorized by its `authentication` relationship.

## DID document changes

The host owns DID publication. ANP Identity owns the local transaction:

```text
prepare_document_change
        │
        ├── rejected before publication ──> abort locally
        │
        └── begin_publication
                │
                ├── confirmed + verified evidence ──> commit
                │
                └── result unknown ──> publication_uncertain
                                           │
                                           └── reconcile(verified remote)
```

`DocumentChangeSession` binds an operation ID, candidate digest, and publication
generation. When the network result is unknown, the identity cannot silently
abort or commit. The host must resolve the DID through a trusted path and pass
verified version, registry version, and digest evidence to `reconcile`.

This prevents a timeout from deleting a key that a remotely published document
may already reference.

## Store root-key sources

| Source | Intended use | Important property |
|---|---|---|
| Local private file | Standalone native applications | Random key stored separately with private file permissions |
| Injected 32-byte key | Mobile secure storage or an existing host vault | Input is consumed and zeroized by Rust |
| Named environment variable | Controlled deployment secret injection | Value must be unpadded base64url for exactly 32 bytes |
| OS keyring | Desktop/native applications | Provider identity is pinned in the Store manifest |

The Store records the chosen provider binding and a root-key fingerprint.
Opening it with another provider or key fails closed. An injected or environment
key must be uniformly random; do not pass a password.

Copying both a local root-key file and the encrypted Store permits offline
decryption. Use a platform vault or keyring when the threat model requires the
root key to be protected separately from application data.

## Multiple DIDs, concurrency, and recovery

One `IdentityManager` can own multiple DIDs. Each `IdentityRef` contains the
Store ID, local identity ID, and DID; a reference from another Store is rejected.
Private-key records and lifecycle state remain namespaced per identity.

Mutations acquire a Store-wide cross-process lock and use monotonic generation
checks. A stale handle receives `Conflict` instead of overwriting newer state.
Call `IdentityManager::recover()` (or Node `manager.recover()`) after a conflict
or interrupted write, then obtain fresh handles. Recovery is a Store-wide
exclusive operation, not a cheap polling read.

Long-lived applications should:

1. open one manager during startup;
2. cache public identity snapshots and active handles;
3. serialize management workflows at the application boundary;
4. recover only after a conflict, crash, or explicit health action.

## Direct native mode and DSH External mode

ANP Identity supports two deployment shapes with the same identity semantics:

| Mode | Typical host | Integration |
|---|---|---|
| Direct | Rust services and mobile native libraries | Link the Rust crate and call the Facade/Host SPI directly |
| External | Node-based AWiki CLI through DSH | Load the native Node Provider from a trusted DSH plugin and inject a bounded provider lease into IM Core |

The External mode does not require IM Core's Node build to statically link ANP
Identity. TypeScript carries public DTOs and HPKE envelopes; privileged plaintext
stays in native code. Mobile builds may continue to link the Rust implementation
directly.

The Node package exposes two entries:

```js
require('@agent-network-protocol/anp-identity')          // public Facade
require('@agent-network-protocol/anp-identity/provider') // trusted Host adapter
```

See [the Node binding guide](bindings/node/README.md) and
[security boundary](docs/boundary.md) before using the Provider entry.

## Security boundary

ANP Identity provides a logical Rust/FFI boundary, not process isolation. A
native addon shares the Node process address space. Compromised native code,
a debugger with sufficient privilege, or a copied local root-key file may
bypass application-level policy.

Security-sensitive rules include:

- no private-key fields in public snapshots, logs, errors, or serializable DTOs;
- no raw ECDH on the public Node API;
- injected JavaScript buffers are consumed and overwritten, but unrelated JS
  copies are outside Rust zeroization;
- migration import and legacy Root export are default-off Rust features;
- legacy Root export requires explicit user-presence confirmation;
- DSH privileged operations require bounded capabilities and one-time tokens;
- unknown document publication outcomes fail closed until reconciliation.

Read [docs/boundary.md](docs/boundary.md) for the complete trust model and
[AGENTS.md](AGENTS.md) for repository-level invariants.

## Building and testing

Rust workspace:

```bash
cargo fmt --check
cargo test --workspace --all-features
cargo clippy --workspace --all-features --all-targets -- -D warnings
./scripts/check-public-api.sh
```

Node binding:

```bash
cd bindings/node
npm ci
npm run build
npm test
```

The repository checks generated TypeScript declarations, public API snapshots,
secret-free DTO boundaries, cross-process conflict behavior, recovery fault
points, and feature-gated key import/export surfaces.

Declaring a native target in build metadata is not a support guarantee. A
platform is supported only after its native package and tests pass there.

## Repository layout

```text
crates/anp-identity/   Rust Facade, Host SPI, custody engine, tests, examples
bindings/node/        asynchronous Node Facade and trusted Provider entry
docs/                 security boundary and protocol notes
api/                  reviewed Rust and TypeScript public API snapshots
scripts/              API and release verification gates
```

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
