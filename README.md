# anp-identity

[![CI](https://github.com/agent-network-protocol/anp-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/agent-network-protocol/anp-identity/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)

Secure, vendor-neutral identity custody and lifecycle management for ANP E1 DIDs.

`anp-identity` creates and manages DID documents while keeping ordinary managed
key operations behind a role-scoped Rust/FFI API boundary. Applications ask for
an operation by KID—sign, verify, derive a shared secret, or authenticate an HTTP
request—without reading private key material. The explicit exception is the
default-off Rust `root-export` feature for the existing, user-confirmed
`RootKeyEnvelopeV1` transfer flow.

The project is available as a Rust crate with asynchronous Node.js/TypeScript
bindings.

> **Release status:** `0.1.0` is pre-release. Registry publication is waiting
> for the coordinated `anp 0.9.4` release. The repository is fully buildable
> from source today; see [Building from source](#building-from-source).

## The problem

An ANP application needs more than a function that generates a DID document.
It also needs to answer operational questions safely:

- Where do the private keys live, and how does the application avoid exporting
  them through every adapter and FFI boundary?
- Which KID is allowed to sign HTTP authentication, sign E2EE assertions, or
  perform X25519 agreement?
- How can multiple DIDs share one process without crossing identity boundaries?
- What happens when two processes update the same identity concurrently?
- How does a key rotation survive a crash between generating a candidate DID
  document and publishing it?
- What happens when publication times out and the caller cannot tell whether
  the old or new DID document is live?

`anp-identity` turns those concerns into one stateful identity runtime instead
of leaving every application to build its own keystore, concurrency protocol,
and DID update state machine.

## How it works

```text
Application
    │
    ├── DidStore ── encrypted records + provider-pinned root key
    │      │
    │      ├── DidIdentity (DID A) ── KID-scoped operations
    │      └── DidIdentity (DID B) ── isolated namespace
    │
    ├── DID document / signatures / public metadata
    │
    └── Publisher or resolver owned by the application
```

The runtime combines five pieces:

1. **Typed E1 document construction** — managed and external public keys are
   validated against a role matrix before a root-bound DID document is created.
2. **Encrypted key custody** — managed private keys are sealed with
   ChaCha20-Poly1305 using record-specific HKDF-derived keys and authenticated
   metadata.
3. **Role-aware cryptography** — signing, verification, ECDH, DID-WBA, and HTTP
   Message Signatures require an explicit KID and enforce its role, origin, and
   lifecycle state.
4. **Transactional persistence** — creation, enrollment, verified document
   adoption, root transfer, namespace deletion, recovery, rotation,
   retirement, and crypto-erasure run under a cross-process exclusive store
   lock with generation checks.
5. **Publication reconciliation** — DID updates use a two-phase state machine,
   including an explicit `PublicationUncertain` state that can only be resolved
   by comparing a verified remote document with the old and candidate digests.

The lower-level [`anp`](https://github.com/agent-network-protocol/anp) crate
provides stateless protocol primitives. `anp-identity` adds private-key custody,
durable state, multi-identity isolation, recovery, and lifecycle policy.

## Capabilities

| Capability | What the module provides |
|---|---|
| DID creation | Root-bound ANP E1 DID documents from managed and external public keys |
| Private-key custody | Encrypted records; only the Rust root-transfer export may return private bytes |
| Device enrollment | Rootless pending device keys, public enrollment material, and verified activation |
| Remote convergence | Monotonic verified-document adoption and local revocation fencing |
| Root transfer | Default-off Rust `root-export` for `RootKeyEnvelopeV1`; wrapped transfer remains available |
| Multi-identity storage | `DidStore` → isolated `DidIdentity` handles |
| Signing | Ed25519 signatures by explicit managed KID |
| Verification | Managed or registered external public KIDs |
| Key agreement | X25519 ECDH with invalid/low-order peer rejection |
| HTTP authentication | Legacy DID-WBA and HTTP Message Signature headers |
| DID updates | Prepare, publish, reconcile, commit, abort, and crash recovery |
| Device document updates | Root-authorized add/remove mutations for exact manifest devices |
| Controlled migration | Default-off Rust `key-import` feature for one-way raw/DER import |
| Namespace retirement | Generation-checked, recoverable deletion without affecting sibling DIDs |
| Key lifecycle | Active, retired, revoked, and explicit local crypto-erasure |
| Concurrency | Cross-process locking plus optimistic generation conflicts |
| Language support | Rust and asynchronous Node.js/TypeScript bindings |

## Supported key roles

The v1 E1 profile uses a deliberately small key matrix:

| Role | Algorithm | Managed private-key use | DID relationship |
|---|---|---|---|
| `root_control` | Ed25519 | Internal DID document proof only | `authentication`, `assertionMethod` |
| `device_signing` | Ed25519 | Device assertions, generic device signing, DID-WBA, and HTTP signing | `authentication`, `assertionMethod` |
| `request_signing` | Ed25519 | Generic signing, DID-WBA, and HTTP request signing | `authentication` |
| `e2ee_signing` | Ed25519 | Generic application payload signing | `assertionMethod` |
| `e2ee_agreement` | X25519 | ECDH | `keyAgreement` |

Every natively created identity has exactly one managed `root_control` key.
An enrolled device or daemon can instead hold a rootless identity view with the
same pinned root public-key fingerprint; root-only operations then fail closed.
Enabling DID-WBA requires a managed `device_signing` or `request_signing` key.
External public keys do not grant the module access to a private-key operation.

## Installation

Registry artifacts are not published yet. After the coordinated release, the
package names will be:

```bash
cargo add anp-identity
npm install @agent-network-protocol/anp-identity
```

Until then, build the repositories as siblings so the pinned development path
can resolve `anp 0.9.4`:

```bash
mkdir anp-workspace
cd anp-workspace
git clone https://github.com/agent-network-protocol/anp.git anp
git clone https://github.com/agent-network-protocol/anp-identity.git anp-identity
cd anp-identity
cargo build --workspace --all-features
```

For the Node binding:

```bash
cd bindings/node
npm ci
npm run build
npm test
```

Node.js 18 or newer is required. The Rust minimum supported version is 1.88.

## Quick start: Rust

The following example creates a local-file-backed store, creates an E1 DID, and
signs a payload with its request-signing key.

```rust
use std::path::Path;

use anp_identity::{
    Capabilities, DidCreateSpec, DidError, DidProfile, DidStore, KeyRole,
    ManagedKeySpec,
};

fn open_or_create_store(path: &Path) -> Result<DidStore, DidError> {
    match DidStore::open_local_file(path) {
        Ok(store) => Ok(store),
        Err(DidError::StoreNotFound) => DidStore::initialize_local_file(path),
        Err(error) => Err(error),
    }
}

fn main() -> Result<(), DidError> {
    let mut store = open_or_create_store(Path::new("./identity-store"))?;
    let existing = store.list_identities()?.into_iter().next();
    let identity = match existing {
        Some(summary) => store.open_identity(&summary.did)?,
        None => store.create_identity(DidCreateSpec {
            profile: DidProfile::E1,
            domain: "example.com".to_string(),
            port: None,
            path_segments: vec!["agents".to_string(), "alice".to_string()],
            capabilities: Capabilities { did_wba: true },
            managed_keys: vec![
                ManagedKeySpec {
                    fragment: "root".to_string(),
                    role: KeyRole::RootControl,
                },
                ManagedKeySpec {
                    fragment: "request".to_string(),
                    role: KeyRole::RequestSigning,
                },
                ManagedKeySpec {
                    fragment: "agreement".to_string(),
                    role: KeyRole::E2eeAgreement,
                },
            ],
            external_keys: Vec::new(),
            services: Vec::new(),
            agent_description_url: None,
            extensions: Vec::new(),
        })?,
    };

    println!("DID: {}", identity.did());
    println!("Document: {}", identity.document());

    let signature = identity.sign("#request", b"hello ANP")?;
    identity.verify("#request", b"hello ANP", &signature)?;
    Ok(())
}
```

`initialize_local_file` creates a random 32-byte root key and stores it in a
private local file. Applications that already own their root key can instead
use `initialize_injected`, `initialize_env`, or `initialize_keyring`.

## Quick start: Node.js

The Node API mirrors the Rust ownership model and keeps filesystem, keyring,
lock, and cryptographic work off the JavaScript event loop.

```js
const { DidStore } = require('@agent-network-protocol/anp-identity')

async function openOrCreateStore(root) {
  try {
    return await DidStore.openLocalFile(root)
  } catch (error) {
    if (error.code !== 'store_not_found') throw error
    return DidStore.initializeLocalFile(root)
  }
}

async function main() {
  const store = await openOrCreateStore('./identity-store')
  const identities = await store.listIdentities()
  const identity = identities.length
    ? await store.openIdentity(identities[0].did)
    : await store.createIdentity({
        profile: 'e1',
        domain: 'example.com',
        pathSegments: ['agents', 'alice'],
        capabilities: { didWba: true },
        managedKeys: [
          { fragment: 'root', role: 'root_control' },
          { fragment: 'request', role: 'request_signing' },
          { fragment: 'agreement', role: 'e2ee_agreement' },
        ],
        externalKeys: [],
        services: [],
        extensions: [],
      })

  const snapshot = await identity.snapshot()
  console.log(snapshot.did)
  console.log(snapshot.document)

  const message = Buffer.from('hello ANP')
  const signature = await identity.sign('#request', message)
  console.log(await identity.verify('#request', message, signature))
}

main().catch(console.error)
```

The JavaScript API exports only `DidStore` and `DidIdentity`. Private DID keys
never appear in a Node value, serialized DTO, TypeScript declaration, or public
API output. The Rust-only, default-off `key-import` feature accepts zeroizing
raw/DER private bytes as a one-way migration input. The separate default-off
`root-export` feature permits only the user-confirmed `RootKeyEnvelopeV1`
egress. Both features are deliberately absent from the default Node build.

## Sign an outbound HTTP request

`http_signature_headers` signs the exact request method, URL, selected headers,
and optional body with an active managed `device_signing` or
`request_signing` key. `http_signature_headers_with_options` additionally
accepts a server nonce, fixed creation/expiry values, and covered components.

```rust
use std::collections::BTreeMap;

let body = br#"{"message":"hello"}"#;
let mut headers = BTreeMap::new();
headers.insert("content-type".to_string(), "application/json".to_string());

let signed_headers = identity.http_signature_headers(
    "#request",
    "https://api.example.com/messages",
    "POST",
    Some(&headers),
    Some(body),
)?;
```

Send the returned headers with the same method, URL, and body. Changing a
covered component after signing will make verification fail. Request transport
is intentionally outside this crate; use the HTTP client appropriate for your
application.

The corresponding verifier is provided by the `anp` crate and requires the KID
to be authorized by the DID document's `authentication` relationship.

## Derive a shared secret

ECDH is available only to an active managed `e2ee_agreement` key:

```rust
let shared = identity.ecdh("#agreement", &peer_x25519_public_key)?;
let raw_x25519_result = shared.as_bytes();
```

The returned value is **not a session key**. Feed it into a domain-separated
HKDF together with the identities and protocol context, then use the derived
key in the caller-owned session. `SharedSecret` zeroizes its Rust buffer on
drop. A Node.js `Buffer` copy must be overwritten by the JavaScript caller.

See [`e2ee_handshake.rs`](crates/anp-identity/examples/e2ee_handshake.rs) for a
complete two-party ECDH, HKDF, and ChaCha20-Poly1305 round trip.

## Update a DID document safely

DID hosting is owned by the application. `anp-identity` coordinates the local
key and document state with that external publisher:

```text
prepare_update
    │
    ├── abort_update                     (publication has not started)
    │
    └── begin_publication
            │
            ├── mark_published → commit_update
            │
            └── mark_publication_uncertain
                    └── reconcile_update(observed_remote_document)
```

After publication starts, a timeout or ambiguous failure must be marked
`PublicationUncertain`. In that state, direct abort, commit, retirement, and
deletion are rejected. `reconcile_update` verifies the observed DID document
and compares its canonical digest:

| Remote observation | Result |
|---|---|
| Old active document | Return to `Prepared`; the caller may safely abort or retry |
| Candidate document | Commit the candidate locally |
| Any other valid document | Return `Conflict`; never import unknown remote state |

This prevents a timeout from deleting a private key that the remote DID
document may already reference.

## Storage and root-key providers

| Provider | Initialization | Intended use |
|---|---|---|
| Local private file | `initialize_local_file` | Standalone applications; generated key in a `0600` file on Unix |
| Injected bytes | `initialize_injected` | Hosts that already manage a uniformly random 32-byte key |
| Environment variable | `initialize_env` | Deployment secret injection; unpadded base64url-encoded 32-byte key |
| OS keyring | `initialize_keyring` | Desktop or platform credential stores, with optional new-store file fallback |

The chosen provider and root-key fingerprint are pinned in the store manifest.
Opening an existing store never silently selects a different provider or
generates a replacement key. Provider unavailability and root-key mismatch are
distinct errors.

An injected or environment-provided root key must be 32 uniformly random bytes,
not a password. Password-based key derivation is outside the v1 API.

## Concurrency and crash recovery

Every mutating operation, including recovery and orphan cleanup, takes the
store-wide cross-process exclusive lock. Registry and identity records use
monotonic generations to detect stale handles rather than overwrite concurrent
work.

When an operation returns `Conflict`:

1. Call `DidStore::reload()` or `DidIdentity::reload()`.
2. Inspect the newly committed state.
3. Decide whether the original operation is still valid.
4. Retry with the refreshed handle if appropriate.

Reload is not a cheap polling read: it takes the store-wide exclusive lock and
runs crash recovery.

Creation and update journals make interrupted operations converge on reopen or
reload. The implementation never treats a partial identity as active merely
because one file exists.

## Security model

The private-key guarantee is a **logical API and FFI boundary**:

- Managed private-key bytes cannot be obtained from the public Rust API, napi
  exports, DTOs, debug output, errors, or `.d.ts` declarations.
- Secret-bearing Rust values use zeroizing memory and are not serialized as
  public models.
- KID role, origin, state, DID ownership, and verification relationships are
  checked before cryptographic operations.
- X25519 rejects malformed, low-order, and all-zero peer results.
- Public API and TypeScript snapshots are reviewed in CI, including the
  declarations generated directly from Rust napi exports.

The module does **not** provide process isolation. The native addon shares an
address space with its Node.js host. A compromised process, malicious native
addon, debugger, core dump, or local memory reader is outside the v1 threat
model. This project is not an HSM, Secure Enclave, or independent KMS.

The local-file provider protects permissions and accidental disclosure. An
attacker who obtains both the root-key file and encrypted records can decrypt
them offline.

Read the complete [security and ownership boundary](docs/boundary.md) before
integrating the module into a security-sensitive host.

## Scope and compatibility

Version 0.1 supports the ANP **E1** DID profile only.

Out of scope for v1:

- general-purpose private-key export or backup outside the controlled
  `root-export` Root Transfer exception;
- root-provider rekey;
- root-control rotation;
- K1, PlainLegacy, or P-256 legacy E2EE identities;
- DID hosting or resolver caching;
- E2EE session and message orchestration;
- browser WASM;
- process-isolated signing.

The repository is pre-release and does not provide a compatibility layer for
stores created under earlier development-only project names or cryptographic
domain separators.

## Building from source

Prerequisites:

- Rust 1.88 or newer;
- Node.js 18 or newer for the Node binding;
- the `anp` repository checked out as a sibling directory until `anp 0.9.4` is
  available from crates.io.

Repository layout:

```text
anp-workspace/
├── anp/
└── anp-identity/
```

Build and test Rust:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
./scripts/check-public-api.sh
cargo run --example e2ee_handshake
```

Build and test Node.js:

```bash
npm --prefix bindings/node ci
npm --prefix bindings/node run build
npm --prefix bindings/node test
```

The Node build currently verifies the build-host platform. The package contains
target definitions for Linux, macOS, and Windows on x64 and arm64, but a
platform should be declared supported only after its native CI build passes.

## Documentation

- [Security and ownership boundary](docs/boundary.md)
- [Node.js binding notes](bindings/node/README.md)
- [Caller-owned ECDH/HKDF example](crates/anp-identity/examples/e2ee_handshake.rs)
- [ANP protocol and stateless SDK](https://github.com/agent-network-protocol/anp)

## Contributing

Issues and pull requests are welcome. Changes that affect storage, key
lifecycle, publication state, public APIs, or napi exports should include tests
for failure and recovery paths. Keep the v1 E1-only boundary explicit and run
the full Rust and Node verification commands before opening a pull request.

## License

Copyright 2026 Agent Network Protocol.

Licensed under the [Apache License, Version 2.0](LICENSE).
