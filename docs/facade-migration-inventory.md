# ANP Identity 0.1 to 0.2 Migration Inventory

This document freezes Step 0 of the 0.2 Facade and DSH dual-mode program. It is
an implementation inventory, not a public compatibility promise.

## Audited revisions

| Repository | Branch | Audited revision |
|---|---|---|
| `anp-identity` | `main` | `42fcc74` |
| `anp` | `master` | `ba18dae` |
| `awiki-cli-rs2` | `release/0815` | `bd43d171` |
| `dsh-awiki` | `main` | `aab3d1f` |
| `awiki-me` | `release/0815` | `de4c4ab1` |

The frozen Rust surfaces are `api/anp-identity.txt`,
`api/anp-identity-key-import.txt`, and `api/anp-identity-root-export.txt`. The
frozen Node surface is `bindings/node/test/fixtures/native.d.ts` together with
the published wrapper declaration `bindings/node/index.d.ts`.

The audited snapshot SHA-256 values are:

| Surface | SHA-256 |
|---|---|
| Rust default | `5ab5ae843c164050533955d8c0b15c1c746a1e1999f6b2d78975c1155ce6b842` |
| Rust key import | `7df1b7d158093aee77d4e27fd91dcc5eeb1d375215d53f54a57002a14ffe6c6e` |
| Rust root export | `a7949fb47122936224b1aa30c39270f494d6cbe888ca2289ba08b3b687d0234d` |
| Node generated declaration | `27d7614420e2cad005317361a9da11ba891fab08f88c51e26f0e4bab3f9b2f1e` |
| Node wrapper declaration | `dd8b66cc2eabfa84e21f473624700e4164db08e43998fcede624ce7be43888b6` |
| Dart generated identity API | `7719bf849f6a651640a91cd772c80bebc0f26f1486cb390d3a639038d87ba9ed` |
| Dart generated identity DTO | `6b741ff7f083b5892c97357666c99e2e3b35c965a8cd5449c94b27161120c81e` |
| Dart generated bridge | `a09d2145fee2784066342424da725ec1da4eb8c836cf53a9be73d43701345fa5` |
| Dart generated FRB entry | `0c19bf7ed34fbe627d1b0cd8b778d633c55ade27c0477cc8073917b1af361bf7` |

## Public API classification

Every 0.1 public root item and method is assigned below. Enum variants and
public fields inherit the category of their owning type. Trait implementations
and formatting implementations inherit the category of the owning type.

### Stable Facade or Facade replacement

| 0.1 item | 0.2 destination |
|---|---|
| `DidStore::{initialize,open}_{injected,env,local_file,keyring}` | `IdentityManager::{initialize,open}(IdentityManagerConfig)` |
| `DidStore::{list_identities,create_identity,open_identity,delete_identity_namespace}` | `IdentityManager::{list,create,get,delete}` |
| `DidStore::reload` | explicit `IdentityManager::recover`; bounded internal conflict refresh |
| `DidCreateSpec`, `DidProfile`, `Capabilities`, `ManagedKeySpec`, `ExternalPublicKeySpec`, `ExternalPublicKeyMaterial`, `PublicOkpJwk`, `ServiceSpec`, `DeviceManifestSpec`, `DeviceManifestEntrySpec`, `DidExtensionSpec` | Facade-owned create and document-change DTOs |
| `IdentitySummary`, `IdentityState` | `IdentityDescriptor`, `PublicIdentityState` |
| `DidIdentity::{identity_id,did,state,revision,document,keys,capabilities}` | `ManagedIdentity::public_identity` |
| `DidIdentity::{key_metadata,public_key_bytes}` | `PublicIdentity.active_keys`; full metadata moves to diagnostics/Host status |
| `DidIdentity::{sign,sign_device_assertion}` | `ManagedIdentity::sign(SignRequest)` with `SigningPurpose` |
| `DidIdentity::sign_origin_proof` | `ManagedIdentity::sign_origin_proof` |
| `DidIdentity::verify` | `ManagedIdentity::verify` |
| `DidIdentity::{prepare_update,pending_revision,begin_publication,mark_publication_uncertain,mark_published,commit_update,abort_update,reconcile_update}` | `DocumentChangeSession::{candidate,begin_publication,complete,reconcile}` and resume |
| `PreparedUpdate`, `PendingRevisionSummary`, `PublicationState`, `ReconcileOutcome`, `DocumentUpdateSpec`, `DeviceMutationSpec`, `DeviceAddSpec`, `DevicePublicKeySpec`, `RequestSigningMutationSpec`, `RequestSigningPublicKeySpec`, `RequestSigningRotation` | Facade-owned document-change requests, outcomes, and opaque operation identifiers |
| `DidResult` | `IdentityResult` |

### Host SPI

| 0.1 item | 0.2 destination |
|---|---|
| `DidStore::{prepare_enrollment,prepare_request_signing_enrollment,discard_unpublished_enrollment}` | `EnrollmentWorkflow` |
| `EnrollmentSpec`, `RequestSigningEnrollmentSpec`, `PreparedEnrollment`, `PreparedRequestSigningEnrollment`, `EnrollmentPublicKey` | Host enrollment DTOs |
| `DidIdentity::{pending_enrollment,pending_request_signing_enrollment,sign_pending_enrollment,ecdh_pending_enrollment}` | opaque `EnrollmentSession` operations |
| `DidIdentity::adopt_verified_document`, `AdoptVerifiedDocumentSpec`, `AdoptDocumentOutcome`, `VerifiedDocumentEvidence`, `DocumentCheckpoint` | `ConvergenceWorkflow` and Host evidence DTOs |
| `DidIdentity::{sign_document_proof,sign_object_proof,sign_pending_root_object_proof}` | typed Host proof requests |
| `DidIdentity::{legacy_did_wba_header,http_signature_headers,http_signature_headers_with_options}`, `HttpSignatureOptions` | `HttpRequestSigningPort` and compatibility port |
| `DidIdentity::{ecdh,managed_key_metadata}`, `SharedSecret` | Rust `KeyAgreementPort`; sealed Provider operation |
| `DidIdentity::{root_capability,root_key_fingerprint,checkpoint}` | `IdentityHostStatus` |
| `DidIdentity::{export_wrapped_root,import_wrapped_root,confirm_root_promotion}`, `RootPromotionSpec`, `RootTransferContext`, `RootTransferExportSpec`, `RootTransferImportOutcome`, `WrappedRootEnvelope`, `WRAPPED_ROOT_ENVELOPE_TYPE`, `WRAPPED_ROOT_ENVELOPE_VERSION` | Root-transfer compatibility workflow; absent from the default API |
| `DidIdentity::export_root_private_key`, `ExportedRootPrivateKey` | default-off `RootTransferPort` for user-confirmed `RootKeyEnvelopeV1` send |
| `DidIdentity::import_legacy_root_transfer`, `LegacyRootTransferEvidence`, `LegacyRootTransferImportSpec` | default-off receive-only legacy root ingress |
| `DidStore::{import_identity,import_device_identity,import_request_signing_identity}`, `IdentityImportSpec`, `DeviceIdentityImportSpec`, `RequestSigningIdentityImportSpec`, `ImportedPrivateKey`, `PrivateKeyEncoding` | default-off `MigrationPort` |
| `DidIdentity::{end_retirement,delete_revoked_key}` | Host/admin erasure workflow after document change |

### Diagnostics

| 0.1 item | 0.2 destination |
|---|---|
| `StoreManifest`, `RootKeyProviderBinding`, `RootKeyProviderKind`, `STORE_MANIFEST_SCHEMA_VERSION` | explicit redacted diagnostics/admin API only |
| `KeyMetadata`, `KeyOrigin`, `KeyState`, `RootCapabilityState` | reduced public descriptors plus full Host/diagnostic status |

### Engine internal or removed

| 0.1 item | 0.2 destination |
|---|---|
| `DidStore`, `DidIdentity` concrete Engine handles | crate-internal implementation behind Facade and Host SPI |
| `DidStore::{generation,manifest}` | Engine internal |
| `DidIdentity::reload` | Engine internal; Facade exposes recover/refresh semantics |
| `DidError` and all variants | Engine internal; mapped to stable `IdentityError` categories |
| `canonical_document_digest` | stateless `anp` utility or Facade internal |

No 0.1 root item remains unassigned: the default, `key-import`, and
`root-export` API baselines are covered by the four tables above.

## Node classification

The Node binding follows the same ownership rules:

- Provider-specific `DidStore` constructors become one manager configuration.
- list/create/open/delete and public identity reads become the default Facade.
- sign, Origin Proof, verification, and document change become semantic Facade
  operations.
- raw `ecdh`, header-returning HTTP methods, wrapped root transfer, convergence,
  enrollment, manifest, generation, and publication primitives leave the
  default root entry.
- sealed operations and exact HTTP header patches live only in the provider
  sub-entry and require a capability lease.
- imported private keys, exported Root Keys, and plaintext shared secrets are
  never Node outputs.

The generated `native.d.ts`, not a second handwritten declaration, becomes the
native source of truth. The wrapper declaration may only narrow it.

## AWiki production call sites

The following non-test files directly mention `anp_identity` at the audited
revision. Each file has a target operation; indirect call sites use the same
seam through `IdentitySigner`.

| File | Current responsibility | Target operation |
|---|---|---|
| `crates/im-core/src/internal/key_provider/mod.rs` | synchronous signing/ECDH/auth abstraction | async `IdentityCustody` and leased `IdentitySession` |
| `crates/im-core/src/internal/key_provider/anp_identity.rs` | Direct Engine adapter | Direct Facade/Host SPI adapter |
| `crates/im-core/src/internal/identity_custody.rs` | controller Store, create, enrollment, document lifecycle | manager plus enrollment/document/convergence Host workflows |
| `crates/im-core/src/internal/identity_custody_migration.rs` | legacy private-key migration | `MigrationPort` |
| `crates/im-core/src/internal/identity_generation.rs` | create request construction | Facade create DTO construction |
| `crates/im-core/src/internal/identity_handle_recovery_pending.rs` | recovery document transaction | `DocumentChangeSession` |
| `crates/im-core/src/internal/identity_legacy_upgrade.rs` | legacy enrollment signing | enrollment Host workflow |
| `crates/im-core/src/internal/identity_pending_upgrade.rs` | staged custody cutover | migration/adoption Host workflow |
| `crates/im-core/src/internal/identity_registration_pending.rs` | persisted registration reference | `IdentityRef` and public snapshot |
| `crates/im-core/src/internal/identity_root_import_completion.rs` | root import and promotion | Root-transfer Host workflow |
| `crates/im-core/src/internal/identity_root_transfer_runtime.rs` | authorized legacy root send/receive | Root-transfer Host workflow and sealed External transfer |
| `crates/im-core/src/core/mod.rs` | custody construction | injected Direct or External custody implementation |
| `crates/im-core/src/identity/registry.rs` | public identity projection | public snapshot DTO |
| `crates/awiki-deamon/src/identity_custody.rs` | independent daemon Store and convergence | manager plus convergence Host workflow |
| `crates/awiki-deamon/src/im_core_adapter.rs` | daemon signer wiring | Direct adapter construction |
| `crates/awiki-deamon/src/app_bridge/bootstrap.rs` | app bootstrap/readiness | manager/Host status |

High-frequency indirect calls are `sign` and `sign_origin_proof`. Conditional
HTTP authentication uses the same signer and AWiki-owned token state. ECDH is
session-establishment frequency, not per-message. Store, publication,
enrollment, migration, and Root Transfer operations are low-frequency.

## Direct golden behavior

The 0.1 Direct implementation remains the behavior oracle for Step 1. Its
reviewed fixtures and contract tests are:

- `anp` proof prepare/sign/complete equivalence tests for Origin Proof, object
  proof, document proof, legacy DID-WBA, and HTTP Message Signatures;
- `anp-identity` transaction, enrollment, root-transfer fixed-vector, import,
  recovery, lifecycle, and input-validation tests;
- `bindings/node/test/full-flow.test.cjs` for the current Node Direct flow;
- `awiki-im-core` custody, boundary, root-transfer, daemon, and migration
  tests, including the persisted-wire retry assertions.

Step 1 Facade and Direct Adapter tests must execute these same semantic cases
through both old Engine and new Facade paths before the old exports are
withdrawn. Randomized keys make signature bytes unsuitable as a repository
fixture; the golden contract is the exact prepared signing input, verified
proof/header result, public snapshot, and persisted state transition.

## Store and root-key evidence

At the audited revision:

- The controller Store is
  `<identity_root_dir>/.anp-identity`.
- With an IM Core identity vault, `open_controller_store` injects the exact
  `identity_vault` root key with key id
  `awiki-workspace-vault:<workspace_id>`. The controller key is not an
  additional HKDF derivative.
- Without an identity vault, controller custody uses the Store local-private-
  file provider.
- The daemon uses its own Store and derives an ANP Identity root key with HKDF;
  this is intentionally independent from controller custody.
- The current DSH AWiki plugin defaults to `$DSH_HOME/awiki/im-core` and loads
  `@awiki/im-core-node`. That runtime creates `vault/root-key.b64u`; there is no
  Host-owned `.host/vault-root-key` and there is no independent ANP Identity
  plugin yet.
- Provider binding is pinned by `manifest.json`. Opening a Store with a
  different binding fails closed; fallback is initialization-only.

These facts select same-key, fingerprint-verified provider adoption for v1.
They do not authorize rekey, production cutover, or deletion of the original
key source.

## Step 0 spike result

The async bridge spike is isolated at
`awiki-cli-rs2/spikes/identity-provider-bridge`. It executes a real Origin
Proof path as Rust prepare, one N-API ThreadsafeFunction call, TypeScript
provider signing through the current ANP Identity Node binding, then Rust
complete. Tests cover normal completion, pre-call lease revocation, in-flight
cancellation with a rejected late result, timeout, provider rejection, and
Host shutdown. The bridge carries only owned buffers and atomics across await;
it holds no Store lock, identity mutex, SQLite transaction, or synchronous
tokio wait.

The HPKE spike uses the single implementation in `anp::sealed_handoff`. Its
published fixture fixes the RFC 9180 suite, recipient key, encapsulated key,
ciphertext, info, AAD, and plaintext. The ANP Identity integration spike covers
both provider-to-IM-Core export and IM-Core-to-provider import. A prototype
HMAC token binds provider, parent lease, consumer, capability, Store, identity,
KID, operation, request, recipient-key digest, input digest, expiry, and nonce;
consumption is one-time. Replay and recipient/AAD substitution fail closed.

## Baseline verification

Before Step 1, the following local baselines are required:

- `cargo test --workspace --all-features` in `anp-identity`;
- `npm test` in `anp-identity/bindings/node`;
- `cargo test -p awiki-im-core --lib` in `awiki-cli-rs2`;
- `npm test -- --run` in `dsh-awiki`.

Remote system tests, real-device E2E, publishing, deployment, and production
Store changes are deliberately outside this Step 0 verification.

## Hot-path baseline

Criterion was run on an x86_64 Intel Xeon 6982P host with Rust 1.88.0 using
20 samples, a one-second warm-up, and a two-second measurement window. The
observed confidence intervals were:

| Operation | Time |
|---|---:|
| Store open, injected provider | 14.630–14.836 us |
| Request-key signature | 44.476–53.398 us |
| Origin Proof | 100.09–101.00 us |
| HTTP signature headers | 94.200–103.75 us |
| X25519 ECDH | 53.871–56.742 us |

These are local implementation baselines, not service-level targets. The
benchmark lives in `crates/anp-identity/benches/hot_paths.rs`; CI should compile
it, while performance regression runs may execute it on a controlled host.
