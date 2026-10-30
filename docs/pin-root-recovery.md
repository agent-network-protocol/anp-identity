# Rust PIN root custody contract

Status: implemented Rust API contract, 2026-10-30. This document owns custody;
Realm HTTP authorization, receipt verification and encrypted backup packaging
remain owned by Core and User Service. End-to-end acceptance is separate.

## Narrow permission

The default-off `pin-recovery` feature includes `key-import` and `root-export`.
It permits only single managed Ed25519 RootControl backup and operation-bound
recovery. There is no Node or Dart private-key export. Root inputs and outputs
are owned `Zeroizing<Vec<u8>>` PKCS#8 DER; their containers implement neither
Debug nor serde. User presence is required for export, ingress and signing.
The host encrypts the export immediately and never logs or journals plaintext.
The existing legacy transfer permission remains scoped to RootKeyEnvelopeV1.

## Public Rust API

All names below are in `anp_identity::host`. The source definitions in
`crates/anp-identity/src/host/pin_recovery.rs` are the exact Rust DTO contract.

`PinRootBackupPort` on `ManagedIdentity` exposes:

- `pin_root_generation() -> IdentityResult<u64>`: current local CAS generation.
- `export_root_for_pin_backup(PinRootBackupRequest) -> IdentityResult<PinRootBackup>`.
  Request fields: `expected_generation`, `root_kid`, `user_presence_confirmed`.
  Output exposes `as_pkcs8_der() -> &[u8]` and public fields `root_kid`,
  `root_public_key_multibase`, `generation`.
- `sign_pin_recovery_intent(PinBackupIntentRequest) -> IdentityResult<String>`.
  This is the active-identity overload of the narrow signing capability.
  Request fields: `expected_generation`, `binding`, `purpose: PinBackupPurpose`,
  `expected_intent: Value`, `challenge: PinRecoveryChallenge`,
  `user_presence_confirmed`. Purpose is only `Authorize` or `BackupCommit`.
  Core builds expected_intent from authenticated operation state rather than
  blindly copying the server challenge. Authorize permits no package, version
  or receipts; BackupCommit requires a package, version, three unique registered
  receipts and at least two unique verified receipts. Both are enable-only and
  reject device candidate fields. Return value is the root compact JWS.

`PinRootRecoveryPort` on `IdentityManager` exposes
`begin_pin_root_recovery(BeginPinRootRecoveryRequest)
-> IdentityResult<PinRootRecoverySession>`.
Request fields: `binding`, `remote: VerifiedRemoteDocument`,
`root_key: Option<Zeroizing<Vec<u8>>>`, `profiles: Vec<String>`,
`device_label: String`, `user_presence_confirmed`.
Root input is required initially; None resumes the exact persisted binding.
The provider generates a random device ID, Ed25519 signing key and X25519
agreement key once. A different target, DPoP key, label or profiles cannot reuse
this pending. Submitting the PIN explicitly can supply ingress presence; final
device submission requires its own confirmation.

`PinRootRecoverySession::proposal() -> &PinRecoveryProposal` returns `identity`,
`binding`, `enrollment: EnrollmentProposal`, `device_proposal: Value`,
`generation`, `phase`. `device_proposal` is the exact Realm DeviceProposal JSON
including the generated public JWKs and device label; hash its JCS bytes.

`PinRootRecoverySession::sign_pin_recovery_intent(PinRecoverySignRequest)
-> IdentityResult<PinRecoverySignedIntent>` takes `expected_generation`,
`challenge`, `remote` (current trusted base), `candidate_document`, and
`user_presence_confirmed`. It permits exactly the addition of the generated
keys/device and preserves the other document fields except proof. It returns
`challenge`, `root_proof`, `device_proof`, `signed_document`, and `generation`.
Signing persists PublicationUncertain before releasing either proof.

`PinRootRecoverySession::complete_pin_root_recovery(PinRecoveryCompletion)
-> IdentityResult<Option<ManagedIdentity>>` takes `expected_generation`,
`binding`, `challenge_id`, `remote`, `outcome: PinRecoveryRemoteOutcome`.
Committed returns Some(identity), atomically enabling all three keys only when
the verified remote document exactly equals the persisted signed candidate and
both checkpoint counters advance. Identical completion can be retried.
NotCommitted returns None and moves the same device back to Prepared only when
the verified base is unchanged or advances with the same root and without this
new device or its keys. Concurrent sibling updates are preserved. Core must
authenticate operation status and prove
the old challenge cannot subsequently commit: after its expiration, a locked
status query observes any earlier commit; or a replacement challenge invalidates
the old exact payload. A momentary uncommitted status is insufficient.

`PinRootRecoverySession::cancel_pin_root_recovery(PinRecoveryCancelRequest)
-> IdentityResult<()>` is the cancellation companion to the four capabilities.
The request contains `expected_generation` and the exact `binding`. It only
removes this identity's three managed pending keys when the persisted phase is
Prepared, identity ID/generation/binding match, and no other local transition
exists. It reuses the namespace deletion journal and crash recovery; retrying a
completed deletion is safe, while a replacement identity at the same DID is
preserved. PublicationUncertain and Active cannot use this entrypoint. Core
cancels the remote operation first and reconciles any uncertain commit before
local deletion. Beginning a later operation refreshes the manager registry and
performs a new creation CAS, so cancellation does not leave a stale-manager trap.

## Binding, wire proofs and checkpoints

`PinRecoveryBinding` has required strings `operation_id`, `account_user_id`,
`target_id`, `handle`, `did`, `domain`, `binding_generation`, `recovery_id`,
`slot_id`, `op_jkt`, `root_kid`, `root_public_key_multibase`, `config_hash`,
`audience`; `backup_epoch: u64`; and `encrypted_package_hash: Option<String>`.
Binding generation is a canonical decimal String of up to 255 digits, never a
u64. Package hash is None before backup upload and required for recovery.
Core obtains binding from authenticated single-target authorization and verified
recovery receipts. Custody validates root bytes against that binding and the
trusted document; it does not verify PST, Realm receipts or control-plane JWTs.

`PinRecoveryChallenge` has `payload: Value` and `intent: Value`, both strictly
checked against the required Realm Docs/02 schemas and local binding. The
payload's `intent_hash` is base64url SHA256(JCS(intent)). Both compact JWS proofs
sign **JCS(payload)**, not intent or a separate domain-prefixed message.
The protected header is exactly `alg: EdDSA`, `kid` of the signing key, and
`typ: awiki-root-authorization+jwt` or `awiki-device-possession+jwt`.
The device/root proofs have identical payload bytes. Only the specified
purpose, operation, audience, DID/root, epoch/slot, DPoP key, binding generation,
checkpoint and exact candidate/proposal hashes can be signed. Challenges have
at most 300 seconds validity. Schema checks precede any signature: operation,
recovery, challenge and receipt IDs use UUID syntax; slots use `rs_` plus a
43-character base64url encoding of 32 bytes; registration versions are exactly
32 lowercase hexadecimal characters; hashes, thumbprints and nonces encode 32
bytes. Required/nullable types, positive counters, decimal generation, string
bounds, receipt uniqueness/count and unknown fields are checked explicitly.
A valid intent hash does not authorize malformed intent fields. No generic root
signing endpoint is introduced.

Custody checkpoints retain `sha256:` plus base64url SHA256(JCS(full document)),
including proof. Realm `document_digest` is that value without the prefix.
`candidate_document_digest` is base64url SHA256(JCS(document without its top-level
proof)). These digest forms are not interchangeable. Device signing method is
Multikey, agreement method is X25519KeyAgreementKey2019; both use multibase.

## State and encrypted persistence

Prepared -> PublicationUncertain -> Active. Only exact authoritative
NotCommitted reconciliation allows PublicationUncertain -> Prepared. A new
challenge can then use a newer trusted base with the same generated device.
Unknown status never authorizes deletion, abort, another device or activation.
A later successful V4 can instead enter terminal SupersededByV4 under the narrow
unprojected-custody evidence and scope described below; this does not reinterpret
the earlier unknown device submission as NotCommitted.

All three keys are sealed by the existing keystore. The existing creation
journal, cross-process exclusive lock, generation CAS and crash cleanup stage
keys and pending metadata together. The pending root is inaccessible to ordinary
signing, legacy pending-root APIs, generic enrollment signing/adoption and
normal activation. Namespace deletion cannot bypass uncertain reconciliation,
including with discard_pending_changes. Completed identities use existing
normal signing, document updates, authentication and root management.

Core's wrapping key, DPoP key and registration payloads remain in Core's Vault;
this API is not a general secret store. No legacy transfer evidence is fabricated.

## Verification ownership

Owning Rust unit tests cover key matching, export confirmation/CAS, sealed
pending, restart idempotency, JWS bytes/signatures, candidate tampering, restricted
signing, exact committed checkpoints, uncertain deletion and reconciliation.
System Test and Linux App acceptance remain owned by the integration plan.

## S4: exact V4 supersession of unprojected PIN custody

Status: approved and implemented on 2026-10-31. Existing IdentityTransitionOutcome::Committed only
records publication of a transition; it does not revoke the predecessor's
custody. The Prepared-only PIN cancellation API cannot represent an uncertain
PIN device commit that may have succeeded before V4 retired the old binding.
Neither an ordinary binding change nor a fabricated NotCommitted observation
is sufficient authority.

One Rust-only companion method is available on IdentityManager:

```rust
fn retire_pin_root_recovery_after_v4(
    &mut self,
    request: PinRecoveryV4RetirementRequest,
) -> IdentityResult<PinRecoveryV4RetirementOutcome>;

struct PinRecoveryV4RetirementRequest {
    identity: IdentityRef,
    expected_generation: u64,
    binding: PinRecoveryBinding,
    scope: PinRecoveryV4RetirementScope,
    evidence: VerifiedPinRecoveryV4Supersession,
}

enum PinRecoveryV4RetirementScope {
    UnprojectedPinRecovery {
        never_projected: bool,
        absent_from_previous_custody: bool,
    },
}

struct VerifiedPinRecoveryV4Supersession {
    v4_operation_id: String,
    v4_intent_hash: String,
    account_user_id: String,
    full_handle: String,
    previous_did: String,
    previous_binding_generation: String,
    successor_did: String,
    successor_binding_generation: String,
    committed_checkpoint: HostDocumentCheckpoint,
    current_binding: PinRecoveryCurrentBinding,
    current_document: VerifiedRemoteDocument,
}

struct PinRecoveryCurrentBinding {
    full_handle: String,
    did: String,
    binding_generation: String,
}

struct PinRecoveryV4RetirementOutcome {
    identity: IdentityRef,
    generation: u64,
}
```

Both scope assertions must be true. Core must hold its owner/operation lock
while proving that this exact reference is absent from current and historical
projections and all previous_custody retention records. If Core cannot prove
that scope, custody is preserved. ANP Identity does not have access to Core's
projection databases and treats this as an explicit verified-host attestation.
A PIN-origin identity that was ever projected or used remains governed by the
existing V4 historical-custody retention policy and cannot use this cleanup.

These are verified-host evidence, analogous to VerifiedRemoteDocument, not new
network credentials. Core constructs them only after checking its durable V4
RecoveryIntentV4, successful RecoveryRemoteResultV4 and exact initiator transition
marker, then independently checking the current authoritative Handle binding.
The result must be `recovered`, match the intent/operation/contract/account/Handle,
and name the same successor. An incomplete or superseded V4 does not qualify.
The V4 intent hash is the existing `sha256:`-prefixed digest; no second V4 wire
schema, JWT, OTP, grant or private material crosses this custody API. The V4
operation ID preserves its existing 1–128 Unicode-scalar, no-whitespace/C0/DEL
contract (including recover_v4_<base64url>); it is not required to be a UUID.
The old PIN operation ID keeps the separate Realm UUID constraint. Provider
code does not infer successful V4 from a changed DID, a failed PIN operation or a
predecessor publication journal alone.

Under the existing cross-process exclusive lock and identity generation CAS,
ANP Identity checks:

- Exact store/identity ID, old DID and complete persisted PinRecoveryBinding,
  including old PIN operation, target, root, slot, DPoP key and binding generation.
- V4 account/Handle/previous DID/previous generation equal that old binding;
  successor DID differs and its canonical decimal generation strictly advances.
- Current authoritative Handle/DID/generation equal the V4 successor fields.
  The successor document passes existing active E1/WBA proof and RootControl
  validation and names a different Ed25519 root. Its checkpoint equals or advances the V4 committed checkpoint;
  the same document version cannot carry a different full-document digest.
- The namespace is specifically PIN-origin Prepared, PublicationUncertain or
  Active, has its expected three managed keys, and has no unrelated pending
  document/root transfer or identity-transition publication. All three phases
  require the unprojected scope assertions. Active is included only for the
  crash window after custody activation but before Core ever saved an identity
  projection; ordinary active identities and historical retained custody are
  excluded even if they originally came from PIN recovery.

The method first persists a terminal `SupersededByV4` PIN phase and public
supersession evidence, marks the identity/key authority Revoked, removes pending
enrollment authority and sets RootCapability to Absent. It uses the existing
state-transition journal and never activates the old root. Subsequent old sign,
completion, resume-to-active and pending promotion paths must reject. The public
outcome returns only the old exact reference and resulting local generation.
Repeating the same immutable V4 claim and scope is idempotent using the original
or resulting generation. Its freshly verified successor document may advance,
while the committed checkpoint and current binding stay bound to that claim.
A changed binding or V4 operation cannot claim a previous isolation.

Core durably records its exact cleanup claim before invoking this method. After
isolation it may use the existing ordinary delete on the returned old reference;
no generic-delete permission is widened. A deletion failure leaves an inert,
encrypted namespace and retryable cleanup, not usable old authority. Core only
removes the matching PIN Vault operation and secret state after custody cleanup
is confirmed. The claim survives a crash between isolation, namespace deletion
and Vault deletion, and must preserve any replacement identity or unrelated
operation. Successor activation does not depend on resurrecting or exporting
the old root, and a failed old-namespace cleanup does not undo successful V4.

Required focused tests cover all three PIN-origin phases, an old PIN operation
that remotely committed before V4, exact cross-account/Handle/DID/generation
rejections, active non-PIN rejection, concurrent old completion versus isolation,
state-transition crash recovery, identical retry and deletion/Vault failure
replay. This extension does not declare historical PIN device commit failure;
it records that a later verified V4 permanently superseded that authority.
