# Identity management and ordinary plugin authorization

This implementation adds an optional DSH settings section, a shared approval overlay and a Host-owned persistent authorization boundary. It does not change the ANP identity, signature or HTTP wire protocols. Real native Desktop acceptance is a separate integration gate; package tests are not that evidence.

## Installation and authority

Load the existing service/provider patch. Configure `allowConsumers` with exact installed loader package identifiers and put ordinary plugins in `userConsumers`. Provider consumers cannot also be user consumers. Configure each plugin's exact HTTPS `httpAllowedOrigins`; the full ordinary capability bundle contains public identity reads, non-management signing, and Host-controlled authenticated HTTP.

Load the optional `./management-remote` Host plugin and `./client` browser contribution through the DSH loader. The browser uses `settings.section` and `shell.overlay`; it never imports the native provider. `./remote` describes only manager queries and decisions, not signing or transport APIs.

```ts
// Host configuration, not a value supplied by an ordinary request.
{
  allowConsumers: ['example-consumer', 'trusted-provider'],
  userConsumers: ['example-consumer'],
  allowProviderConsumers: ['trusted-provider'],
  httpAllowedOrigins: { 'example-consumer': ['https://api.example.com'] },
}
```

The Host resolves ordinary callers by the actual installed Cordis fiber and loader entry. Unknown, disabled and mismatched contexts fail closed. Normal user-mode proxies cannot acquire legacy or Provider leases by claiming a different allowed consumer string. The manager is acquired only from the root/service Host context, and ordinary facades do not contain manager methods. This is cooperative same-process policy, not a sandbox against a plugin that can monkey-patch the process or access other code's references.

## Ordinary consumer flow

```ts
import { bindIdentityClient } from '@agent-network-protocol/dsh-anp-identity/user-client'

const identity = bindIdentityClient(ctx)
const creation = await identity.requestCreateIdentity({
  requestId: 'stable-create-id',
  purpose: 'Create the identity used by this integration',
  parameters: { label: 'Work', handle: 'work.example', domain: 'example.com', path: '/agents/work' },
})
// Return immediately to the plugin's caller. Query this ID after notification.
const result = await identity.getCreateRequest(creation.id)
if (result.kind === 'create' && result.executionStatus === 'succeeded') {
  const access = await identity.requestAccess({
    requestId: 'stable-operation-id',
    purpose: 'Read my remote profile',
    identity: result.result!.reference,
    operation: { action: 'http', request: new Request('https://api.example.com/profile') },
  })
  // After the user approves, query the authoritative request again.
  const approved = await identity.getAccessRequest(access.id)
  if (approved.kind === 'access' && approved.status === 'approved' && approved.grantId) {
    const client = await identity.openAuthorizedIdentity(approved.grantId)
    await client.authenticatedHttp.dispatch(new Request('https://api.example.com/profile'), 'execution-id')
  }
}
```

Creation and use are separate decisions. Creation does not grant use, publish a document, register a Handle, or disclose keys. The optional `parameters.handle` is supplied by the requesting plugin, normalized using the existing catalog rules, frozen with the other creation parameters, and displayed read-only for confirmation. Approval reserves and persists it through the existing create intent and local uniqueness checks, including crash reconciliation. Omission remains compatible with older plugins; existing identities are not backfilled. The saved Handle is local metadata, not proof of registration or ownership on an external service. A request's purpose is plugin-declared text, not verified business intent.

The ordinary HTTP API does **not** accept a consumer transport callback: the Host dispatches exactly one attempt with manual redirects, validates the fixed operation, signs internally, and does not return signed outbound headers. The confirmation summary explicitly marks a query-bearing URL without storing query names or values; the fingerprint still binds the full URL and body. Permanent mode leads with the persistent full-use scope rather than a single-operation summary. Legacy Host APIs keep their previous transport contract. Raw non-management signatures can still be used outside the website list, as stated in the confirmation UI.

## Persistence and revocation

- Once is the default user choice and binds one immutable operation. The Host fingerprints actual normalized bytes; a consumer cannot supply the fingerprint. The ledger atomically consumes once admission before execution. Multiple objects/processes cannot create extra admissions. Native-key/parameter preflight failures do not consume; admitted failures or uncertain results never refund. An execution ID is a status-query key, not a replay instruction.
- Once expires unused after five minutes. A permanent grant lasts until revoked, but each opened object lasts five minutes. Permanent execution uses the approved capability/purpose/Origin snapshot intersected with current Host policy. Upgrades do not expand approval.
- The manager must echo the displayed `reviewedSnapshot` on access approval. A changed Host policy rejects that decision and requires a refreshed review; it cannot silently broaden a pending confirmation after restart.
- Revocation requires a confirmation showing the plugin and identity before the versioned manager call. A cancelled dialog makes no mutation, and externally invalidated grants close a stale confirmation. Revocation is persisted and checked on every operation and before HTTP transport. In-flight operations may already have executed; neither revocation nor identity deletion logs out external servers.
- Creation results keep stable operation provenance and deletion tombstones. Uncertain creation is reconciled with the native journal, never blindly recreated. Concurrent creation/recovery uses the same native-create lock.
- Processed creation records provide a read-only result/reconciliation action, not another creation approval. Startup completes previously fenced deletion tombstones only after confirming absence from both the native Store and catalog. Ordinary requests wait for Provider readiness before taking an authorization transaction, avoiding a startup lock inversion.
- Denial/revocation suppresses automatic re-prompting even with changed request IDs or wording. The manager's explicit history re-request creates a new record. Disable/uninstall events cancel pending requests; a transient frontend disconnect or ordinary Host restart does not.
- Public JSON inspection never fetches a remote document. Deletion is forbidden while effective ordinary grants or legacy/Host associations remain; unknown old Provider ownership fails conservatively.

## Upgrade and rollback

Stop old writers before upgrade. The existing catalog file is migrated in-place to schema `anp-identity-catalog/2`, with a synced `.before-v2` backup and preserved legacy associations. Backup publication uses temp-file sync, atomic rename and directory sync before the live catalog upgrade. Under the catalog lock, a validated live v1 catalog repairs partial/mismatched backups left by an interrupted older writer; corrupt live catalogs and already-v2 catalogs never replace that backup. Legacy associations do not become user grants. A separate non-secret authorization ledger contains requests, snapshots, operation fingerprints and execution status, never signature payloads, HTTP bodies, private keys or login tokens.

Old processes cannot parse the v2 catalog; mixed-version writes are unsupported. Rollback requires coordinated stopped writers and restoration of matching catalog, authorization and native state, not deletion of just one metadata file. Do not use corrupt-catalog recovery to downgrade a newer schema.

## Verification

Run `npm run verify` after building the matching native Node binding. Tests cover real native Store creation/signatures, caller context, Host HTTP, restart and deletion, plus cross-process ledger contention and UI component/controller behavior. The native binding requires the declared compatible sibling ANP Rust dependency; an older unrelated checkout is not an equivalent build baseline.

DSH native-window, live ordinary-consumer product integration, and real-service checks must be reported separately. No publication, Handle registration, key lifecycle or recovery controls are added to this MVP.
# Local presentation integration

The optional `settings.nav.icon` contribution provides a contact-card glyph only for the settings menu. Identity list entries remain text-only. The shell owns that root-scoped list slot; ANP registers the glyph under `anp-identity`, matching its settings-section id. Older shells without the slot continue to render the page with their default navigation glyph. This presentation extension does not grant identity access or alter protocol behavior.
