# Changelog

All notable changes to ANP Identity are documented here.

## 0.2.0-rc.1 (DSH plugin) — 2026-09-12

- Add identity management with plugin-supplied Handles, DID document inspection,
  creation confirmation, request inbox, permission details and revocation.
- Separate creation from identity-use approval; support single-operation and
  persistent revocable grants with an explicit full-permission MVP disclosure.
- Add catalog v2 migration and recovery, Host-identity exclusion, and short
  authorization ledger transactions with generation/CAS revalidation.
- Include a documented, isolated signed-HTTPS demo in the source repository.
- Preserve release/0815 Host identity-transition and deletion-recovery APIs,
  AWiki defaults, and the published native runtime dependency at 0.2.2.
- Publish this candidate under the npm `next` tag; do not advance `latest`.

### Upgrade and security limitations

- Stop old catalog writers before catalog v2 migration. Follow V7-MANAGEMENT.md
  for coordinated rollback; changing npm tags alone does not roll back storage.
- Review F2 remains unresolved: same-process root-service/gateway management
  access is not a security boundary against malicious plugins. This candidate
  does not include DSH Host-side authentication changes.
- Identity creation does not publish a DID document, register a Handle, or
  automatically grant identity use. Native and Rust packages are not re-released.

## 0.2.2 (Rust), 0.2.1 (Node), 0.1.1 (DSH Host) — 2026-09-08

### Fixed

- Refresh the Store registry generation before identity namespace deletion so
  recovery or another Store view cannot leave a valid local deletion stuck on
  a stale compare-and-swap generation.
- Make Host Provider deletion discard unpublished local mutation state and let
  DSH resume deletion tombstones or close an operation whose native delete
  succeeded before its response was lost.

## 0.2.0 — first public API release

`0.2.0` establishes the supported application surface before the project is
published. There is no previously released ANP Identity Store or public API to
upgrade.

### Public Facade

- Added `IdentityManager`, `ManagedIdentity`, and
  `DocumentChangeSession` as the stable Rust and Node application API.
- Added purpose-scoped signing and verification, Origin Proof signing, public
  identity snapshots, multi-DID management, and explicit publication
  reconciliation.
- Moved privileged HTTP signing, enrollment, key agreement, migration, and Root
  Transfer workflows into `anp_identity::host` and the separate Node Provider
  entry.

### Boundary

- Removed the Store engine, raw lifecycle records, manifests, generations, and
  raw ECDH from the public application API.
- Kept `key-import` and plaintext legacy Root export behind default-off Rust
  features. Legacy Root export still requires explicit user confirmation.
- Added sealed HPKE handoff for secrets that must cross the DSH TypeScript
  bridge.

### Node and DSH

- Added asynchronous Facade bindings and a capability-scoped trusted Provider
  entry.
- Added declaration and package-surface checks that prevent Engine APIs or raw
  secret operations from leaking through the default Node entry.

### First-release storage policy

ANP Identity `0.2.0` initializes and owns a fresh Store. It does not implement
adoption or in-place conversion of an older ANP Identity Store. Hosts migrating
from their own legacy key storage use the explicit one-way Host migration
workflow.
