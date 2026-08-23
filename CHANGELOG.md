# Changelog

All notable changes to ANP Identity are documented here.

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
