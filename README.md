# anp-did

`anp-did` is the stateful E1 identity module for ANP. It builds and manages DID
documents, keeps managed private keys behind a logical Rust API/FFI boundary,
and exposes KID-scoped cryptographic operations without private-key export.

The v1 scope is intentionally limited to E1. It does not implement private-key
backup/export, root-provider rekey, root-control rotation, K1, PlainLegacy,
P-256 legacy E2EE, or browser WASM.

During development this workspace uses the sibling `../anp/rust` crate because
the coordinated ANP 0.9.4 registry release is pending PyPI credentials. Public
artifacts declare version 0.9.4, but standalone clones still require the sibling
path until that coordinated release is published and the development path can
be removed.

Injected root keys must be uniformly random 32-byte values, not passwords or
other low-entropy input. `initialize_env` / `open_env` read the same material as
unpadded base64url from a named environment variable. Store provider metadata is
available through `DidStore::manifest()`.

Concurrent writers use optimistic generation checks. After `Conflict`, call
`DidStore::reload()` or `DidIdentity::reload()` before inspecting the new
committed state and deciding whether to retry. Explicit crypto-erasure keeps a
key `Revoked` and records `KeyMetadata::material_erased = true`; authorization
state and local key-material state are intentionally separate.

See [`docs/boundary.md`](docs/boundary.md) for the security and ownership
boundary.
