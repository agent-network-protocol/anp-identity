# anp-did

`anp-did` is the stateful E1 identity module for ANP. It builds and manages DID
documents, keeps managed private keys behind a logical Rust API/FFI boundary,
and exposes KID-scoped cryptographic operations without private-key export.

The v1 scope is intentionally limited to E1. It does not implement private-key
backup/export, root-provider rekey, root-control rotation, K1, PlainLegacy,
P-256 legacy E2EE, or browser WASM.

During development this workspace uses the sibling `../anp/rust` crate because
the coordinated ANP 0.9.4 registry release is pending PyPI credentials. Public
artifacts must replace the path dependency with the published minimum version.

See [`docs/boundary.md`](docs/boundary.md) for the security and ownership
boundary.
