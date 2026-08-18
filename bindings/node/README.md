# @agent-network-protocol/anp-did

Node.js bindings for the E1-only `anp-did` Rust crate. All APIs that can touch
the filesystem or OS keyring are asynchronous.

Private DID keys are never returned by the JavaScript API. This is a logical
API/FFI boundary, not process isolation: the native addon shares an address
space with Node.js and is not an HSM or independent KMS.

`initializeInjected()` and `openInjected()` consume and overwrite their
32-byte root-key `Buffer`, including validation-error paths. Pass a disposable
Buffer and do not expect to reuse it after the call.

`ecdh()` returns a raw X25519 result as a `Buffer`. It is not a session key. Use
a domain-separated HKDF immediately, then overwrite the Buffer. JavaScript
copies are not covered by Rust zeroization.

The v1 package is verified on the build host platform. Build scripts list Linux,
macOS, and Windows x64/arm64 targets, but a platform becomes supported only
after its native CI build passes.
