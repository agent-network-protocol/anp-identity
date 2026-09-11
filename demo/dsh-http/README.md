# Ordinary DSH plugin → identity approval → signed HTTP

This example contains a real ordinary DSH plugin, a settings page, and an independent local HTTPS verifier. No model API key is needed. The plugin uses only `bindIdentityClient`; it does not acquire a manager/Provider lease or receive private keys.

## Prerequisites and build

- Node.js 22.19+ (or 24+), npm, OpenSSL with `req -addext`, and Rust 1.88+ if building the native binding.
- This repository's matching native binding. The workspace currently requires the compatible `anp` Rust checkout at `../anp/rust` (see root `Cargo.toml`); an arbitrary older checkout is not equivalent.
- For the interactive page, a DSH CLI/host with web settings support compatible with `0.1.5-rc.1`, Cordis `4.0.2`, and Loader `1.0.3`. This is a source example, not a standalone Electron distribution.

From the repository root:

```sh
npm --prefix bindings/node ci
npm --prefix bindings/node run build
npm --prefix packages/dsh-anp-identity ci --legacy-peer-deps
npm --prefix packages/dsh-anp-identity run verify
cd demo/dsh-http
node build.mjs
node setup.mjs
```

`setup.mjs` generates a local seven-day TLS certificate and a random enrollment control token. It retains existing configuration. Set `ANP_DEMO_PORT=19444` on the **first** setup to avoid a port conflict (default: 19443). It does not install a system certificate or disable TLS checks. Build outputs and the whole `runtime/` directory are ignored by Git.

## Run the verifier

In a dedicated terminal, from `demo/dsh-http`:

```sh
node server/index.mjs
```

The server listens only on `127.0.0.1`. Keep it running for both the interactive demo and regression tests.

## Run the interactive plugin

From `demo/dsh-http`, with the compatible `dsh` command on PATH:

```sh
node prepare-host.mjs
npm --prefix runtime/dsh-home/profiles/anp-demo install --legacy-peer-deps --install-links
node run-host.mjs
```

Open the web address printed by DSH and choose **设置 → 签名演示**. `ANP_DEMO_DSH_BIN` may point to a different compatible DSH executable. The helper selects only its generated `anp-demo` profile, stores identities under `runtime/identity-state`, and trusts the demo CA only in the child process. It does not install or launch Desktop. If another DSH owns the web port, stop that test host or configure a separate port using your host's supported configuration.

The profile is generated with checkout-relative local package sources, not published substitutes. After rebuilding, reinstall the local packages if your package manager copied rather than linked them. Do not point these helpers at a daily-use profile. For a native Desktop host, install the same three local packages (native binding, identity plugin, demo plugin) in a separate profile and supply the environment shown in `run-host.mjs`; Desktop profile selection remains the host's responsibility.

### Acceptance steps

1. Click **开始演示：申请创建身份**. The plugin supplies a unique `demo-<UUID>` Handle alongside the name/domain/path. Check it in the read-only creation popup and confirm; the same Handle appears in identity details. The displayed domain/path build a DID; this does **not** publish a document or register/verify the Handle on an external service. Old demo identities without a Handle remain unchanged.
2. Approve the separate public-document read request with **单次授权**. The plugin enrolls only the public document at the controlled local server.
3. Click **授权并发送签名请求** and approve the exact `POST /hello` request. The Host signs and dispatches it; the server should return **HTTP 200** with `verified: true`.
4. Expand the result to inspect the headers **received by the demo server**. This is server-side diagnostic disclosure, not an API returning reusable outbound headers to an ordinary plugin.
5. Within five minutes, click **试试篡改正文 / 签名 / 重放**. All three checks should be rejected. This button runs verifier checks on the last received request; the regression tests below also send the negative cases over real HTTPS.
6. Try **永久授权** (until revoked). The MVP grants all ordinary identity-use permissions, so a permanent read approval also permits subsequent allowed HTTP operations. The UI explains this; individual capability selection is intentionally absent. Revoke through **身份 → 你授权的插件** and confirm further use fails.

Creation and use are separate approvals. Each once grant admits one exact operation, including on failure; no automatic retry bypasses consent. Re-running the demo creates another test identity and never deletes old ones. The plugin and server enrollment tables are in memory: restart and begin a new demo when needed.

## Regression tests

With the matching native binding built and the verifier running:

```sh
node --test test/*.test.mjs
```

Coverage includes an actual native E1/Ed25519 signature crossing verified HTTPS, HTTP 200, body/signature tampering, replay, expiration, missing signatures, protected enrollment, immutable public-document pinning, and malformed frontend remote results. Tests use a temporary native Store and clean it up. They update the server's last request; send a fresh request from the page before demonstrating its negative checks again.

Package/UI tests are not evidence of a fresh-machine install or native-window acceptance. The source demo's creation → once approval → real HTTP 200 flow was exercised in an isolated native Desktop on 2026-09-11; the portable CLI helpers are separate integration steps.

## Trust boundaries and limitations

- The verifier pins locally enrolled public documents. It is **not** a public DID resolver, domain-ownership proof, publication service, or general production ANP verifier. It checks the demo's fixed Ed25519 HTTP format and target only, not every DID-document protocol proof.
- `/enroll` and `/checks` require a private local control token; browser Origin requests are rejected. Do not expose this server publicly.
- `runtime/config.json`, TLS keys, identity state, and the local-file root key are private development data. Do not share them. The explicit `local-file` provider is only for this isolated example; copying the state and root key enables offline decryption.
- Certificates expire after seven days. Stop the demo and move the old runtime directory aside before regenerating; that also starts a fresh profile and preserves the old data for deliberate cleanup.
- The contact-card settings-menu icon requires the optional DSH `settings.nav.icon` shell extension. Older hosts keep their default menu glyph; identity list rows intentionally have no icons. That DSH shell change is outside this repository.
- No ANP wire protocol change, production deployment, registry publication, or external-server logout is performed.

## Source map

- `plugin/src/index.ts`: ordinary consumer creation, authorization and dispatch.
- `plugin/src/client.tsx`: interactive settings page.
- `server/verifier.mjs`: independent signature and replay checks.
- `server/index.mjs`: real TLS endpoints and bounded request handling.
- `test/`: native HTTPS and frontend-result regressions.
