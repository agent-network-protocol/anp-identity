# Local ordinary-consumer acceptance fixture

This private test package is not part of the published identity plugin. Load it as a real Cordis Loader installation named **`anp-identity-runtime-consumer`** in an isolated DSH profile. It injects only `anpIdentity` and calls `bindIdentityClient(ctx)`. There is no manager, Provider, root lease, private-key API, UI approval route, arbitrary signing payload, arbitrary HTTP proxy or code execution endpoint.

## Host setup

1. Build/stage the exact candidate identity plugin and native binding in the isolated profile's package resolution. Staging may use root-coordinated test-only metadata versions; do not modify this fixture's imports to bypass the normal Loader resolution.
2. Add `anp-identity-runtime-consumer` to identity Host `allowConsumers` and `userConsumers`, never to `allowProviderConsumers`.
3. Load this package and its `cordis.patch.yml`. Set `ANP_IDENTITY_TEST_CONTROL_PATH` to an absolute file inside the isolated acceptance evidence/state directory. No production profile or existing identity Store is permitted.
4. Startup writes a mode-0600 descriptor containing a fresh random control nonce, ephemeral loopback port, PID and resolved package paths. Never print or publish the descriptor; its nonce is a local test-control credential. It is removed on ordinary plugin disposal. Restart changes the nonce and port; the CLI rereads them for every command.

`GET /status` provides public evidence for both `import.meta.resolve('@agent-network-protocol/dsh-anp-identity/user-client')` and `import.meta.resolve('@agent-network-protocol/anp-identity/provider')`. The latter is resolution-only: this ordinary consumer never imports or calls Provider APIs. `status: listening` in the descriptor proves only the control listener was started, not native Provider readiness or successful acceptance.

## Controller protocol

The listener binds only `127.0.0.1` on a random port. Every request needs `X-Anp-Test-Control` from the private descriptor. It checks the exact loopback Host, rejects all browser Origin headers, publishes no CORS headers and has no Browser/Remote route. POST requires JSON, has a 16 KiB cap and rejects unexpected fields. Request IDs and execution IDs are caller-chosen stable public identifiers, not control credentials. UI approvals must be performed through the actual DSH identity manager.

Use the provided CLI so the nonce is never embedded in shell history or output:

```sh
node control.mjs /absolute/isolated/control.json GET /status
node control.mjs /absolute/isolated/control.json POST /create '{"requestId":"runtime-create-1"}'
node control.mjs /absolute/isolated/control.json GET '/request/create?id=runtime-create-1'
```

| Endpoint | Input | Public result |
| --- | --- | --- |
| `POST /create` | `{requestId}` | Ordinary creation request; fixed name/domain/path, no identity until real UI approval |
| `GET /request/create?id=...` | Request ID | Current own creation request, including minimum result/reference when successful |
| `POST /read-access` | `{requestId,reference}` | Own access request with frozen public-read operation; no preferred authorization mode |
| `POST /sign-access` | `{requestId,reference}` | Own access request with fixed authentication payload and `#request` key |
| `GET /request/access?id=...` | Request ID | Current own access request; after UI approval includes grant ID/mode |
| `POST /executeRead` | `{grantId,executionId}` | Real authorized public document, reference and active key descriptors |
| `POST /executeSign` | `{grantId,executionId,reference}` | Real signature byte count/key ID and independent verification boolean; signature bytes are not returned |
| `GET /execution?id=...` | Execution ID | Own durable execution status |
| `GET /status` | None | Public resolution evidence and retained-object counts; no control nonce |

`reference` is the exact `{storeId,identityId,did}` returned by the ordinary creation result, not a Handle/name lookup. Creation uses `Runtime acceptance identity`, `example.com`, `/anp-identity/runtime-acceptance`; this does not publish to that domain.

All failures have non-success HTTP status and a bounded error code only; no exception message, stack, nonce or native internals are returned. Creation errors can also be represented by the ordinary request's durable execution status, so do not equate HTTP 200 with completed identity creation.

## Acceptance sequence

1. Submit creation. Observe its pending UI request. Before allowing creation, the UI must show no new identity and the ordinary result must contain no created reference.
2. Approve creation in the real UI. Query the same request ID; save its exact reference. Confirm no use grant was created and the manager still exposes the new grant-free identity.
3. Submit `/read-access`. In the UI choose **once** and approve. Query the grant. Execute read with `executionId=once-read-1`: succeeds and caches that legitimately read public document in fixture memory. Execute again using a new execution ID and the same grant: must fail. The cache is public verification data only, not a second service read or grant.
4. Submit `/sign-access`, choose once in the UI, approve and execute with `executionId=once-sign-1`. Expect `signatureBytes:64`, `verified:true`, `verification:node_crypto_ed25519`. This independently verifies the fixed authentication bytes with Node crypto and the previously authorized public document. It does not call native verify or read another document implicitly. Repeat with a new execution ID: must fail.
5. Submit another read/sign access request and explicitly choose **permanent** in the UI. Execute successfully, then restart the isolated DSH runtime. Re-query the same ordinary access request and use its saved grant ID. A fresh object must reopen successfully; the permanent grant, not the expired in-memory object, survives.
6. After restart, perform an explicit authorized read before signing if independent verification is required again. With no cached public document, signing returns `verified:null`, `verification:public_document_not_read`; this must never be recorded as verification PASS.
7. With a permanent object retained by a successful operation, revoke its grant in the real UI. Execute again using the same grant and a new execution ID: the fixture deliberately reuses its retained object, and the call must fail. Reusing objects demonstrates the revocation fence, rather than only testing failed acquisition of a new object.

Retained objects expire according to the production lease rules; the fixture does not silently refresh them. Run the old-object revocation check within the five-minute object lifetime. Restart clears only fixture memory and regenerates its control credential; it must not clear the isolated identity Store. A same-execution-ID retry is status inspection, not authorization to redo a consumed operation.

No runtime has been launched by authoring this fixture. Syntax validation and these instructions are not actual DSH UI, native-window or end-to-end acceptance evidence.
