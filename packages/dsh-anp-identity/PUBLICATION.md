# Shared protocol identity and CIMD publication

The Host keeps all identity, Delegation and DPoP private keys in the local encrypted ANP Identity Store. The shared plugin owns permissions and publication state; the MCP and PAP adapters own their separate connection and Token state. Remote signers are unsupported.

## Explicit identity creation

`requestCreateIdentity` accepts `parameters.usage: 'protocol'` and `profile: 'e1' | 'web'`. The creation approval displays that purpose and method. Protocol E1 creates local root, device-signing and agreement keys; protocol Web creates only device-signing and agreement keys. Their Manifest advertises the exact identity-only `anp.core.binding.v1` and `anp.identity.discovery.v1` bundle. Registration authority and ready-admin status come from the server, never from that local Manifest. Protocol creation grants no use permission and does not expose raw DeviceSigning operations.

Omitting `usage` preserves ordinary E1 root/request-signing creation and its existing approval semantics. Existing identities and DIDs remain intact. An ordinary identity without a compatible registered Manifest cannot use the device-management driver. Adding a separate RequestSigning key to a protocol identity requires the existing authorized enrollment/document workflow; the protocol lease does not provide that capability.

## Registration and management

Trusted management Contexts call `registerLocalIdentity` and `configureManagedPublicationBackend`. Registration submits the locally produced public document through the real User Service `register` RPC. Web uses a distinct native `signWebRegistrationProof`, binding the complete normalized business projection, exact audience, operation id, Handle, account factors, bootstrap device and local document digest. The caller supplies a stable Web `registration_operation_id` and an explicit management audience. A returned Access Token is checked through the actual `device_registry_get`; the DID, local signing key, active admin role and management readiness must agree before the credential is retained.

`EncryptedManagementCredentialBroker` encrypts Device Access credentials with a fresh 32-byte Host key from its key resolver. It partitions by exact origin and identity, uses a cross-process lock and atomic fsynced replacement, and preserves mutation bodies for operation replay. No Token, proof, key or login function belongs in Browser configuration, ordinary catalog data or model tools.

The real publication driver resolves `document_id` through an independently authorized exact-device endpoint. It signs each management request through the native method allowlist and follows User Service's live Registry, auth-generation, nonce, body binding and CAS checks. Device Access is not treated as an ordinary account JWT. Public status remains readable without returning credentials.

DID changes use the existing authorized `device_document_update` or authentication-only `device_oauth_keys_update` path. E1 retains its root proof; Web uses the ready-admin device proof and cannot use ordinary service updates to enroll keys. Each candidate carries immutable native `baseEvidence`; its CAS values never come from a newer Registry. A changed remote checkpoint produces a conflict instead of overwriting another device's document. An uncertain publication reconciles the document and checkpoint from one authenticated resolve response.

## Device-bound callback relay

`createManagedPublicationDriver` exposes typed `execute` overloads only for `pap-callback-register` and `pap-callback-claim`. The Host installer returns the same restricted capability as `configureManagedPublicationBackend(...).callbackManagement`; it checks the installed management Context, native-provider generation and disposal before the request and before returning its result. The ordinary identity client, management Remote and model tools do not expose it.

Registration accepts only transaction/client/issuer/redirect identifiers, independent state/claim SHA-256 hashes and a bounded whole-second expiry. The client id and fixed HTTPS redirect must match the resolved identity and `/user-service/v1/pap-callback`. Its exact-device request uses the live Registry/checkpoint and the native `agent_client_pap_callback_register` proof. The encrypted operation ledger fixes the original request for response-loss recovery and rejects changed callback material under the same operation id.

Pickup accepts only a transaction id and canonical independent 32-byte claim secret. `agent_client_pap_callback_claim` binds the fixed device route and real DID, and successful pickup returns the raw private `{code, state, iss}` or `{error, state, iss}` business response. A successful OAuth error is not a management failure. Pickup results do not contain publisher DID/document fields and are never written to the local operation ledger or automatically retried. A lost successful pickup response is uncertain; neither C nor the relay reconstructs a second private result. Documented management failures such as `callback_not_ready` and `callback_claimed` remain stable codes without server text or callback data.


## Capability-driven V2 publication

`PublicationConfig.capabilities` contains explicit `mcpMachine`, `papSession` and `papAccount` values. `activeKid` selects an ES256 local key. HTTP maps these to the single snake_case schema: `schema_version`, `operation_id`, `expected_version`, `client_name`, `capabilities`, `signing_keys`, `active_kid` and `redirect_uris`. V1 legacy EdDSA records retain their original projection and do not gain V2 permissions.

MCP-only publication has `client_credentials`, `private_key_jwt`, ES256/JWKS, empty `response_types`, and no callback dependency. PAP Session adds no OAuth grant. PAP account requires an actual callback and adds `authorization_code`, `refresh_token` and `code`. The five profile names are derived from capabilities; they are not caller-selected independent values. V2 PAP account may separately declare an RFC 8252 loopback callback with exact `http://127.0.0.1:<port>/path` or `http://[::1]:<port>/path`. The declaration requires an explicit canonical port from 1 through 65535, a fixed nonempty path and no userinfo, query, fragment, whitespace, backslash, dot-segment or invalid percent encoding. Its bytes are preserved. V1 and all metadata/JWKS/resource URLs retain their HTTPS rules; MCP-only and Session-only profiles reject callbacks. OAuth Consumers may ignore only the loopback port when matching a redirect, retaining host/path equality. The fixed HTTPS relay is an independent lane and never a loopback failure fallback.

An absent OAuth key is first created locally and published through the authorized DID-key workflow. Only after that checkpoint does the coordinator prepare fixed metadata/JWKS bytes, publish the ANPCIMD digest/key binding, activate and read both public resources back byte-for-byte. Responses must match the selected profile, capabilities, key, algorithm and both independent public-material digests. A consumer receives a usable OAuth identity only after the complete checkpoint is confirmed.

Catalog schema v4 atomically backs up v1/v2/v3 before migration, preserves legacy bytes and grants, and rejects unsupported downgrade writers. The native Store's document digest remains distinct from the hexadecimal CIMD/JWKS response-byte digests and the RFC 7638 thumbprint.

## Preauthorized protocol leases

The Host explicitly configures `protocolPolicies`. Each policy fixes its consumer, identity, profiles, expiry, scope ceiling and exact issuer/resource sets. `publicTargets: true` is an explicit bounded approval for unfamiliar publicly discovered targets; it does not grant remote business permission. The policy owner is the fixed local identity Host owner. Policy changes reload the service and invalidate prior leases.

Only the configured installed Host discovery adapter may call `bindProtocolIdentityClient(ctx)` from `./protocol-client`. The bound Context is checked on registration, invocation and return. Its adapter validates public discovery over its protected network transport; C validates the evidence fields, expiry and policy scope, then creates opaque local target and signer objects. A consumer-supplied JSON flag is never accepted as discovery evidence. This same-process authority does not sandbox hostile code that already stole a trusted Context.

Leases bind publication key/version, policy generation and native-provider generation. They recheck those values before and after signing. An assertion uses the exact validated issuer, fixed published client id and selected key. OAuth leases do not expose raw authentication signing. Temporary Session and DPoP keys have separate purposes, C-minted scope/key references and native handles; restoring a persisted handle requires a fresh lease and actual native scope/purpose verification. Company and request endpoints are frozen from discovery, owner comes from the Host policy, and user/account scope comes from the trusted PAP adapter's bound records.

Each protocol lease check also reads the current native `StoreInfo.backendAvailable` fact after the public metadata await, then synchronously rechecks its original caller, provider generation and policy/target expiry. A false value rejects use with `provider_unavailable`; an absent availability field is `provider_incompatible`. D performs this check before using a cached Access Token as well as before physical resource/Token requests. Native private operations independently enforce availability for `os_keyring`; injected/local-file backends retain their existing custody semantics. An OS keyring unlock may restore an otherwise current lease without changing its grant or identity; disposal, expired policy and changed publication remain separate invalidations. This contract requires the matching native availability candidate. The historical e2c candidate's API v2 number alone does not provide it, and an already-open e2c Store does not automatically stop signing when its OS collection is locked.

General service `health()` also uses a short internal readonly native lease. A live false availability fact reports `status: unavailable` while retaining the independent catalog state. It checks the original Host and provider slot after the await and disposes the read lease. A legacy provider without the field retains its general structural health behavior; that compatibility does not satisfy the protocol lease handshake or promise signing availability.

## Validation

Owner unit/Loader/UI tests cover migration, approvals, revocation, publication recovery, independent grants and the protocol lease. `test/protocol-native.spec.ts` exercises real C authorization and real A ES256/PAP custody with independent signature verification; its local publication acceptance fixture is not User Service control-plane evidence.

`test/management-live.spec.ts` is an opt-in fixed local component contract. Set `DSH_IDENTITY_USER_SERVICE_SOURCE` to the B candidate and `DSH_IDENTITY_PYTHON` to its environment, then run `npx vitest run test/management-live.spec.ts`. The bridge uses actual production registration, factor verification, MySQL transactions, Registry, Device Access, management proofs and publication. Only external synthetic email delivery is substituted. One case creates E1 and Web identities consecutively in the same Store with explicit protocol approval and callback-free machine publication. A separate case performs actual PAP account publication, device-bound relay registration, public callback receipt, original-device one-shot pickup and replay denial. `test/helpers/managed-callback-fixture.ts` exports that real C/A/B setup to the PAP adapter component tests, without returning a native lease or management credential. This is not product E2E, System Test or deployment evidence.

## Fresh Host registration bootstrap

The optional `./protocol-bootstrap` plugin submits a stable `usage: protocol` creation request from its actual Loader-installed Context. It never approves that request. The existing `management-remote` accepts optional non-secret `registrationBootstrap` configuration; only its constructor-captured root management Context continues an approved, successfully created reference. The default bundle leaves this flow disabled and keeps the unconfigured manager compatible. The [first-stage patch](examples/fresh-bootstrap.cordis.patch.yml) contains deployment placeholders, not credentials. Retain existing approved consumers when adapting it.

The Host needs the matching local native API v2/ES256 candidate and the actual `@deepseek-ai/dsh-credentials@0.1.5-rc.2` record API with a writable protected provider. `credentials-local@0.1.5-rc.2` supplies owner-only file protection and a writer lock. Native Store custody remains independently configured, normally keyring without a silent file fallback. No AWiki messaging/Core credential is imported. Candidate provenance is separate from registry version numbers.

User Service must opt into the independent product. The client sends `X-AWiki-Client-Version: dsh-identity/1106/<version>` on its fixed-origin factor and management requests, reading version from the actual installed C package. It never borrows an AWiki version or accepts a version override from configuration. The server's `products.identity` entry defines the accepted release/version floor; an absent or disabled entry in an enforced deployment still rejects it. Deploy the new server implementation before its new policy file. Public server-info fields and an observe-only environment do not grant admission. C exposes only `client_upgrade_required`, without relaying server text or upgrade URLs.

The manager pins the approved reference's actual ready provider generation before factor work. It sends one Handle-bound activation email and polls the same full Handle/email target. The user completes User Service's normal email page and Turnstile verification; C never reads an activation token or automatically confirms it. The existing register/Registry checks must succeed before encrypted credential storage, driver installation, ES256 enrollment and publication. The controller cannot switch to a replacement provider. Original manager identity and provider generation are rechecked after native/key/body awaits, before physical HTTP, and before returning results.

Safe status phases are `awaiting_approval`, `awaiting_email_verification`, `registering`, `publishing`, `published`, `blocked` and `registration_uncertain`; a disposed controller reports `disposed`. Only phases, closed reasons and public identity/client references reach the manager UI. Mail-send and registration-start intents are durable before their physical requests. Restart does not resend an uncertain mail attempt or repeat a possibly committed registration. Cancellation cannot roll back a server transaction already sent; an unknown registration result requires management recovery.

Each stable bootstrap id owns its own broker directory. Its 32-byte master comes from real atomic owner-scoped Host credential records, not ENV, the identity Root Key, UI/model input or a fallback key file. Existing keys are not rewritten. A durable marker and matching journal protect an established key even before the first Device Access ciphertext exists. Missing used keys, bad records, readonly storage or lifecycle loss fail closed. Do not rename ids/request ids or delete state to force a retry; restore the matching credential record, broker and journal together. This Host provider's file protection is not an OS Secret Service guarantee.

### One-time protocol permission setup

`published` confirms registration/publication, not D/F authorization. Copy the safe `{storeId, identityId, did}` from the manager, add an explicit `protocolPolicies` entry and matching consumer configuration, then restart the Host. The new reference is unknown before creation, so this implementation does not create a guessed policy or an automatic policy template. This is identity/profile/scope setup, not an approval for every remote station. Keep an explicit absolute expiry unchanged across restart; never silently renew it with a fresh `Date.now()` expression.

For a machine connection, add `@deepseek-ai/dsh-mcp-client` to both `allowConsumers` and `userConsumers`, not `allowProviderConsumers`. Preserve the service's other fields and use this policy with the real copied reference and target URLs:

```json
{"id":"work-mcp","version":1,"consumer":"@deepseek-ai/dsh-mcp-client","owner":"@agent-network-protocol/dsh-anp-identity","identity":{"storeId":"COPIED_STORE_ID","identityId":"COPIED_IDENTITY_ID","did":"COPIED_DID"},"profiles":["mcp_machine"],"issuers":["https://issuer.example"],"resources":["https://resource.example/mcp"],"publicTargets":false,"scopes":["agent.self.read","catalog.read"],"expiresAt":1800000000000}
```

A matching actual Loader row is:

```yaml
- insert:
    - id: work-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      inject: ['anpIdentity', 'credentials']
      config:
        transport: streamable-http
        serverName: work
        url: https://resource.example/mcp
        authentication:
          mode: cimd-client-credentials
          connectionId: work-mcp
          identityRef: { storeId: COPIED_STORE_ID, identityId: COPIED_IDENTITY_ID, did: COPIED_DID }
          policyRef: work-mcp
          requestedScopes: [agent.self.read, catalog.read]
          issuer: https://issuer.example
          stateRoot: /home/dsh/.dsh/mcp-credentials
          encryptionKeyRef: EXISTING_PROTECTED_MCP_KEY
```

`EXISTING_PROTECTED_MCP_KEY` must already be a real Host credential reference with D's required 32-byte base64url key. Do not put a literal secret in the patch. D owns that separate token-store prerequisite and persistent connection-id/fence management. An administrator may explicitly choose `publicTargets: true` for unfamiliar public targets while retaining fixed profiles, scope ceilings and expiry; C never widens it. The remote AS independently decides admission and business permissions.

For PAP, first publish the chosen PAP capability. Configure a separate policy for exactly `@agentconnect/dsh-pap/plugin`, with `pap_session`/`pap_account` profiles and the intended Company/issuer/resource/scope ceiling. Its actual plugin configuration is `{enabled:true, identityRef:<copied reference>, policyRef:<configured id>, stateRoot:<private F directory>}`. F's manager and tools are separate canonical entries, not the signing consumer. A no-AS Session does not require a callback driver or account capability. Product account handoff selects only the published fixed HTTPS relay; the independent engine loopback lane is not its fallback.

### Target-bound PAP Host factory

`bindPapHostConsumer(actualInstalledContext)` accepts only the actual installed F plugin allowed by Host policy. `resolveBinding(reference, policyRef, profile)` reads an existing matching policy and current published identity, returning only the public binding and an optional matching HTTPS relay. It never invents a policy for a fresh reference. Status/tools cannot revive a disposed factory; explicit identity selection or reload must bind again and acquire fresh leases.

`callbackManagementFor({identityRef,policyRef,targetRef})` additionally requires C's current opaque account target from the same installed fiber. Issuer, resource, scopes, publication and provider/manager generations are checked around execution. The existing encrypted broker records public transaction-to-target metadata, and claim checks that binding before a physical request. Another Company/resource/scope cannot consume the transaction. The object exposes only register/claim and `dispose`, with no Native Provider, Device Access, general HTTP or arbitrary proof purpose. Private claim results are not cached or written to the operation journal.

The bootstrap registration configuration/journal remain fixed for a stable id; this MVP has no configuration-migration or uncertain-registration recovery UI. Current Linux component evidence does not claim other-platform broker permission handling or OS keyring auto-lock acceptance. The strict component runs production admission, email factors, SQL, Registry and proofs; only external SMTP delivery and exact Siteverify transport are captured, under a test-user control unavailable to C's fetch adapter. Real Loader tests cover scoped ordinary consumers; management and legacy Provider admission remain root-only, and direct ACP-style `ctx.plugin()` without a trusted installation entry is rejected.

The opt-in `test/registration-bootstrap-live.spec.ts` uses the actual Loader-installed manager, requester, native provider and registry credential provider. Its E1 cases cover missing/low-version admission, an incorrect email token hash, user confirmation, publication/readback and same-state restart without another email or registration. Two precise lifecycle cases close the real provider after an email-status body await and after a successful registration response: the first sends no further email/register request; the second retains `registration_uncertain` and sends no Registry request or credential write. It does not claim to undo the already committed remote registration. Run this component with `DSH_IDENTITY_USER_SERVICE_SOURCE=<strict B candidate> DSH_IDENTITY_PYTHON=<B Python>` and `node node_modules/vitest/vitest.mjs run test/registration-bootstrap-live.spec.ts` under its source/native test configuration. The strict bridge requires the independently enabled `dsh-identity/1106` policy and matching native API v2 candidate. Without the opt-in environment, normal owner collection skips the live cases.

The separate `test/registration-bootstrap-web-live.spec.ts` exercises fresh rootless Web creation through the same actual approval, strict factors and native proof. It verifies that the UUID registration operation on the wire matches the durable journal, the published public document contains no root method or root proof, and restarting the same Store preserves the reference/operation without another registration or email. This positive Web lane does not repeat the E1 lifecycle cases or claim a RootControl operation exists for Web.
