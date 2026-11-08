# ANP Identity for DeepSeek Harness

This candidate targets Harness `0.2.2-rc.1`, Cordis `4.1.0`, and Loader `1.1.0`, not Harness `0.1.5`. Remote descriptors use lazy `create()` codecs. In-process Gateway callers must supply an explicit Peer and install the Remote Access service.

Shared protocol identities without a dedicated request-signing key can request `ordinary-http/1` approval for public reads and native exact-request HTTP authentication with their unique device authentication key. This profile cannot perform raw signatures or OAuth assertions. A dedicated request-signing identity keeps its original ordinary-use profile; existing grants are never expanded. Older versions do not understand the new HTTP-only snapshot, so revoke/archive those grants before a downgrade.

An explicitly configured `userConsumers` entry may use `httpAllowedOrigins[consumer]: ['*']` for any HTTPS origin. The manager labels this broad permission before user approval. Both the approved grant and current Host policy must permit each dispatch; existing exact-origin grants never widen silently. Legacy Host consumers cannot use this wildcard. One-time operation binding and revocation remain enforced. Older versions do not understand wildcard snapshots; revoke those grants before downgrading.

`@agent-network-protocol/dsh-anp-identity` gives DSH applications one shared, multi-DID identity store without making each application implement key custody, DID document lifecycle, crash recovery, or request signing.

Ordinary plugins use `bindIdentityClient(ctx)` to request user-approved identity creation and use. Trusted Host integrations retain a separate facade through `ctx.anpIdentity`. The plugin delegates private-key operations to the ANP Identity native module, keeps private keys encrypted at rest, and stores only non-secret DSH metadata—labels, handles, and consumer grants—in its catalog.

## What problem it solves

A DSH installation may host several plugins and several independent DIDs. Those plugins need consistent answers to the same questions:

- Where are DID private keys stored, and which key is valid for a purpose?
- How can a DID document update survive process and network failures?
- How can two plugins share an identity without either plugin owning its private key?
- How can a request be authenticated without exposing a reusable signature header patch?
- How can a Store contain several DIDs while handles and deletion grants remain consistent?

This package supplies that coordination layer. ANP Identity remains the source of truth for identities and encrypted keys. A transactional catalog adds DSH-specific ownership metadata. Creation uses a recoverable intent; deletion writes a tombstone before touching the native Store; cross-process mutations use a file lock, generation checks, and atomic rename. The current publication extension upgrades the catalog to schema v4; see the coordinated upgrade and rollback instructions in [V7-MANAGEMENT.md](./V7-MANAGEMENT.md).

## What it provides

- An optional settings page with Handle/DID details, creation confirmations, an authorization inbox, once or persistent revocable grants, permission details and guarded deletion.
- Multi-DID create, list, open, delete, and recovery operations.
- Purpose-based Ed25519 signing and verification.
- Origin Proof signing.
- Transactional DID document change sessions.
- Consumer-scoped leases, grants, labels, and unique handles.
- Bounded authenticated HTTP dispatch with exact HTTPS-origin allowlists, a 4 MiB body limit, managed-header rejection, and manual redirects.
- A separate Host Provider lease for AWiki IM Core and similar trusted native consumers. Host-only operations include sealed ECDH, sealed import/export, enrollment, Root Transfer, and exact HTTP header patches.

Creation accepts the native `profile: 'e1' | 'web'` through the same client
lease. Web omits the DID `root_control` key while retaining Store encryption,
purpose-scoped signing, document changes and Host enrollment. Web Host status has
`rootKeyFingerprint: null`; Root Import/Transfer remain WBA-only. The public
types are imported from the native package, without a second method model here.

User-approved protocol creation (`parameters.usage: 'protocol'`) defaults to the
full Direct/Group messaging Manifest, including E2EE, for both E1 and Web.
The existing device-signing and agreement keys support later messaging plugin
integration. Creating an identity does not connect a messaging plugin or grant it
access; existing identity documents are unchanged. See [PUBLICATION.md](./PUBLICATION.md)
for the exact profiles and registration server requirements.

## What it does not provide

- It is not a DID registry, resolver, publication server, backup system, or wallet UI.
- It does not implement AWiki messaging, Bearer Token state, challenge retries, or P5 Root Transfer. `dsh-awiki` and AWiki IM Core own those workflows.
- It does not expose raw ECDH shared secrets, Root Keys, imported private keys, or general signing tools to Browser, Remote, agents, or models.
- Consumer names are a same-process policy and diagnostics boundary. They prevent accidental misuse; they do not sandbox malicious code running in the same Node.js process.

See [BOUNDARY.md](./BOUNDARY.md) for the complete trust model.

## Installation

Install the DSH plugin:

```bash
pnpm add @agent-network-protocol/dsh-anp-identity
```

The package installs the exact compatible ANP Identity wrapper. That wrapper
selects the prebuilt native package for the current platform; users do not need
Rust or a source checkout.

The current source pins `@agent-network-protocol/anp-identity@0.2.5` from npm
for both runtime and development dependencies. The lockfile includes the exact
registry wrapper and its five platform packages.

Load the Service before its Provider. The included `cordis.patch.yml` is a starting point:

The source candidate also provides an opt-in fresh protocol registration flow through `./protocol-bootstrap` and the existing manager's non-secret `registrationBootstrap` configuration. It retains real creation approval, User Service email/Turnstile confirmation, Registry verification and encrypted Host credential custody. It requires independent `dsh-identity/1106` admission and a matching native API v2 candidate; the same registry version number alone does not prove those methods exist. [Publication and fresh setup](PUBLICATION.md#fresh-host-registration-bootstrap) describes the two-stage Host configuration. Published state does not automatically grant MCP/PAP permission.

The shipping DSH layer grants `@awiki/dsh-plugin` client and Host Provider
access by default so the documented two-plugin AWiki installation works without
an extra local patch. Set `DSH_ANP_IDENTITY_ALLOW_CONSUMERS` and
`DSH_ANP_IDENTITY_ALLOW_PROVIDER_CONSUMERS` to explicit JSON arrays to replace
those defaults for a different deployment.

For MCP or PAP protocol use, configure the exact consumer in
`DSH_ANP_IDENTITY_ALLOW_CONSUMERS` and `DSH_ANP_IDENTITY_USER_CONSUMERS`, and
provide explicit `ProtocolUsePolicy` entries through
`DSH_ANP_IDENTITY_PROTOCOL_POLICIES` (a JSON array, default `[]`). These are
Host configuration inputs; loading the bundle alone grants no protocol target,
resource, scope, or signer permission. Keep the default empty policy until the
deployment has approved its precise targets. See [PUBLICATION.md](PUBLICATION.md)
for the publication capability boundary.

```yaml
- insert:
    - id: anp-identity
      name: '@agent-network-protocol/dsh-anp-identity'
      config:
        stateRoot: /var/lib/dsh/anp-identity
        allowConsumers: ['example/identity-client', '@awiki/dsh-plugin']
        allowProviderConsumers: ['@awiki/dsh-plugin']
        httpAllowedOrigins:
          example/identity-client: ['https://api.example.com']

    - id: anp-identity-provider
      name: '@agent-network-protocol/dsh-anp-identity/provider'
      config:
        stateRoot: /var/lib/dsh/anp-identity
        rootKeyProvider: keyring
        rootKeyProviderId: anp-identity/dsh
```

`rootKeyProviderId` is `service/account` for keyring, the environment variable name for `env`, and the key id for programmatic `injected` setup. `local-file` must be selected explicitly; copying both the Store and its local Root Key file permits offline decryption.

Both `local-file` and OS keyring are existing local implementations. A file-based Host can select `rootKeyProvider: local-file` (or `DSH_ANP_IDENTITY_ROOT_KEY_PROVIDER=local-file` for the bundle); OS keyring is optional. Management-broker keys reuse DSH's existing atomic credential records, with encrypted local files for broker and protocol state.

## Use it from another DSH plugin

Ordinary plugins must be configured in `userConsumers` by the Host. They use the loader-bound client below, not a self-declared consumer name or a legacy lease:

```ts
import { bindIdentityClient } from '@agent-network-protocol/dsh-anp-identity/user-client'

export const inject = ['anpIdentity']
// Call from the installed plugin's Context after its Loader entry is ready.
const client = bindIdentityClient(ctx)
const request = await client.requestCreateIdentity({
  requestId: 'stable-create-id',
  purpose: 'Create an identity for this integration',
  parameters: { label: 'Work', domain: 'example.com', path: '/agents/work' },
})
// Query request.id after user confirmation, then request separate use authorization.
```

Creation does not publish the document, register a Handle, or grant use. Once authorization binds one operation; permanent authorization lasts until revoked. The current MVP grants the full ordinary capability bundle, not individually selected permissions. See [the complete management contract](./V7-MANAGEMENT.md) and the [runnable signed HTTP demo](../../demo/dsh-http/README.md).

### Existing trusted Host consumers

The following legacy facade is for explicitly configured **trusted Host integrations**, not ordinary user-mode plugins. Declare the Cordis dependency, acquire only the capabilities you need, and dispose the lease with the calling plugin's fiber:

```ts
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@agent-network-protocol/dsh-anp-identity'

export const inject = ['anpIdentity']

export async function apply(ctx: Context): Promise<void> {
  const lease = await ctx.anpIdentity.acquireClient({
    consumer: 'example/identity-client',
    capabilities: ['identity:read', 'identity:create', 'identity:sign'],
  })
  ctx.effect(() => () => lease.dispose(), 'example: ANP Identity client lease')

  const identities = await lease.list()
  const identity = identities.length === 0
    ? await lease.create({
        label: 'Example agent',
        identity: {
          profile: 'e1',
          domain: 'agents.example.com',
          pathSegments: ['agents', 'example'],
          managedKeys: [
            { fragment: 'root', role: 'root_control' },
            { fragment: 'request', role: 'request_signing' },
          ],
        },
      })
    : await lease.get(identities[0]!.reference)

  const snapshot = await identity.publicIdentity()
  await identity.sign({
    purpose: 'authentication',
    kid: `${snapshot.reference.did}#request`,
    payload: Buffer.from('canonical application bytes'),
  })
}
```

For HTTP authentication, request `identity:http-auth`, configure an exact origin for that consumer, and call `identity.authenticatedHttp.dispatch(request, transport)`. The caller never receives the signature header patch.

## Modules and cooperation

| Module | Responsibility |
| --- | --- |
| `ctx.anpIdentity` | Public multi-DID facade, client leases, catalog, grants, handles, and HTTP dispatch |
| `./provider` | Opens the native Store and registers exactly one native Provider with Cordis lifecycle ownership |
| `./provider-api` | Versioned Host-only contract used by an externally bridged native consumer such as AWiki IM Core |
| `@agent-network-protocol/anp-identity` | Encrypted key custody, DID documents, signing, recovery, and sealed secret handoffs |
| `dsh-awiki` | AWiki account, messaging, Bearer Token/challenge state, and application workflows |

Mobile applications do not need this DSH package. They can link the ANP Identity Rust crate directly through their native integration while using the same Facade and Host SPI semantics.

## Recovery behavior

The native Store is always the identity truth. On startup:

- a Store identity absent from catalog and journals becomes `Unclaimed` with no grants;
- a catalog entry absent from the Store is removed;
- a pending create intent is completed when its Store identity can be identified;
- a deletion tombstone rolls forward, including after a transient native
  failure; if a delete response is lost, the plugin removes the tombstone only
  after confirming that the exact native identity is absent;
- a corrupt catalog blocks grants and handles. Explicit `recover()` rebuilds entries as `Unclaimed` and never invents authorization.

Host Provider deletion is an explicit local-destructive operation. It discards
unpublished local document or enrollment state before removing the complete
identity namespace; it does not revoke or modify the remote DID.

`recover()` is an exclusive, Store-wide operation. Do not use it as a polling API.

## Development

```bash
npm ci --legacy-peer-deps
npm run verify
```

The test suite uses the real native binding for multi-DID, restart, signing, HTTP dispatch, corruption recovery, and tombstone recovery, plus real child processes for catalog locking.

The functional HTTP-signing E2E additionally requires the `dsh` CLI, Node
`^22.19.0` or `>=24.0.0`, `pnpm`, `uv`, OpenSSL, and the sibling ANP checkout
expected by the workspace:

```bash
npm run test:functional
```

It downloads the exact published native wrapper and host platform package
pinned by this plugin, packs the DSH plugin from source, and installs them
into a temporary real DSH profile, then sends signed GET and POST
requests to an independent HTTPS process backed by the ANP Python verifier. A
tampered POST must be rejected. The temporary DSH profile, Store, certificate,
and tarballs are removed after the run.

The management UI tests render the real DSH primitives. Version `0.1.5-rc.2` of
`@deepseek-ai/dsh-client-ui-primitives` imports syntax-highlighting, Markdown,
terminal, and styling packages from its entry point but lists them only as its
own development dependencies. We explicitly include those imports as development
dependencies here so a clean `npm ci` can load the same components without
relying on a parent workspace's `node_modules`. They are test-environment
dependencies; the browser build continues to use the host-provided UI primitives.

Licensed under Apache-2.0.


## Shared public client identity foundation

The publication module prepares one stable CIMD/JWKS pair for an existing managed
identity. The Host registers `createPublicationBackend(...)` with
`service.registerPublicationBackend(managerContext, name, backend)`. Registration
requires the live installed `@agent-network-protocol/dsh-anp-identity/management-remote`
Context. The transport delegates management authentication to the Host's existing
`authenticatedFetch` and DID publication to `publishDocument`; neither function
nor its credentials belongs in Loader YAML, Browser requests or model tools.
Read [PUBLICATION.md](./PUBLICATION.md) for the contract and remaining integration boundaries.

The manager exposes publication status, publish and retry commands. The existing
settings view displays safe status/CIMD and a retry action. It does not collect
credentials or assume a working callback. Missing redirect configuration stays
`awaiting_configuration`; no default callback or PAP grant is advertised.

Ordinary Host consumers opt in through `oauthAllowedAudiences` and user approval.
Their authorized facade provides `oauthClientIdentity()` and
`signOAuthClientAssertion(exactAudience)`. The Host chooses the published client
and key. Opted-in consumers cannot use the old raw authentication signer to
bypass this typed policy; domain-separated application signing remains available.
Tokens/assertions are never exposed by the manager Remote.

Protocol identity creation uses an explicit `usage: 'protocol'` approval, local E1/Web device custody, capability-driven ES256 publication and target-bound machine/PAP leases. See [the publication and management contract](./PUBLICATION.md) for the real User Service driver, encrypted management broker, catalog v4 migration and validation boundaries.

The trusted Host publication driver also supplies typed, device-bound PAP callback registration and one-shot pickup. V2 PAP account supports a separate strict RFC 8252 loopback redirect declaration; V1 and protected public fetch URLs keep their HTTPS-only rules. These callbacks are not exposed by Remote or model tools.


The trusted User Service registration/publication driver signs every post-registration request with the existing ANP HTTP signer and registered device key; it does not reuse the saved registration Bearer. Device-operation authorization and public API shapes remain unchanged. See [the transport contract](PUBLICATION.md#registration-and-management).

## Configurable registration service

New registration configurations default to `https://awiki.me`. The authenticated
**Settings → Identity → Identity service** form saves the HTTPS root address on
the Host (not in browser local storage). Saving does not send an OTP, create an
identity, publish a DID or migrate an existing identity.

Omit `registrationBootstrap.origin` to use this saved default for a new flow.
An explicitly configured origin keeps precedence. Every new default-based flow
pins its original origin by its stable id/requestId; changing the preference or
restarting the Host cannot redirect an existing verification or publication flow.
Use a new identity and new flow IDs when moving between services, and configure
the matching DID domain/Handle in the creation request. Existing `id.awiki.info`
identities and their MCP/PAP bindings remain unchanged.

## Public identity onboarding and protocol guidance

The Identity settings page is **身份管理**. Use its **创建公共身份** button or ask
the Agent: “帮我创建一个公共身份，用于登录三方服务。”
The always-installed tools `identity_status`, `identity_request_creation` and
`identity_connection_guide` are visible even before a protocol connection exists.
A required runtime context routes identity requests to these tools instead of
workspace searches, vault inspection or an unrelated AWiki CLI.

The Agent request opens an owner form only. The user enters a Handle, label and
phone/email in that form; country code and national phone number are separate,
defaulting to China +86. A second explicit approval creates an identity-only
E1/Web protocol identity. Only after that approval may the existing verified
registration flow send a code and publish DID/CIMD materials. OTPs are entered in
the owner page, never passed through model tools. No third-party grant, account
callback or messaging capability is created automatically.

The built-in `./protocol-bootstrap` entry now also provides the owner-only
creation requester when no static request is configured. It must remain enabled
and listed in both allowConsumers and userConsumers. Explicit Host lists are
still authoritative; do not grant legacy Provider access to this requester.
Static Host bootstrap configurations continue using their original flow and are
not silently replaced by the form.

Owner registration inputs are stored under protected Host storage for restart;
OTP values are never persisted. An uncertain/unfinished flow cannot be replaced
or blindly retried. The Agent-facing status and intent outputs expose only public
references/status, not phone/email, credentials, storage paths or signing objects.
ANP/MCP/PAP guides give discovery order, actual available registry names, exact
parameter conventions, approval handling and no-replay rules for uncertain writes.

After creation approval, the owner dialog stays open through verification and
publication. It displays a blocked SMS admission error instead of disappearing
or claiming that a code was sent. **Continue registration** reopens that same
flow. After fixing a failed SMS send/admission, **Retry sending code** is an
explicit owner action that reuses the approved identity; it never retries an
uncertain registration or an already accepted challenge automatically.

The PAP Host accepts the published `@awiki/dsh-pap/plugin` consumer (and the
legacy package name for existing explicit policies). Protocol consumers must
also be in `userConsumers`, and still require an exact identity/target/profile
policy; ANP additionally requires the Host HTTP-origin scope and user approval.
