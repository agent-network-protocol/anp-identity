# ANP Identity for DeepSeek Harness

`@agent-network-protocol/dsh-anp-identity` gives DSH applications one shared, multi-DID identity store without making each application implement key custody, DID document lifecycle, crash recovery, or request signing.

Applications use a small TypeScript facade through `ctx.anpIdentity`. The plugin delegates private-key operations to the ANP Identity native module, keeps private keys encrypted at rest, and stores only non-secret DSH metadata—labels, handles, and consumer grants—in its catalog.

## What problem it solves

A DSH installation may host several plugins and several independent DIDs. Those plugins need consistent answers to the same questions:

- Where are DID private keys stored, and which key is valid for a purpose?
- How can a DID document update survive process and network failures?
- How can two plugins share an identity without either plugin owning its private key?
- How can a request be authenticated without exposing a reusable signature header patch?
- How can a Store contain several DIDs while handles and deletion grants remain consistent?

This package supplies that coordination layer. ANP Identity remains the source of truth for identities and encrypted keys. A transactional `catalog-v1` adds DSH-specific ownership metadata. Creation uses a recoverable intent; deletion writes a tombstone before touching the native Store; cross-process mutations use a file lock, generation checks, and atomic rename.

## What it provides

- Multi-DID create, list, open, delete, and recovery operations.
- Purpose-based Ed25519 signing and verification.
- Origin Proof signing.
- Transactional DID document change sessions.
- Consumer-scoped leases, grants, labels, and unique handles.
- Bounded authenticated HTTP dispatch with exact HTTPS-origin allowlists, a 4 MiB body limit, managed-header rejection, and manual redirects.
- A separate Host Provider lease for AWiki IM Core and similar trusted native consumers. Host-only operations include sealed ECDH, sealed import/export, enrollment, Root Transfer, and exact HTTP header patches.

## What it does not provide

- It is not a DID registry, resolver, publication server, backup system, or wallet UI.
- It does not implement AWiki messaging, Bearer Token state, challenge retries, or P5 Root Transfer. `dsh-awiki` and AWiki IM Core own those workflows.
- It does not expose raw ECDH shared secrets, Root Keys, imported private keys, or general signing tools to Browser, Remote, agents, or models.
- Consumer names are a same-process policy and diagnostics boundary. They prevent accidental misuse; they do not sandbox malicious code running in the same Node.js process.

See [BOUNDARY.md](./BOUNDARY.md) for the complete trust model.

## Installation

Install the DSH plugin and the matching native binding:

```bash
pnpm add @agent-network-protocol/dsh-anp-identity \
  @agent-network-protocol/anp-identity
```

ANP Identity `0.2.x` is required. The TypeScript package contains no native binary itself.

Load the Service before its Provider. The included `cordis.patch.yml` is a starting point:

```yaml
- insert:
    - id: anp-identity
      name: '@agent-network-protocol/dsh-anp-identity'
      config:
        stateRoot: /var/lib/dsh/anp-identity
        allowConsumers: ['example/identity-client', 'awiki']
        allowProviderConsumers: ['awiki']
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

## Use it from another DSH plugin

Declare the Cordis dependency, acquire only the capabilities you need, and dispose the lease with the calling plugin's fiber:

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
- a deletion tombstone rolls forward;
- a corrupt catalog blocks grants and handles. Explicit `recover()` rebuilds entries as `Unclaimed` and never invents authorization.

`recover()` is an exclusive, Store-wide operation. Do not use it as a polling API.

## Development

```bash
npm install --legacy-peer-deps
npm run verify
```

The test suite uses the real native binding for multi-DID, restart, signing, HTTP dispatch, corruption recovery, and tombstone recovery, plus real child processes for catalog locking.

Licensed under Apache-2.0.
