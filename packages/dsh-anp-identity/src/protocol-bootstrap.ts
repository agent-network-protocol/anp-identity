import { resolveInstalledConsumer } from './installed-consumer.js'
import type AnpIdentityService from './index.js'
/** Optional installed consumer that requests user approval before creating a protocol identity. */
import { Service, type Context } from '@deepseek-ai/cordis'
import type { RequestCreateInput } from './authorization-types.js'
import z from '@deepseek-ai/schemastery'
import { setTimeout } from 'node:timers/promises'
import { bindIdentityClient } from './user-client.js'

export const PROTOCOL_BOOTSTRAP_CONSUMER = '@agent-network-protocol/dsh-anp-identity/protocol-bootstrap'
export const name = 'anp-identity-protocol-bootstrap'
export const inject = ['anpIdentity']

export interface Config {
  requestId?: string
  profile: 'e1' | 'web'
  identityOnly: boolean
  label?: string
  domain?: string
  path?: string
  /** Canonical full Handle shown in the creation approval. */
  handle?: string
  providerReadyTimeoutMs: number
}
export const Config: z<Config> = z.object({
  requestId: z.string(), profile: z.union([z.const('e1'), z.const('web')]).default('e1'),
  identityOnly: z.boolean().default(true),
  label: z.string(), domain: z.string(), path: z.string(), handle: z.string(),
  providerReadyTimeoutMs: z.number().min(1000).max(60000).default(10000),
})

declare module '@deepseek-ai/cordis' { interface Context { anpIdentityRequester: RegistrationRequester } }

/** Uses only this real installed ordinary consumer; it cannot approve creation. */
export class RegistrationRequester extends Service {
  private readonly owner: Context;
  constructor(ctx: Context) { super(ctx, 'anpIdentityRequester'); this.owner = ctx; }
  available(manager: Context): boolean {
    if (manager.root !== this.owner.root || resolveInstalledConsumer(this.owner.root, this.owner)?.options.name !== PROTOCOL_BOOTSTRAP_CONSUMER) return false;
    try {
      (manager.anpIdentity as AnpIdentityService).acquireManagement(manager);
      bindIdentityClient(this.owner);
      return true;
    } catch { return false; }
  }
  async request(manager: Context, input: RequestCreateInput) {
    if (manager.root !== this.owner.root || resolveInstalledConsumer(this.owner.root, this.owner)?.options.name !== PROTOCOL_BOOTSTRAP_CONSUMER) throw new Error('consumer_forbidden');
    (manager.anpIdentity as AnpIdentityService).acquireManagement(manager);
    const result = await bindIdentityClient(this.owner).requestCreateIdentity(input);
    (manager.anpIdentity as AnpIdentityService).acquireManagement(manager);
    return result;
  }
}

/** Submit one stable request from this actual installed Context; this never approves or registers it.
 * @param context - Loader-installed ordinary consumer.
 * @param config - Non-secret local creation request and bounded provider startup wait.
 */
export async function apply(context: Context, config: Config): Promise<void> {
  new RegistrationRequester(context)
  if (!config.requestId) return
  if (!config.label || !config.domain || !config.path || !config.handle) throw new Error('protocol_bootstrap_invalid_configuration')
  const controller = new AbortController()
  context.effect(() => () => controller.abort(), 'anp-identity: protocol creation request')
  const deadline = Date.now() + config.providerReadyTimeoutMs
  while ((await context.anpIdentity.health()).status === 'unavailable') {
    if (Date.now() >= deadline) throw new Error('protocol_bootstrap_provider_unavailable')
    await setTimeout(Math.min(100, deadline - Date.now()), undefined, { signal: controller.signal })
  }
  const request = await bindIdentityClient(context).requestCreateIdentity({
    requestId: config.requestId,
    purpose: `Create protocol identity ${config.handle}; server registration and publication require independent verification.`,
    parameters: { profile: config.profile, usage: 'protocol', identityOnly: config.identityOnly, label: config.label, domain: config.domain, path: config.path, handle: config.handle },
  })
  if (request.id !== config.requestId) throw new Error('protocol_bootstrap_request_conflict')
}
