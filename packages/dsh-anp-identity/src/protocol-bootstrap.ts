/** Optional installed consumer that requests user approval before creating a protocol identity. */
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import { setTimeout } from 'node:timers/promises'
import { bindIdentityClient } from './user-client.js'

export const PROTOCOL_BOOTSTRAP_CONSUMER = '@agent-network-protocol/dsh-anp-identity/protocol-bootstrap'
export const name = 'anp-identity-protocol-bootstrap'
export const inject = ['anpIdentity']

export interface Config {
  requestId: string
  profile: 'e1' | 'web'
  label: string
  domain: string
  path: string
  /** Canonical full Handle shown in the creation approval. */
  handle: string
  providerReadyTimeoutMs: number
}
export const Config: z<Config> = z.object({
  requestId: z.string().required(), profile: z.union([z.const('e1'), z.const('web')]).default('e1'),
  label: z.string().required(), domain: z.string().required(), path: z.string().required(), handle: z.string().required(),
  providerReadyTimeoutMs: z.number().min(1000).max(60000).default(10000),
})

/** Submit one stable request from this actual installed Context; this never approves or registers it.
 * @param context - Loader-installed ordinary consumer.
 * @param config - Non-secret local creation request and bounded provider startup wait.
 */
export async function apply(context: Context, config: Config): Promise<void> {
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
    parameters: { profile: config.profile, usage: 'protocol', label: config.label, domain: config.domain, path: config.path, handle: config.handle },
  })
  if (request.id !== config.requestId) throw new Error('protocol_bootstrap_request_conflict')
}
