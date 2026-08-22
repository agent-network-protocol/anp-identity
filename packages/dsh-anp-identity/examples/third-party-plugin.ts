import type { Context } from '@deepseek-ai/cordis'
import type {} from '@agent-network-protocol/dsh-anp-identity'

export const name = 'anp-identity-third-party-example'
export const inject = ['anpIdentity']

export async function apply(ctx: Context): Promise<void> {
  const lease = await ctx.anpIdentity.acquireClient({
    consumer: 'example/identity-client',
    capabilities: ['identity:read', 'identity:create', 'identity:sign', 'identity:handle'],
  })
  ctx.effect(() => () => lease.dispose(), 'example: ANP Identity client lease')
  const identity = await lease.create({
    label: 'Example agent',
    handle: 'example.agent',
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
  const publicIdentity = await identity.publicIdentity()
  await identity.sign({
    purpose: 'authentication',
    kid: `${publicIdentity.reference.did}#request`,
    payload: Buffer.from('application-defined canonical bytes'),
  })
}
