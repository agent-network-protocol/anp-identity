/** Optional Host adapter for DSH MCP CIMD signing. */
import type { Context } from '@deepseek-ai/cordis'
import type {} from '@deepseek-ai/cordis-plugin-loader'
import z from '@deepseek-ai/schemastery'
import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import { bindProtocolIdentityClient, type ValidatedTargetEvidence } from './protocol-client.js'

export const name = 'anp-identity-mcp-signing-provider'
export const inject = ['anpIdentity', 'loader']

export interface Config {
  name: string
  bindings: Record<string, { identityRef: IdentityReference; policyRef: string }>
}

export const Config: z<Config> = z.object({
  name: z.string().pattern(/^[a-z][a-z0-9-]{0,63}$/u).default('anp-identity'),
  bindings: z.dict(z.object({
    identityRef: z.object({ storeId: z.string().required(), identityId: z.string().required(), did: z.string().required() }).required(),
    policyRef: z.string().required(),
  })).required(),
})

interface McpSigningBindings {
  bind(caller: Context, input: {
    readonly credentialRef: string
    readonly target: ValidatedTargetEvidence & { readonly profile: 'mcp_machine' }
    readonly requestedScopes: readonly string[]
  }): Promise<{
    readonly identity: {
      clientId: string; keyId: string; algorithm: 'ES256'; keyVersion: string; policyVersion: string
    }
    assertActive(): Promise<void>
    signClientAssertion(): Promise<string>
    dispose(): void
  }>
}

interface McpSigningRegistry {
  register(name: string, provider: McpSigningBindings): () => void
}

const mcpModule = '@deepseek-ai/dsh-mcp-client'

/** Register only when the Host explicitly loads the adapter and has a compatible MCP client. */
export async function apply(context: Context, config: Config): Promise<void> {
  const { McpSigningProviderRegistry } = await context.loader.import(mcpModule) as {
    McpSigningProviderRegistry?: new (owner: Context) => McpSigningRegistry;
  }
  if (!McpSigningProviderRegistry) throw new Error('ANP Identity MCP signing requires a DSH MCP client with Host signing provider support')
  const bindings = new Map(Object.entries(structuredClone(config.bindings)))
  new McpSigningProviderRegistry(context).register(config.name, {
    async bind(caller, input) {
      const binding = bindings.get(input.credentialRef)
      if (!binding) throw new Error('ANP Identity MCP credential reference is not configured')
      const lease = await bindProtocolIdentityClient(caller).registerValidatedTarget({
        identityRef: binding.identityRef,
        policyRef: binding.policyRef,
        discovery: input.target,
        requestedScopes: [...input.requestedScopes],
      })
      try {
        const identity = await lease.getOAuthClientIdentity()
        return {
          identity: { clientId: identity.clientId, keyId: identity.keyId, algorithm: identity.algorithm,
            keyVersion: String(identity.version), policyVersion: String(lease.policyGeneration) },
          assertActive: () => lease.assertActive(),
          signClientAssertion: () => lease.signOAuthClientAssertion(lease.targetRef),
          dispose: () => lease.dispose(),
        }
      } catch (error) {
        lease.dispose()
        throw error
      }
    },
  })
}
