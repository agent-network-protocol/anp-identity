/** Host opt-in for domain-based connections; discovery never grants authority. */
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import type { IdentityReference } from './types.js'
import type { ProtocolUsePolicy } from './protocol-client.js'

export type DomainProfile = 'anp' | 'pap_session' | 'mcp_machine'
export interface DomainAccessConfig {
  enabled: boolean
  identity?: IdentityReference
  /** Legacy persistent-read scope set. Additional discovered scopes require the shared owner policy or exact consent. */
  scopes: string[]
  secretStore?: 'keyring' | 'local-file'
  expiresAt?: number
}
export interface DomainBinding {
  identityRef: IdentityReference
  policyRef: string
  stateRoot: string
  secretsRoot: string
  secretStore: 'keyring' | 'local-file'
  scopes: string[]
}
const consumers: Record<DomainProfile, readonly string[]> = {
  anp: ['@agent-network-protocol/dsh-anp/plugin'],
  pap_session: ['@awiki/dsh-pap/plugin'],
  mcp_machine: ['@deepseek-ai/dsh-mcp-client/domain', '@deepseek-ai/dsh-mcp-client'],
}
const same = (a: IdentityReference, b: IdentityReference) => a.storeId === b.storeId && a.identityId === b.identityId && a.did === b.did
export class DomainAccessError extends Error {
  constructor(readonly code: string) { super(code) }
}
/** Resolve only locally published identities and install a Host-owned global policy. */
export class DomainAccessResolver {
  constructor(private readonly config: DomainAccessConfig | undefined, private readonly root: string,
    private readonly candidates: (profile: DomainProfile) => Promise<IdentityReference[]>,
    private readonly install: (policy: ProtocolUsePolicy) => void,
    private readonly selection?: () => Promise<{ identity: IdentityReference | null; version: number }>) {
    if (config && (config.secretStore !== undefined && !['keyring', 'local-file'].includes(config.secretStore)
      || typeof config.enabled !== 'boolean' || !Array.isArray(config.scopes)
      || config.scopes.length > 64 || config.scopes.some(scope => !/^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/u.test(scope))
      || config.expiresAt !== undefined && (!Number.isSafeInteger(config.expiresAt) || config.expiresAt <= 0))) {
      throw new DomainAccessError('invalid_domain_access_configuration')
    }
    this.config = config && structuredClone(config)
  }
  async resolve(consumer: string, profile: DomainProfile): Promise<DomainBinding> {
    if (!Object.hasOwn(consumers, profile) || !consumers[profile].includes(consumer)) throw new DomainAccessError('consumer_forbidden')
    const config = this.config
    if (!config?.enabled) throw new DomainAccessError('domain_access_disabled')
    const expiresAt = config.expiresAt ?? Number.MAX_SAFE_INTEGER
    if (Date.now() >= expiresAt) throw new DomainAccessError('domain_access_expired')
    const selection = await this.selection?.()
    const selected = selection ? selection.identity : config.identity
    const available = await this.candidates(profile)
    const eligible = selected ? available.filter(identity => same(identity, selected)) : available
    if (!eligible.length) throw new DomainAccessError('published_identity_required')
    if (eligible.length !== 1) throw new DomainAccessError('default_identity_required')
    const identityRef = structuredClone(eligible[0]!)
    if (selection && JSON.stringify(await this.selection!()) !== JSON.stringify(selection)) throw new DomainAccessError('default_identity_changed')
    const targetConsumer = consumer
    const scopes = profile === 'mcp_machine' ? [...new Set(config.scopes)].sort() : []
    const policyFields: unknown[] = [identityRef, targetConsumer, profile, scopes, expiresAt]
    if (selection?.version) policyFields.push(selection.version)
    const digest = createHash('sha256').update(JSON.stringify(policyFields)).digest('hex')
    const policyRef = `domain-${digest}`
    const storage = createHash('sha256').update(JSON.stringify([identityRef, targetConsumer, profile])).digest('hex')
    if (profile !== 'anp' && (profile !== 'mcp_machine' || scopes.length)) this.install({ id: policyRef, version: 1, consumer: targetConsumer, identity: identityRef,
      owner: '@agent-network-protocol/dsh-anp-identity', profiles: [profile], issuers: [], resources: [], publicTargets: true, scopes, expiresAt })
    return { identityRef, policyRef, scopes, secretStore: config.secretStore ?? 'keyring', stateRoot: join(this.root, 'domain-access', storage, 'state'), secretsRoot: join(this.root, 'domain-access', storage, 'secrets') }
  }
}
