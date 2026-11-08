/** Recoverable Host publication coordinator, sharing the existing identity and catalog. */
import { createHash, randomUUID } from 'node:crypto'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import lockfile from 'proper-lockfile'
import type { IdentityReference, PublicIdentity } from '@agent-network-protocol/anp-identity'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import { CatalogStore, findEntry, type CatalogEntry } from './catalog.js'
import { pluginError } from './errors.js'
import { exactHttps, parsePublicJson, publicationRedirectUri } from './publication-http.js'
import { PublicationConfigSchema, PublicJwkSchema, publicationProfile,
  type PublicationBackend, type PublicationConfig, type PublicationRecord, type OAuthClientIdentity,
  type PreparedClientMaterials, type PublicationJwk } from './publication-types.js'

const sha = (value: string) => createHash('sha256').update(value).digest('hex')
function sameKey(left: unknown, right: PublicationJwk): boolean {
  const result = PublicJwkSchema.safeParse(left)
  return result.success && Object.keys(result.data).every(key => result.data[key as keyof typeof result.data] === (right as unknown as Record<string, unknown>)[key])
}
function binding(identity: PublicIdentity, record: PublicationRecord): void {
  const services = (identity.document as { service?: Array<Record<string, unknown>> }).service ?? []
  const matches = services.filter(service => service.type === 'ANPCIMD')
  const service = matches[0]
  if (matches.length !== 1 || !service || service.serviceEndpoint !== record.clientId
    || service.anp_metadata_sha256 !== record.metadataSha256
    || JSON.stringify(service.anp_oauth_keys) !== JSON.stringify([record.key.kid])) throw pluginError('provider_incompatible')
}

export class PublicationCoordinator {
  constructor(readonly store: CatalogStore, readonly host: {
    withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>
  }) {}

  async status(reference: IdentityReference): Promise<OAuthClientIdentity> {
    const entry = await this.entry(reference)
    const record = entry.publication
    if (!record) return { state: 'local', did: reference.did }
    if (record.state === 'published') await this.requirePublished(reference)
    return { state: record.state, did: reference.did, clientId: record.clientId,
      jwksUri: record.clientId.replace(/client\.json$/u, 'jwks.json'),
      keyId: record.key.kid, algorithm: record.key.alg, version: record.version, signerMode: 'local',
      ...(record.config.capabilities ? { capabilities: record.config.capabilities } : {}) }
  }

  async requirePublished(reference: IdentityReference): Promise<PublicationRecord> {
    const record = (await this.entry(reference)).publication
    if (!record || record.state !== 'published' || !record.metadata || sha(record.metadata) !== record.metadataSha256) throw pluginError('provider_unavailable')
    await this.host.withNative(async native => {
      const identity = await native.publicIdentity(reference)
      const key = await native.oauthPublicJwk(reference, record.key.kid)
      if (!sameKey(key, record.key)) throw pluginError('provider_incompatible')
      binding(identity, record)
    })
    return structuredClone(record)
  }

  async publish(reference: IdentityReference, raw: PublicationConfig, backend: PublicationBackend,
    assertActive: () => Promise<void>): Promise<OAuthClientIdentity> {
    const parsed = PublicationConfigSchema.safeParse(raw)
    if (!parsed.success) throw pluginError('invalid_request')
    const config = parsed.data
    exactHttps(backend.origin)
    config.redirectUris.forEach(uri => publicationRedirectUri(uri, config.capabilities))
    if (new Set(config.redirectUris).size !== config.redirectUris.length) throw pluginError('invalid_request')
    const clientId = exactHttps(backend.clientId(config.documentId), true)
    if (clientId !== `${backend.origin}/user-service/v1/agent-clients/${config.documentId}/client.json`) throw pluginError('invalid_request')
    const lockRoot = join(this.store.stateRoot, 'journal', 'publication', sha(JSON.stringify(reference)))
    await mkdir(lockRoot, { recursive: true, mode: 0o700 })
    const release = await lockfile.lock(lockRoot, { realpath: false, stale: 60000, update: 10000,
      retries: { retries: 50, minTimeout: 20, maxTimeout: 100 } })
    try {
      await assertActive()
      const previous = (await this.entry(reference)).publication
      const key = PublicJwkSchema.parse(await this.host.withNative(async native => {
        if (!config.capabilities) {
          const identity = await native.publicIdentity(reference)
          const candidates = identity.activeKeys.filter(key => key.algorithm === 'ed25519' && key.purposes.includes('authentication') && !key.purposes.includes('device_assertion'))
          const selected = config.activeKid ?? previous?.key.kid ?? (candidates.length === 1 ? candidates[0]!.kid : undefined)
          if (!selected) throw pluginError('provider_incompatible')
          return native.oauthPublicJwk(reference, selected)
        }
        if (!config.activeKid || !config.activeKid.startsWith(reference.did + '#')) throw pluginError('invalid_request')
        try { return await native.oauthPublicJwk(reference, config.activeKid) }
        catch { /* An unenrolled selected key must first pass the authorized DID update. */ }
        const provider = native as unknown as {
          prepareOAuthKeyChange?: (ref: IdentityReference, request: { fragment: string; operation_id: string; expected_revision: number }) => Promise<import('@agent-network-protocol/anp-identity/provider').ProviderDocumentChangeSession>
          exportCandidateOAuthPublicJwk?: (ref: IdentityReference, kid: string) => Promise<unknown>
        }
        if (typeof provider.prepareOAuthKeyChange !== 'function' || typeof provider.exportCandidateOAuthPublicJwk !== 'function') throw pluginError('provider_incompatible')
        const identity = await native.publicIdentity(reference)
        const session = await native.resumeDocumentChange(reference) ?? await provider.prepareOAuthKeyChange(reference, {
          fragment: config.activeKid.slice(reference.did.length + 1), operation_id: 'oauth-key-' + sha(config.activeKid).slice(0, 48), expected_revision: identity.revision,
        })
        const selected = PublicJwkSchema.parse(await provider.exportCandidateOAuthPublicJwk(reference, config.activeKid))
        if (selected.alg !== 'ES256' || selected.kid !== config.activeKid) throw pluginError('provider_incompatible')
        await assertActive()
        await backend.publishDocument(reference, session, assertActive)
        if (await native.resumeDocumentChange(reference)) throw pluginError('provider_unavailable')
        return native.oauthPublicJwk(reference, config.activeKid)
      }))
      if (config.capabilities && (key.alg !== 'ES256' || !config.activeKid || key.kid !== config.activeKid)) throw pluginError('provider_incompatible')
      if (previous && previous.clientId !== clientId) throw pluginError('invalid_request')
      const same = previous && JSON.stringify(previous.config) === JSON.stringify(config) && sameKey(previous.key, key)
      if (previous && previous.state !== 'published' && previous.state !== 'awaiting_configuration' && !same) throw pluginError('catalog_conflict')
      let record: PublicationRecord = same ? structuredClone(previous) : {
        config, clientId, key, state: 'publishing', operationId: randomUUID(),
        expectedVersion: previous?.version ?? 0, version: previous?.version ?? 0,
      }
      if (same && record.state === 'published') {
        try { await this.readBack(backend, record) }
        catch {
          await this.save(reference, { ...record, state: 'failed', failure: 'material_mismatch' })
          throw pluginError('provider_unavailable')
        }
        return this.status(reference)
      }
      record = { ...record, state: (config.capabilities ? !config.capabilities.papAccount || config.redirectUris.length > 0 : config.redirectUris.length > 0) ? 'publishing' : 'awaiting_configuration' }
      await this.save(reference, record)
      if (record.state === 'awaiting_configuration') return this.status(reference)
      try {
        await assertActive()
        const prepared = await backend.prepare(config.documentId, {
          operation_id: record.operationId, expected_version: record.expectedVersion,
          client_name: config.clientName, redirect_uris: config.redirectUris,
          ...(config.capabilities ? { schema_version: 2 as const,
            capabilities: { mcp_machine: config.capabilities.mcpMachine, pap_session: config.capabilities.papSession, pap_account: config.capabilities.papAccount },
            signing_keys: [key], active_kid: key.kid } : { key: key as import('@agent-network-protocol/anp-identity').OAuthPublicJwk }),
        })
        record = this.materials(record, prepared)
        await this.save(reference, record)
        await this.host.withNative(async native => {
          await assertActive()
          const identity = await native.publicIdentity(reference)
          let current = false
          try { binding(identity, record); current = true } catch { /* Prepare/reconcile below. */ }
          const pending = await native.resumeDocumentChange(reference)
          if (pending || !current) {
            const session = pending ?? await native.prepareDocumentChange(reference, { changes: [{
              change: 'bind_oauth_client', clientId, kid: key.kid, metadataSha256: record.metadataSha256!,
            }] })
            const candidate = await session.candidate()
            binding({ ...identity, document: candidate.candidateDocument }, record)
            await backend.publishDocument(reference, session, assertActive)
            if (await native.resumeDocumentChange(reference)) throw pluginError('provider_unavailable')
            binding(await native.publicIdentity(reference), record)
          }
        })
        await assertActive()
        const activated = await backend.activate(config.documentId, record.operationId)
        const accepted = this.materials(record, activated)
        if (activated.state !== 'published' || accepted.version !== record.version
          || accepted.metadata !== record.metadata || accepted.jwks !== record.jwks) throw pluginError('provider_incompatible')
        await this.readBack(backend, record)
        await assertActive()
        await this.save(reference, { ...record, state: 'published' })
        return this.status(reference)
      } catch (error) {
        await this.save(reference, { ...record, state: 'failed', failure: 'publication_failed' }).catch(() => {})
        throw pluginError('provider_unavailable')
      }
    } finally { await release() }
  }

  private materials(record: PublicationRecord, result: PreparedClientMaterials): PublicationRecord {
    if (!['prepared', 'published'].includes(result.state) || result.client_id !== record.clientId
      || result.operation_id !== record.operationId || !Number.isSafeInteger(result.version) || result.version <= record.expectedVersion
      || typeof result.metadata !== 'string' || typeof result.jwks !== 'string'
      || result.metadata.length > 16384 || result.jwks.length > 16384 || sha(result.metadata) !== result.metadata_sha256) throw pluginError('provider_incompatible')
    if (record.config.capabilities && (result.schema_version !== 2 || result.profile !== publicationProfile(record.config.capabilities)
      || result.active_kid !== record.key.kid || result.key_set_digest !== sha(result.jwks)
      || !result.capabilities || result.capabilities.mcp_machine !== record.config.capabilities.mcpMachine
      || result.capabilities.pap_session !== record.config.capabilities.papSession || result.capabilities.pap_account !== record.config.capabilities.papAccount)) throw pluginError('provider_incompatible')
    const metadata = parsePublicJson(result.metadata) as Record<string, unknown>
    const jwks = parsePublicJson(result.jwks) as { keys?: unknown[] }
    if (metadata.client_id !== record.clientId || metadata.jwks_uri !== record.clientId.replace(/client\.json$/u, 'jwks.json')
      || metadata.token_endpoint_auth_method !== 'private_key_jwt' || metadata.token_endpoint_auth_signing_alg !== record.key.alg
      || metadata.client_name !== record.config.clientName || JSON.stringify(metadata.redirect_uris) !== JSON.stringify(record.config.redirectUris)
      || JSON.stringify(metadata.grant_types) !== JSON.stringify(record.config.capabilities ? [
        ...(record.config.capabilities.mcpMachine ? ['client_credentials'] : []),
        ...(record.config.capabilities.papAccount ? ['authorization_code', 'refresh_token'] : []),
      ] : ['authorization_code']) || JSON.stringify(metadata.response_types) !== JSON.stringify(record.config.capabilities ? (record.config.capabilities.papAccount ? ['code'] : []) : ['code'])
      || !Array.isArray(jwks.keys) || jwks.keys.length !== 1 || !sameKey(jwks.keys[0], record.key)) throw pluginError('provider_incompatible')
    const allowed = new Set(['client_id', 'jwks_uri', 'client_name', 'redirect_uris', 'grant_types', 'response_types', 'token_endpoint_auth_method', 'token_endpoint_auth_signing_alg'])
    if (Object.keys(metadata).some(key => !allowed.has(key)) || Object.keys(jwks).some(key => key !== 'keys')) throw pluginError('provider_incompatible')
    return { ...record, version: result.version, metadata: result.metadata, jwks: result.jwks, metadataSha256: result.metadata_sha256! }
  }

  private async readBack(backend: PublicationBackend, record: PublicationRecord): Promise<void> {
    const [metadata, jwks] = await Promise.all([
      backend.readPublic(record.config.documentId, 'client.json'), backend.readPublic(record.config.documentId, 'jwks.json'),
    ])
    if (metadata !== record.metadata || jwks !== record.jwks || sha(metadata) !== record.metadataSha256) throw pluginError('provider_incompatible')
  }
  private async entry(reference: IdentityReference): Promise<CatalogEntry> {
    const catalog = await this.store.load().catch(() => { throw pluginError('catalog_corrupt') })
    const entry = findEntry(catalog, reference)
    if (!entry || entry.state !== 'active') throw pluginError('identity_not_found')
    return entry
  }
  private async save(reference: IdentityReference, record: PublicationRecord): Promise<void> {
    await this.store.mutate(catalog => {
      const entry = findEntry(catalog, reference)
      if (!entry || entry.state !== 'active') throw pluginError('identity_not_found')
      return { ...catalog, entries: catalog.entries.map(item => item === entry ? { ...item, publication: structuredClone(record) } : item) }
    })
  }
}
