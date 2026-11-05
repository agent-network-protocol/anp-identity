/** Real User Service device-management transport. Credentials stay in the Host broker. */
import { randomUUID, createHash } from 'node:crypto'
import type { IdentityReference, JsonValue, VerifiedRemoteDocument } from '@agent-network-protocol/anp-identity'
import type { ProviderLease, ProviderDocumentChangeSession } from '@agent-network-protocol/anp-identity/provider'
import type { PublicationBackend, PreparedClientMaterials, PublicationIntentV2 } from './publication-types.js'
import { exactHttps, parsePublicJson } from './publication-http.js'
import { AnpIdentityPluginError, pluginError } from './errors.js'
import { PapCallbackOperationSchema, PapCallbackRegistrationResultSchema, PapCallbackClaimResultSchema,
  PapCallbackManagementError, papCallbackManagementError } from './pap-callback.js'
import type { PapCallbackManagementOperations, PapCallbackRegisterOperation, PapCallbackClaimOperation,
  PapCallbackOperation, PapCallbackRegistrationResult, PapCallbackClaimResult } from './pap-callback.js'

export interface DeviceManagementCredential {
  accessToken: string
  deviceId: string
  signingKeyId: string
  audience?: string
  operationBindings?: Record<string, Record<string, unknown>>
}
/** The implementation must encrypt secrets at rest and partition by exact identity and service origin. */
export interface ManagementCredentialBroker {
  get(reference: IdentityReference, origin: string): Promise<DeviceManagementCredential | undefined>
  set(reference: IdentityReference, origin: string, credential: DeviceManagementCredential): Promise<void>
  reserveOperation(reference: IdentityReference, origin: string, operationId: string, body: Record<string, unknown>): Promise<Record<string, unknown>>
}
interface Checkpoint { document_version: number; document_hash: string; registry_version: number }
interface Registry { did: string; checkpoint: Checkpoint; devices: Array<{ device_id: string; signing_key_id: string; status: string; role: string; management_ready: boolean }> }
export interface ManagedPublicationDriver extends PapCallbackManagementOperations {
  readonly documentId: string
  readonly backend: PublicationBackend
  readonly reference: IdentityReference
  readVerifiedDocument(): Promise<VerifiedRemoteDocument>
}

/** Create a device-authorized publication driver from a live Registry and an authenticated resolve.
 * @param input - Host custody, protected credentials and the fixed User Service origin.
 * @returns A driver bound to the server-resolved document id, never a user-supplied id.
 */
export async function createManagedPublicationDriver(input: {
  reference: IdentityReference
  origin: string
  credentials: ManagementCredentialBroker
  withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>
  fetch?: typeof fetch
  /** Supplied by the Host installer to revoke this driver with its management Context and provider generation. */
  assertActive?: () => Promise<void>
  /** Synchronous final epoch check immediately before physical sends and after body/native awaits. */
  assertCurrent?: () => void
}): Promise<ManagedPublicationDriver> {
  const origin = exactHttps(input.origin)
  if (new URL(origin).origin !== origin) throw pluginError('invalid_request')
  const transport = input.fetch ?? fetch
  const send: typeof fetch = async (request, init) => {
    await input.assertActive?.(); input.assertCurrent?.()
    const response = await transport(request, init)
    try { await input.assertActive?.(); input.assertCurrent?.(); return response }
    catch (error) { await response.body?.cancel(); throw error }
  }
  const reference = Object.freeze(structuredClone(input.reference))
  const credential = async () => {
    const value = await input.credentials.get(reference, origin)
    if (!value || !value.accessToken || !value.deviceId || !value.signingKeyId) throw pluginError('provider_unavailable')
    return value
  }
  const read = async (request: Request, callbackErrors = false): Promise<Record<string, unknown>> => {
    const response = await send(request)
    if ((!callbackErrors && response.status !== 200) || response.redirected || !(response.headers.get('content-type') ?? '').startsWith('application/json')) {
      await response.body?.cancel(); throw pluginError('provider_unavailable')
    }
    const reader = response.body?.getReader(); const parts: Uint8Array[] = []; let size = 0
    try {
      while (reader) { const part = await reader.read(); if (part.done) break; size += part.value.length; if (size > 131072) throw pluginError('provider_incompatible'); parts.push(part.value) }
      const result = parsePublicJson(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(parts)))
      if (!result || typeof result !== 'object' || Array.isArray(result)) throw pluginError('provider_incompatible')
      const object = result as Record<string, unknown>
      input.assertCurrent?.()
      if (response.status !== 200) throw papCallbackManagementError(object) ?? pluginError('provider_unavailable')
      return object
    } finally { await reader?.cancel(); reader?.releaseLock() }
  }
  const rpc = async (method: string, params: unknown): Promise<Record<string, unknown>> => {
    const auth = await credential()
    const result = await read(new Request(origin + '/user-service/v1/did-auth/rpc', { method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(15000),
      headers: { authorization: 'Bearer ' + auth.accessToken, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: randomUUID(), method, params }) }))
    if (result.error || !result.result || typeof result.result !== 'object' || Array.isArray(result.result)) throw pluginError('provider_unavailable')
    return result.result as Record<string, unknown>
  }
  const registry = async (): Promise<Registry> => {
    const current = await rpc('device_registry_get', {}) as unknown as Registry
    const auth = await credential()
    const device = current.devices?.find(device => device.device_id === auth.deviceId)
    if (current.did !== reference.did || !device || device.signing_key_id !== auth.signingKeyId
      || device.status !== 'active' || device.role !== 'admin' || !device.management_ready
      || !Number.isSafeInteger(current.checkpoint?.document_version) || !Number.isSafeInteger(current.checkpoint.registry_version)
      || !/^sha256:[A-Za-z0-9_-]{43}$/u.test(current.checkpoint.document_hash)) throw pluginError('provider_incompatible')
    return current
  }
  const proof = async (method: string, params: Record<string, unknown>) => {
    const auth = await credential()
    return input.withNative(async native => {
      const signer = (native as unknown as { signManagementProof?: (ref: IdentityReference, request: unknown) => Promise<unknown> }).signManagementProof
      if (typeof signer !== 'function') throw pluginError('provider_incompatible')
      return signer.call(native, reference, { key: { kid: auth.signingKeyId }, method, params,
        ...(auth.audience === undefined ? {} : { audience: auth.audience }) })
    })
  }
  type PublicationAction = 'prepare' | 'activate' | 'status' | 'resolve'
  type DeviceAction = PublicationAction | 'pap-callback-register' | 'pap-callback-claim'
  const methods: Record<DeviceAction, string> = { prepare: 'agent_client_prepare', activate: 'agent_client_activate',
    status: 'agent_client_status', resolve: 'agent_client_resolve',
    'pap-callback-register': 'agent_client_pap_callback_register', 'pap-callback-claim': 'agent_client_pap_callback_claim' }
  const deviceResponse = async (action: DeviceAction, operationId: string, extra: Record<string, unknown> = {}) => {
    await input.assertActive?.()
    const [current, auth] = await Promise.all([registry(), credential()])
    const httpPath = '/user-service/v1/agent-clients/device/' + action
    const proposed = { operation_id: operationId, expected_document_version: current.checkpoint.document_version,
      expected_document_hash: current.checkpoint.document_hash, expected_registry_version: current.checkpoint.registry_version,
      authorizing_device_id: auth.deviceId, ...extra }
    const body: Record<string, unknown> = action === 'prepare' || action === 'activate' || action === 'pap-callback-register'
      ? await input.credentials.reserveOperation(reference, origin, methods[action] + ':' + operationId, proposed) : proposed
    if (action === 'pap-callback-register' && JSON.stringify(body.callback) !== JSON.stringify(extra.callback)) throw pluginError('catalog_conflict')
    const signed = await proof(methods[action], { ...body, http_path: httpPath, target_did: reference.did })
    await input.assertActive?.()
    const result = await read(new Request(origin + httpPath, { method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(15000),
      headers: { authorization: 'Bearer ' + auth.accessToken, 'content-type': 'application/json' }, body: JSON.stringify({ ...body, authorizing_device_proof: signed }) }), action === 'pap-callback-register' || action === 'pap-callback-claim')
    await input.assertActive?.()
    return result
  }
  const deviceCommand = async (action: PublicationAction, operationId: string, extra: Record<string, unknown> = {}) => {
    const result = await deviceResponse(action, operationId, extra)
    if (result.did !== reference.did || typeof result.document_id !== 'string') throw pluginError('provider_incompatible')
    return result
  }
  const resolved = await deviceCommand('resolve', randomUUID())
  const documentId = resolved.document_id as string
  if (!/^[A-Za-z0-9_-]{1,128}$/u.test(documentId)) throw pluginError('provider_incompatible')
  const clientId = `${origin}/user-service/v1/agent-clients/${documentId}/client.json`
  if (resolved.client_id !== clientId) throw pluginError('provider_incompatible')
  const checkpointObservation = async (): Promise<VerifiedRemoteDocument> => {
    const result = await deviceCommand('resolve', randomUUID())
    const checkpoint = result.checkpoint as Checkpoint | undefined
    if (!checkpoint || !Number.isSafeInteger(checkpoint.document_version) || !Number.isSafeInteger(checkpoint.registry_version)
      || !/^sha256:[A-Za-z0-9_-]{43}$/u.test(checkpoint.document_hash) || !result.document || typeof result.document !== 'object') throw pluginError('provider_incompatible')
    return { document: result.document as JsonValue, evidence: { documentVersion: checkpoint.document_version,
      registryVersion: checkpoint.registry_version, documentDigest: checkpoint.document_hash } }
  }
  const backend: PublicationBackend = {
    origin, clientId: id => { if (id !== documentId) throw pluginError('invalid_request'); return clientId },
    prepare: async (id, publication) => {
      if (id !== documentId || !('schema_version' in publication)) throw pluginError('invalid_request')
      return await deviceCommand('prepare', publication.operation_id, { publication: publication as PublicationIntentV2 }) as unknown as PreparedClientMaterials
    },
    activate: async (id, operationId) => {
      if (id !== documentId) throw pluginError('invalid_request')
      return await deviceCommand('activate', randomUUID(), { publication_operation_id: operationId }) as unknown as PreparedClientMaterials
    },
    readPublic: async (id, part) => {
      if (id !== documentId) throw pluginError('invalid_request')
      const response = await send(new Request(`${origin}/user-service/v1/agent-clients/${id}/${part}`, { redirect: 'manual', signal: AbortSignal.timeout(15000) }))
      if (response.status !== 200 || response.redirected) { await response.body?.cancel(); throw pluginError('provider_unavailable') }
      const text = await response.text()
      input.assertCurrent?.()
      if (Buffer.byteLength(text) > 32768) throw pluginError('provider_incompatible')
      parsePublicJson(text)
      return text
    },
    publishDocument: async (reference, session: ProviderDocumentChangeSession, assertActive) => {
      if (JSON.stringify(reference) !== JSON.stringify(reference)) throw pluginError('invalid_request')
      await assertActive()
      if (await session.hostPhase() === 'publication_uncertain') {
        await session.reconcile(await checkpointObservation()); return
      }
      const candidate = await session.candidate()
      const previous = await input.withNative(native => native.publicIdentity(reference))
      const oldDocument = previous.document as Record<string, unknown>
      const nextDocument = candidate.candidateDocument as Record<string, unknown>
      const methods = (document: Record<string, unknown>) => ((document.authentication ?? []) as string[])
      const oldKeys = methods(oldDocument); const nextKeys = methods(nextDocument)
      const add = nextKeys.filter(key => !oldKeys.includes(key)); const remove = oldKeys.filter(key => !nextKeys.includes(key))
      const [current, auth] = await Promise.all([registry(), credential()])
      const base = candidate.baseEvidence
      if (!base || current.checkpoint.document_version !== base.documentVersion || current.checkpoint.registry_version !== base.registryVersion
        || current.checkpoint.document_hash !== base.documentDigest && current.checkpoint.document_hash !== 'sha256:' + base.documentDigest) throw pluginError('catalog_conflict')
      const method = add.length || remove.length ? 'device_oauth_keys_update' : 'device_document_update'
      const params: Record<string, unknown> = { operation_id: candidate.operationId, expected_document_version: base.documentVersion,
        expected_document_hash: base.documentDigest.startsWith('sha256:') ? base.documentDigest : 'sha256:' + base.documentDigest, expected_registry_version: base.registryVersion,
        authorizing_device_id: auth.deviceId, new_document: candidate.candidateDocument,
        ...(method === 'device_oauth_keys_update' ? { add_key_ids: add, remove_key_ids: remove } : {}) }
      const bound = await input.credentials.reserveOperation(reference, origin, method + ':' + candidate.operationId, params)
      bound.authorizing_device_proof = await proof(method, bound)
      const attempt = await session.beginPublication()
      try {
        await assertActive()
        await rpc(method, bound)
      } catch {
        await session.complete(attempt, { result: 'unknown' }); throw pluginError('provider_unavailable')
      }
      const observation = await checkpointObservation()
      await assertActive()
      // Reconcile compares the authoritative remote digest/document with the native pending candidate.
      await session.complete(attempt, { result: 'unknown' })
      await session.reconcile(observation)
    },
  }
  async function execute(command: PapCallbackRegisterOperation): Promise<PapCallbackRegistrationResult>
  async function execute(command: PapCallbackClaimOperation): Promise<PapCallbackClaimResult>
  async function execute(command: PapCallbackOperation): Promise<PapCallbackRegistrationResult | PapCallbackClaimResult> {
    try {
      await input.assertActive?.()
      const parsed = PapCallbackOperationSchema.safeParse(command)
      if (!parsed.success) throw pluginError('invalid_request')
      const value = parsed.data
      if (value.action === 'pap-callback-register') {
        exactHttps(value.callback.issuer)
        const expiry = Date.parse(value.callback.expires_at)
        if (expiry <= Date.now() || expiry > Date.now() + 600000) throw pluginError('invalid_request')
        if (value.callback.client_id !== clientId || value.callback.redirect_uri !== origin + '/user-service/v1/pap-callback') throw pluginError('invalid_request')
        const result = await deviceResponse(value.action, value.operationId, { callback: value.callback })
        const registered = PapCallbackRegistrationResultSchema.safeParse(result)
        if (!registered.success || result.did !== reference.did || result.document_id !== documentId
          || registered.data.transaction_id !== value.callback.transaction_id || registered.data.callback_uri !== value.callback.redirect_uri
          || registered.data.expires_at !== value.callback.expires_at) throw pluginError('provider_incompatible')
        return { transaction_id: registered.data.transaction_id, callback_uri: registered.data.callback_uri, expires_at: registered.data.expires_at }
      }
      // Claim results contain private business data and never use the publisher response or replay ledger.
      const result = await deviceResponse(value.action, value.operationId, { callback: value.callback })
      const claimed = PapCallbackClaimResultSchema.safeParse(result)
      if (!claimed.success) throw pluginError('provider_incompatible')
      exactHttps(claimed.data.iss)
      return claimed.data
    } catch (error) {
      if (error instanceof PapCallbackManagementError || error instanceof AnpIdentityPluginError) throw error
      throw pluginError('provider_unavailable')
    }
  }
  return { reference: structuredClone(reference), documentId, backend, readVerifiedDocument: checkpointObservation, execute }
}

/** Registration fields supplied through the trusted Host management flow, never persisted in the catalog. */
export interface LocalRegistrationInput {
  handle: string
  phone?: string
  otp_code?: string
  email?: string
  invite_code?: string
  name?: string
  registration_operation_id?: string
}
/** Register a locally held E1 Manifest and retain only a live, server-verified device credential.
 * @param input - Local identity, registration confirmation and protected broker.
 * @returns Public registration facts. No Access Token is returned.
 */
export async function registerLocalIdentity(input: {
  reference: IdentityReference; origin: string; registration: LocalRegistrationInput; credentials: ManagementCredentialBroker
  withNative<T>(operation: (native: ProviderLease) => Promise<T>): Promise<T>
  fetch?: typeof fetch
  managementAudience?: string
  handleDomain?: string
  assertActive?: () => void
}): Promise<{ did: string; deviceId: string; state: 'registered' }> {
  input.assertActive?.()
  const origin = exactHttps(input.origin)
  if (new URL(origin).origin !== origin || !input.reference.did.startsWith('did:wba:') && !input.reference.did.startsWith('did:web:')) throw pluginError('provider_incompatible')
  const identity = await input.withNative(native => native.publicIdentity(input.reference))
  input.assertActive?.()
  const document = identity.document as Record<string, unknown>
  // The live Registry below is authoritative; this list only identifies the locally held candidate key.
  const candidates = identity.activeKeys.filter(key => key.purposes.includes('device_assertion'))
  const web = input.reference.did.startsWith('did:web:')
  if (candidates.length !== 1 || !web && !document.proof) throw pluginError('provider_incompatible')
  const registration = structuredClone(input.registration)
  let bootstrap: unknown
  if (web) {
    if (!registration.registration_operation_id || !input.managementAudience) throw pluginError('invalid_request')
    const projection = webRegistrationProjection({ document: identity.document, registration, audience: input.managementAudience, handleDomain: input.handleDomain ?? new URL(origin).hostname })
    bootstrap = await input.withNative(async native => {
      const signer = (native as unknown as { signWebRegistrationProof?: (ref: IdentityReference, request: unknown) => Promise<unknown> }).signWebRegistrationProof
      if (typeof signer !== 'function') throw pluginError('provider_incompatible')
      return signer.call(native, input.reference, { key: { kid: candidates[0]!.kid }, business_projection: projection })
    })
  } else if (registration.registration_operation_id) throw pluginError('invalid_request')
  const transport = input.fetch ?? fetch
  const send: typeof fetch = async (request, init) => {
    input.assertActive?.()
    const response = await transport(request, init)
    try { input.assertActive?.(); return response }
    catch (error) { await response.body?.cancel(); throw error }
  }
  const response = await send(new Request(origin + '/user-service/v1/did-auth/rpc', { method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(15000),
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: randomUUID(), method: 'register',
      params: { ...registration, did_document: identity.document, is_agent: true, ...(bootstrap ? { bootstrap_proof: bootstrap } : {}) } }) }))
  if (response.status !== 200 || response.redirected) { await response.body?.cancel(); throw pluginError('provider_unavailable') }
  const bytes = await response.text()
  input.assertActive?.()
  if (Buffer.byteLength(bytes) > 32768) throw pluginError('provider_incompatible')
  const envelope = parsePublicJson(bytes) as { result?: Record<string, unknown>; error?: unknown }
  const result = envelope.result
  if (envelope.error || result?.state !== 'registered' || result.did !== input.reference.did || typeof result.access_token !== 'string') throw pluginError('provider_unavailable')
  const token = result.access_token
  const registryResponse = await send(new Request(origin + '/user-service/v1/did-auth/rpc', { method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(15000),
    headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: randomUUID(), method: 'device_registry_get', params: {} }) }))
  if (registryResponse.status !== 200 || registryResponse.redirected) { await registryResponse.body?.cancel(); throw pluginError('provider_unavailable') }
  const registryBytes = await registryResponse.text()
  input.assertActive?.()
  if (Buffer.byteLength(registryBytes) > 32768) throw pluginError('provider_incompatible')
  const registryEnvelope = parsePublicJson(registryBytes) as { result?: Registry; error?: unknown }
  const registry = registryEnvelope.result
  const device = registry?.devices.find(device => device.signing_key_id === candidates[0]!.kid)
  if (registryEnvelope.error || registry?.did !== input.reference.did || !device || device.status !== 'active'
    || device.role !== 'admin' || !device.management_ready) throw pluginError('provider_unavailable')
  await input.credentials.set(input.reference, origin, { accessToken: token, deviceId: device.device_id, signingKeyId: device.signing_key_id, ...(web ? { audience: input.managementAudience! } : {}) })
  input.assertActive?.()
  await input.withNative(native => native.adoptVerifiedDocument(input.reference, { document: identity.document,
    evidence: { documentVersion: registry.checkpoint.document_version, registryVersion: registry.checkpoint.registry_version, documentDigest: registry.checkpoint.document_hash } }))
  input.assertActive?.()
  return { did: input.reference.did, deviceId: device.device_id, state: 'registered' }
}

/** RFC 8785 serialization for native-produced JSON values.
 * @param value - Finite JSON data, with keys ordered by UTF-16 code units.
 * @returns Canonical UTF-8 text.
 */
export function canonicalManagementJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) throw pluginError('invalid_request')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalManagementJson).join(',') + ']'
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonicalManagementJson(value[key]!)).join(',') + '}'
}
/** Construct the exact Web registration business projection; OTP and proof freshness are excluded.
 * @param input - Public local document and the explicit registration account/profile fields.
 * @returns Projection checked by the local native signer and User Service.
 */
export function webRegistrationProjection(input: { document: JsonValue; registration: LocalRegistrationInput; audience: string; handleDomain: string }): JsonValue {
  const document = input.document as Record<string, JsonValue>
  const manifest = document.deviceManifest as { devices?: Array<Record<string, JsonValue>> } | undefined
  const device = manifest?.devices?.[0]
  if (manifest?.devices?.length !== 1 || !device || !input.registration.registration_operation_id) throw pluginError('invalid_request')
  const digest = (value: string) => 'sha256:' + createHash('sha256').update(value).digest('base64url')
  const phone = input.registration.phone
  if (phone && !/^\+[1-9][0-9]{6,14}$/u.test(phone)) throw pluginError('invalid_request')
  const handle = input.registration.handle.trim().toLowerCase()
  return { contract: 'awiki.register.web.v1', audience: input.audience, registration_operation_id: input.registration.registration_operation_id,
    full_handle: handle + '.' + input.handleDomain, did: document.id!,
    bootstrap_device: { device_id: device.device_id!, signing_key_id: device.signing_key_id!, e2ee_key_id: device.e2ee_key_id! },
    document_hash: digest(canonicalManagementJson(input.document)), account: { phone: phone ?? null, email: input.registration.email?.trim().toLowerCase() ?? null },
    profile: { name: input.registration.name ?? null, avatar: null, role: null, endpoint_url: null, description: null, is_public: false, is_agent: true },
    invite_code_hash: input.registration.invite_code ? digest(input.registration.invite_code.trim()) : null }
}
