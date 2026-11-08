/** Private Host orchestration from a real creation approval to verified device publication. */
import type { Context } from '@deepseek-ai/cordis'
import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import type AnpIdentityService from './index.js'
import type { IdentityManagement } from './management-types.js'
import type { HostManagementSecret, HostManagementSecretContext } from './host-management-secret.js'
import { createHash, randomUUID } from 'node:crypto'
import { lstat, mkdir, open, readFile, readdir, realpath, rename, unlink } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
import { setTimeout } from 'node:timers/promises'
import lockfile from 'proper-lockfile'
import { z } from 'zod'
import { EncryptedManagementCredentialBroker } from './management-credentials.js'
import { exactHttps, parsePublicJson, publicationRedirectUri } from './publication-http.js'
import { PublicationCapabilitiesSchema } from './publication-types.js'
import { PROTOCOL_BOOTSTRAP_CONSUMER } from './protocol-bootstrap.js'
import { syncDirectory } from './sync-directory.js'
import { identityClientVersionHeader } from './client-metadata.js'

export const RegistrationBootstrapConfigSchema = z.object({
  id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/u),
  requestId: z.string().min(1).max(128),
  stateRoot: z.string().refine(isAbsolute),
  origin: z.string().refine(value => { try { return new URL(exactHttps(value)).origin === value } catch { return false } }),
  email: z.string().email().max(254).transform(value => value.trim().toLowerCase()).optional(),
  phone: z.string().regex(/^\+[1-9][0-9]{6,14}$/u).optional(),
  clientName: z.string().trim().min(1).max(128),
  capabilities: PublicationCapabilitiesSchema.default({ mcpMachine: true, papSession: false, papAccount: false }),
  redirectUris: z.array(z.string().max(2048)).max(8).default([]),
  managementAudience: z.string().min(1).max(256).default('awiki-user-service'),
  pollIntervalMs: z.number().int().min(100).max(60000).default(5000),
  providerReadyTimeoutMs: z.number().int().min(1000).max(60000).default(10000),
}).strict().superRefine((value, context) => {
  if (Boolean(value.email) === Boolean(value.phone)) {
    context.addIssue({ code: 'custom', message: 'Select exactly one registration contact method' })
  }
  if (value.capabilities.papAccount && value.redirectUris.length === 0
    || new Set(value.redirectUris).size !== value.redirectUris.length) {
    context.addIssue({ code: 'custom', message: 'Invalid protocol callback configuration', path: ['redirectUris'] })
  }
  for (const uri of value.redirectUris) {
    try { publicationRedirectUri(uri, value.capabilities) }
    catch { context.addIssue({ code: 'custom', message: 'Invalid protocol callback configuration', path: ['redirectUris'] }) }
  }
})
export type RegistrationBootstrapConfig = z.infer<typeof RegistrationBootstrapConfigSchema>
export type RegistrationBootstrapInput = z.input<typeof RegistrationBootstrapConfigSchema>
export type RegistrationBootstrapPhase = 'awaiting_approval' | 'awaiting_email_verification' | 'awaiting_phone_verification' | 'registering'
  | 'publishing' | 'published' | 'registration_uncertain' | 'blocked' | 'disposed'
export type RegistrationBootstrapReason = 'approval_unavailable' | 'approval_denied' | 'invalid_configuration'
  | 'credential_unavailable' | 'email_unavailable' | 'phone_unavailable' | 'provider_unavailable' | 'publication_failed' | 'client_upgrade_required'
/** Safe manager/UI projection; no factor, credential, key or remote response is returned. */
export interface RegistrationBootstrapStatus {
  id: string
  requestId: string
  phase: RegistrationBootstrapPhase
  origin?: string
  clientVersion?: string
  reason?: RegistrationBootstrapReason
  reference?: IdentityReference
  clientId?: string
}
export interface RegistrationBootstrapController {
  submitOtp(code: string): void
  status(): RegistrationBootstrapStatus
  dispose(): Promise<void>
}
const JournalSchema = z.object({
  schema: z.literal(1), fingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
  emailAttempted: z.boolean(), phoneAttempted: z.boolean().default(false), phoneDelivered: z.boolean().default(false),
  registerStarted: z.boolean(), registered: z.boolean(),
  webOperationId: z.string().uuid().optional(),
}).strict()
type Journal = z.infer<typeof JournalSchema>
const digest = (value: string) => createHash('sha256').update(value).digest('hex')

class BootstrapUpgradeRequired extends Error {
  readonly code = 'client_upgrade_required'
  constructor(readonly registrationRejected: boolean) { super('The identity client requires an admission upgrade.') }
}
class BootstrapCredentialStateUnavailable extends Error {
  readonly code = 'credential_unavailable'
  constructor() { super('The management credential state is unavailable.') }
}

async function responseObject(response: Response, maximum: number, cancelPeer?: () => void): Promise<Record<string, unknown>> {
  const reader = response.body?.getReader(); const chunks: Uint8Array[] = []; let size = 0
  try {
    while (reader) { const part = await reader.read(); if (part.done) break; size += part.value.length; if (size > maximum) throw new Error('bootstrap_response_unavailable'); chunks.push(part.value) }
    const value = parsePublicJson(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('bootstrap_response_unavailable')
    return value as Record<string, unknown>
  } catch (error) { cancelPeer?.(); throw error }
  finally { await reader?.cancel(); reader?.releaseLock() }
}

function clientVersionHeader(): string {
  return identityClientVersionHeader(JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')))
}

/** Install the configured manager-owned flow. Its caller supplies the actual management facade and Context.
 * @param options - Non-secret configuration, actual Host management authority and optional HTTP transport.
 * @returns A safe status projection and quiescent disposer.
 */
export function startRegistrationBootstrap(options: {
  context: Context
  service: AnpIdentityService
  manager: IdentityManagement
  config: RegistrationBootstrapConfig
  fetch?: typeof fetch
}): RegistrationBootstrapController {
  const config = RegistrationBootstrapConfigSchema.parse(options.config)
  const controller = new AbortController()
  const header = clientVersionHeader()
  const fingerprint = digest(JSON.stringify(config))
  const startedAt = Date.now()
  let view: RegistrationBootstrapStatus = { id: config.id, requestId: config.requestId, phase: 'awaiting_approval', origin: config.origin, clientVersion: header }
  let secret: HostManagementSecret | undefined
  let broker: EncryptedManagementCredentialBroker | undefined
  let root: string | undefined
  let brokerRoot: string | undefined
  let providerFence: (() => void) | undefined
  let pinnedReference: IdentityReference | undefined
  let manager = options.manager
  let backend: Awaited<ReturnType<AnpIdentityService['configureManagedPublicationBackend']>> | undefined
  let otpCode: string | undefined
  const assertManagerActive = () => {
    controller.signal.throwIfAborted()
    // This assertion retains the real manager Loader identity; it never accepts a caller string.
    options.service.acquireManagement(options.context)
  }
  const assertActive = () => { assertManagerActive(); providerFence?.() }
  const update = (phase: RegistrationBootstrapPhase, reason?: RegistrationBootstrapReason) => {
    view = { ...view, phase }; delete view.reason
    if (reason) view.reason = reason
  }
  const send: typeof fetch = async (input, init) => {
    assertActive()
    const request = new Request(input, init)
    if (new URL(request.url).origin !== config.origin) throw new Error('bootstrap_origin_mismatch')
    request.headers.set('X-AWiki-Client-Version', header)
    const isRegister = request.method === 'POST' && new URL(request.url).pathname === '/user-service/v1/did-auth/rpc'
      && (await request.clone().json() as { method?: unknown }).method === 'register'
    assertActive()
    const reply = await (options.fetch ?? fetch)(new Request(request, {
      redirect: 'manual', signal: AbortSignal.any([request.signal, controller.signal]),
    }))
    try {
      assertActive()
      if ((reply.headers.get('content-type') ?? '').startsWith('application/json')) {
        const envelope = await responseObject(reply.clone(), 131072, () => { void reply.body?.cancel().catch(() => {}) })
        assertActive()
        const error = envelope.error as { data?: { awiki_code?: unknown } } | undefined
        if (error?.data?.awiki_code === 'client.upgrade_required') {
          await reply.body?.cancel(); throw new BootstrapUpgradeRequired(isRegister)
        }
      }
      assertActive(); return reply
    } catch (error) { await reply.body?.cancel(); throw error }
  }
  const json = async (request: Request): Promise<Record<string, unknown>> => {
    const response = await send(request)
    if (response.status !== 200 || response.redirected || !(response.headers.get('content-type') ?? '').startsWith('application/json')) {
      await response.body?.cancel(); throw new Error(config.phone ? 'bootstrap_phone_unavailable' : 'bootstrap_email_unavailable')
    }
    const value = await responseObject(response, 32768)
    assertActive(); return value
  }
  const setup = async () => {
    if (root) return
    await mkdir(config.stateRoot, { recursive: true, mode: 0o700 })
    assertActive()
    const base = await realpath(config.stateRoot)
    assertActive()
    if ((await lstat(base)).mode & 0o077) throw new Error('bootstrap_state_unavailable')
    root = join(base, 'registration-bootstrap', digest(config.id))
    await mkdir(root, { recursive: true, mode: 0o700 })
    assertActive()
    const rootInfo = await lstat(root)
    if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error('bootstrap_state_unavailable')
    brokerRoot = join(root, 'credentials')
    await mkdir(brokerRoot, { recursive: true, mode: 0o700 })
    assertActive()
    const brokerInfo = await lstat(brokerRoot)
    if (!brokerInfo.isDirectory() || brokerInfo.isSymbolicLink()) throw new Error('bootstrap_state_unavailable')
    const { createHostManagementSecret } = await import('./host-management-secret.js')
    assertActive()
    secret = createHostManagementSecret({
      context: { get credentials() { return options.context.get('credentials') as HostManagementSecretContext['credentials'] } },
      stateRoot: brokerRoot, bootstrapId: config.id, assertActive,
      hasExistingCiphertext: async () => {
        try {
          const info = await lstat(brokerRoot!)
          if (!info.isDirectory() || info.isSymbolicLink()) return true
          const entries = await readdir(brokerRoot!, { withFileTypes: true })
          return entries.some(entry => !(entry.isDirectory() && /^[a-f0-9]{64}\.json\.lock$/u.test(entry.name)))
        } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false; throw error }
      },
    })
    broker = new EncryptedManagementCredentialBroker(brokerRoot, () => secret!.getKey())
  }
  const establishKey = async (requireExisting: boolean) => {
    const marker = join(brokerRoot!, '.key-established')
    if (requireExisting) {
      try {
        const info = await lstat(marker)
        assertActive()
        if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077)) throw new BootstrapCredentialStateUnavailable()
      } catch { throw new BootstrapCredentialStateUnavailable() }
    }
    const key = await secret!.getKey()
    try { assertActive() } finally { key.fill(0) }
    let file
    try { file = await open(marker, 'wx', 0o600) }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      const info = await lstat(marker)
      if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077)) throw new Error('bootstrap_state_unavailable')
      assertActive(); return
    }
    try { assertActive(); await file.writeFile('1\n'); assertActive(); await file.sync(); assertActive() } finally { await file.close() }
    await syncDirectory(brokerRoot!)
    assertActive()
  }
  const journal = async (): Promise<Journal> => {
    try {
      const path = join(root!, 'state.json'); const info = await lstat(path)
      if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) || info.size > 16384) throw new Error('bootstrap_state_unavailable')
      const value = JournalSchema.parse(JSON.parse(await readFile(path, 'utf8')))
      assertActive()
      if (value.fingerprint !== fingerprint) throw new Error('bootstrap_configuration_changed')
      return value
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
      return { schema: 1, fingerprint, emailAttempted: false, phoneAttempted: false, phoneDelivered: false, registerStarted: false, registered: false }
    }
  }
  const save = async (value: Journal) => {
    assertActive()
    const temporary = join(root!, 'state-' + randomUUID())
    const handle = await open(temporary, 'wx', 0o600)
    try { assertActive(); await handle.writeFile(JSON.stringify(value)); assertActive(); await handle.sync(); assertActive() } finally { await handle.close() }
    try { assertActive(); await rename(temporary, join(root!, 'state.json')); assertActive(); await syncDirectory(root!); assertActive() } finally { await unlink(temporary).catch(() => {}) }
  }
  const step = async () => {
    assertActive()
    let review
    try { review = await manager.getRequest(config.requestId) }
    catch (error) {
      const code = (error as { code?: unknown }).code
      if (code === 'invalid_request' || code === 'provider_unavailable' && !providerFence && Date.now() - startedAt < config.providerReadyTimeoutMs) {
        update('awaiting_approval', code === 'provider_unavailable' ? 'approval_unavailable' : undefined); return
      }
      throw error
    }
    assertActive()
    const request = review.request
    if (request.kind !== 'create' || request.caller.consumer !== PROTOCOL_BOOTSTRAP_CONSUMER || request.parameters.usage !== 'protocol') {
      update('blocked', 'invalid_configuration'); return
    }
    if (request.status === 'pending' || request.status === 'approved' && (request.executionStatus === 'running' || request.executionStatus === 'unknown')) { update('awaiting_approval'); return }
    if (request.status !== 'approved' || request.executionStatus !== 'succeeded' || !request.result) { update('blocked', 'approval_denied'); return }
    const reference = structuredClone(request.result.reference)
    if (!providerFence) {
      providerFence = await options.service.pinManagementContext(options.context, reference, assertManagerActive)
      pinnedReference = structuredClone(reference)
      manager = options.service.acquireManagement(options.context, providerFence)
    }
    assertActive()
    if (pinnedReference!.storeId !== reference.storeId || pinnedReference!.identityId !== reference.identityId
      || pinnedReference!.did !== reference.did) { update('blocked', 'invalid_configuration'); return }
    const domain = request.parameters.domain
    const fullHandle = request.parameters.handle
    const suffix = '.' + domain
    if (!fullHandle || !fullHandle.endsWith(suffix) || !/^[a-z0-9][a-z0-9_-]*$/u.test(fullHandle.slice(0, -suffix.length))) {
      update('blocked', 'invalid_configuration'); return
    }
    const handle = fullHandle.slice(0, -suffix.length)
    view.reference = reference
    await setup()
    assertActive()
    let release: (() => Promise<void>) | undefined
    try { release = await lockfile.lock(root!, { realpath: false, retries: 0 }) }
    catch (error) { if ((error as NodeJS.ErrnoException).code === 'ELOCKED') return; throw error }
    try {
      assertActive()
      const state = await journal()
      await establishKey(state.emailAttempted || state.phoneAttempted || state.registerStarted || state.registered)
      if (!state.registered) {
        if (state.registerStarted) { update('registration_uncertain'); return }
        if (config.phone) {
          if (!state.phoneAttempted) {
            state.phoneAttempted = true; await save(state)
            const id = randomUUID()
            const receipt = await json(new Request(config.origin + '/user-service/v1/handle/rpc', { method: 'POST',
              signal: AbortSignal.timeout(15000), headers: { 'content-type': 'application/json' },
              body: JSON.stringify({ jsonrpc: '2.0', id, method: 'send_otp', params: {
                phone: config.phone, purpose: 'awiki.identity.register.v1', handle, domain, full_handle: fullHandle,
              } }) }))
            const result = receipt.result as { ok?: unknown } | undefined
            if (receipt.jsonrpc !== '2.0' || receipt.id !== id || receipt.error || result?.ok !== true) {
              throw new Error('bootstrap_phone_unavailable')
            }
            state.phoneDelivered = true; await save(state)
          }
          if (!state.phoneDelivered) throw new Error('bootstrap_phone_unavailable')
          update('awaiting_phone_verification')
          if (!otpCode) return
        } else {
          const statusUrl = new URL(config.origin + '/user-service/v1/auth/email-status')
          statusUrl.searchParams.set('email', config.email!); statusUrl.searchParams.set('handle', fullHandle)
          const verified = await json(new Request(statusUrl, { signal: AbortSignal.timeout(15000), cache: 'no-store' }))
          if (typeof verified.verified !== 'boolean') throw new Error('bootstrap_email_unavailable')
          if (!verified.verified) {
            update('awaiting_email_verification')
            if (!state.emailAttempted) {
              state.emailAttempted = true; await save(state)
              await json(new Request(config.origin + '/user-service/v1/auth/email-send', { method: 'POST',
                signal: AbortSignal.timeout(15000), headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ email: config.email, handle: fullHandle }) }))
            }
            return
          }
        }
        if (reference.did.startsWith('did:web:')) state.webOperationId ??= randomUUID()
        state.registerStarted = true; await save(state); update('registering')
        let registrationActive = true
        const assertInitialRegistration = () => {
          assertActive()
          if (!registrationActive || !state.registerStarted || state.registered || view.phase !== 'registering') throw new Error('bootstrap_registration_unavailable')
        }
        try {
          await options.service.registerLocalIdentity(options.context, { reference, origin: config.origin, credentials: broker!, fetch: send,
            assertActive: assertInitialRegistration,
            handleDomain: domain, managementAudience: config.managementAudience,
            registration: { handle, ...(config.phone ? { phone: config.phone, otp_code: otpCode! } : { email: config.email! }),
              ...(state.webOperationId ? { registration_operation_id: state.webOperationId } : {}) } })
          state.registered = true; await save(state)
        } catch (error) {
          if (error instanceof BootstrapUpgradeRequired && error.registrationRejected) {
            state.registerStarted = false; await save(state); update('blocked', 'client_upgrade_required'); return
          }
          update('registration_uncertain', error instanceof BootstrapUpgradeRequired ? 'client_upgrade_required' : undefined); return
        } finally { registrationActive = false; otpCode = undefined }
      }
      assertActive(); update('publishing')
      if (!backend) {
        const candidate = await options.service.configureManagedPublicationBackend(options.context, 'bootstrap-' + config.id,
          { reference, origin: config.origin, credentials: broker!, fetch: send })
        try { assertActive() } catch (error) { candidate.dispose(); throw error }
        backend = candidate
      }
      assertActive()
      const current = await manager.publicationStatus(reference)
      assertActive()
      const published = await manager.publishIdentity({ reference, config: {
        backend: backend.backend, documentId: backend.documentId, clientName: config.clientName, capabilities: config.capabilities,
        redirectUris: config.redirectUris, activeKid: current.algorithm === 'ES256' && current.keyId ? current.keyId : reference.did + '#oauth',
      } })
      if (!published.clientId || new URL(exactHttps(published.clientId, true)).origin !== config.origin) throw new Error('bootstrap_publication_failed')
      if (published.state !== 'published' || published.did !== reference.did || published.algorithm !== 'ES256'
        || JSON.stringify(published.capabilities) !== JSON.stringify(config.capabilities)) throw new Error('bootstrap_publication_failed')
      assertActive(); view.clientId = published.clientId; update('published')
    } finally { await release() }
  }
  const pending = (async () => {
    try {
      while (!controller.signal.aborted) {
        await step()
        if (view.phase === 'blocked' || view.phase === 'published' || view.phase === 'registration_uncertain') return
        await setTimeout(config.pollIntervalMs, undefined, { signal: controller.signal })
      }
    } catch (error) {
      if (controller.signal.aborted) return
      const code = (error as { code?: unknown }).code
      update('blocked', code === 'client_upgrade_required' ? 'client_upgrade_required'
        : code === 'credential_unavailable' ? 'credential_unavailable'
        : (error as Error).message === 'bootstrap_email_unavailable' ? 'email_unavailable'
          : (error as Error).message === 'bootstrap_phone_unavailable' ? 'phone_unavailable'
          : view.phase === 'publishing' ? 'publication_failed' : 'provider_unavailable')
    }
  })()
  return {
    submitOtp(code) {
      assertActive()
      if (!config.phone || view.phase !== 'awaiting_phone_verification' || otpCode !== undefined || !/^[0-9]{6}$/u.test(code)) {
        throw new Error('bootstrap_otp_unavailable')
      }
      otpCode = code
    },
    status: () => structuredClone(view),
    async dispose() {
      controller.abort(); otpCode = undefined; secret?.dispose(); backend?.dispose(); await pending
      update('disposed')
    },
  }
}
