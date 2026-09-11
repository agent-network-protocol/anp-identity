import { createHash, randomUUID } from 'node:crypto'
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import lockfile from 'proper-lockfile'
import { normalizeHandle } from './catalog.js'
import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import type {
  AccessAuthorizationRequest, AuthorizationDecision, AuthorizationExecution,
  AuthorizationGrant, AuthorizationOptions, AuthorizationRequest, AuthorizationState,
  AuthorizedLease, CapabilitySnapshot, ControlledOperation, CreateAuthorizationRequest,
  CreateParameters, CreateResult, DeletionReconciliation, RequestAccessInput, RequestCreateInput, VerifiedCaller,
} from './authorization-types.js'

export * from './authorization-types.js'
const SCHEMA = 'anp-identity-authorization/1' as const
const ORDINARY = ['identity:read', 'identity:sign', 'identity:http-auth'] as const
const FIVE_MINUTES = 300_000
const SEVEN_DAYS = 7 * 24 * 60 * 60_000

export class AuthorizationError extends Error {
  constructor(readonly code: string) { super(code); this.name = 'AuthorizationError' }
}
function fail(code: string): never { throw new AuthorizationError(code) }
function copy<T>(value: T): T { return structuredClone(value) }
function digest(value: unknown): string { return createHash('sha256').update(canonical(value)).digest('hex') }
function canonical(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value)
  if (value instanceof Uint8Array) return canonical({ bytes: Buffer.from(value).toString('base64') })
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (typeof value === 'object' && value !== null && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`
  }
  return fail('invalid_operation_payload')
}
function text(value: unknown, max = 1000): string {
  if (typeof value !== 'string' || !value.trim() || value.length > max || /[\u0000-\u001f\u007f]/u.test(value)) fail('invalid_authorization_input')
  return value
}
function reference(value: IdentityReference): IdentityReference {
  return { storeId: text(value.storeId, 512), identityId: text(value.identityId, 512), did: text(value.did, 4096) }
}
function equalIdentity(a: IdentityReference, b: IdentityReference): boolean {
  return a.storeId === b.storeId && a.identityId === b.identityId && a.did === b.did
}
function caller(value: VerifiedCaller): VerifiedCaller {
  return { consumer: text(value.consumer, 256), displayName: text(value.displayName, 256) }
}
function operation(value: ControlledOperation): ControlledOperation {
  if (!ORDINARY.includes(value.capability) || !/^[a-f0-9]{64}$/u.test(value.fingerprint)) fail('invalid_operation')
  const result: ControlledOperation = {
    capability: value.capability, fingerprint: value.fingerprint, summary: text(value.summary, 1024),
    ...(value.signingPurpose === undefined ? {} : { signingPurpose: text(value.signingPurpose, 256) }),
    ...(value.httpOrigin === undefined ? {} : { httpOrigin: origin(value.httpOrigin) }),
  }
  if ((result.capability === 'identity:sign') !== (result.signingPurpose !== undefined)
    || (result.capability === 'identity:http-auth') !== (result.httpOrigin !== undefined)) fail('invalid_operation')
  return result
}
function origin(value: string): string {
  let parsed: URL
  try { parsed = new URL(value) } catch { return fail('invalid_http_origin') }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.origin !== value) fail('invalid_http_origin')
  return parsed.origin
}
function snapshot(value: CapabilitySnapshot): CapabilitySnapshot {
  if (value.capabilities.length !== ORDINARY.length || ORDINARY.some(cap => !value.capabilities.includes(cap))) fail('incompatible_identity_capabilities')
  return {
    version: text(value.version, 256), capabilities: [...ORDINARY],
    signingPurposes: [...new Set(value.signingPurposes.map(v => text(v, 256)))].sort(),
    httpOrigins: [...new Set(value.httpOrigins.map(origin))].sort(),
  }
}
function permits(policy: CapabilitySnapshot, value: ControlledOperation): boolean {
  return policy.capabilities.includes(value.capability)
    && (value.signingPurpose === undefined || policy.signingPurposes.includes(value.signingPurpose))
    && (value.httpOrigin === undefined || policy.httpOrigins.includes(value.httpOrigin))
}

/** Compute at the Host boundary from the actual immutable operation, not a plugin-provided digest. */
export function freezeOperation(
  descriptor: Omit<ControlledOperation, 'fingerprint'>,
  canonicalPayload: unknown,
): ControlledOperation {
  return operation({ ...descriptor, fingerprint: digest({ descriptor, payload: canonicalPayload }) })
}

/** Persistent non-secret authorization ledger. Caller authentication belongs to the Host. */
export class AuthorizationEngine {
  readonly statePath: string
  readonly #lockPath: string
  readonly #now: () => number
  readonly #listeners = new Set<() => void>()
  constructor(readonly stateRoot: string, readonly options: AuthorizationOptions) {
    this.statePath = join(stateRoot, 'authorization-v1.json')
    this.#lockPath = join(stateRoot, 'authorization-v1.lock')
    this.#now = options.now ?? Date.now
    for (const ttl of [options.requestTtlMs, options.onceTtlMs, options.leaseTtlMs]) {
      if (ttl !== undefined && (!Number.isSafeInteger(ttl) || ttl <= 0)) fail('invalid_authorization_ttl')
    }
  }

  async initialize(): Promise<void> {
    await mkdir(this.stateRoot, { recursive: true, mode: 0o700 })
    await this.#locked(async () => {
      try { await this.#read() } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
        await this.#write({ schema: SCHEMA, generation: 0, requests: [], grants: [], executions: [], deletedIdentities: [], deletingIdentities: [], suppressions: [] })
      }
    })
  }

  subscribeRequestChanges(listener: () => void): () => void {
    this.#listeners.add(listener)
    return () => { this.#listeners.delete(listener) }
  }

  async requestCreate(verifiedCaller: VerifiedCaller, input: RequestCreateInput): Promise<CreateAuthorizationRequest> {
    const source = caller(verifiedCaller)
    const parameters: CreateParameters = { label: text(input.parameters.label, 256), domain: text(input.parameters.domain, 253), path: text(input.parameters.path, 2048),
      ...(input.parameters.handle === undefined ? {} : { handle: normalizeHandle(text(input.parameters.handle, 128)) }) }
    const domain = new URL(`https://${parameters.domain}`)
    if (domain.host !== parameters.domain || domain.username || domain.password || domain.pathname !== '/' || !parameters.path.startsWith('/') || /[?#]/u.test(parameters.path)) fail('invalid_create_parameters')
    return this.#transaction(async state => {
      await this.options.validateCaller(source)
      return this.#request(state, source, input.requestId, input.purpose, { kind: 'create', parameters }) as CreateAuthorizationRequest
    })
  }

  async requestAccess(verifiedCaller: VerifiedCaller, input: RequestAccessInput): Promise<AccessAuthorizationRequest> {
    const source = caller(verifiedCaller)
    const details = {
      kind: 'access' as const,
      ...(input.identity === undefined ? {} : { identity: reference(input.identity) }),
      ...(input.operation === undefined ? {} : { operation: operation(input.operation) }),
    }
    return this.#snapshotTransaction(async state => {
      await this.options.validateCaller(source)
      if (details.identity !== undefined) {
        this.#identityAvailable(state, details.identity)
        const policy = snapshot(await this.options.resolveSnapshot(source, details.identity))
        if (details.operation !== undefined && !permits(policy, details.operation)) fail('operation_not_permitted')
      }
      return this.#request(state, source, input.requestId, input.purpose, details) as AccessAuthorizationRequest
    })
  }

  #request(state: AuthorizationState, source: VerifiedCaller, id: string, purpose: string,
    details: { kind: 'create'; parameters: CreateParameters } | { kind: 'access'; identity?: IdentityReference; operation?: ControlledOperation }): AuthorizationRequest {
    text(id, 256); text(purpose, 1000)
    const fingerprint = digest({ consumer: source.consumer, purpose, ...details })
    const existingId = state.requests.find(req => req.id === id)
    if (existingId !== undefined) {
      if (existingId.caller.consumer !== source.consumer || existingId.fingerprint !== fingerprint) fail('request_conflict')
      return existingId
    }
    const duplicate = state.requests.find(req => req.fingerprint === fingerprint && req.status === 'pending')
    if (duplicate !== undefined) return duplicate
    // Changing IDs, wording, or create parameters cannot bypass a user refusal.
    if (state.suppressions.some(block => block.consumer === source.consumer && block.kind === details.kind
      && (block.identity === undefined || details.kind === 'create' || details.identity === undefined || equalIdentity(block.identity, details.identity)))) fail('request_previously_denied')
    const request: AuthorizationRequest = {
      id, caller: source, purpose, fingerprint, version: 1, status: 'pending', prompted: false,
      createdAt: this.#now(), expiresAt: this.#now() + (this.options.requestTtlMs ?? SEVEN_DAYS), ...details,
    }
    state.requests.push(request)
    return request
  }

  async getRequest(verifiedCaller: VerifiedCaller, requestId: string): Promise<AuthorizationRequest> {
    return this.#transaction(async state => {
      const req = this.#findRequest(state, requestId)
      this.#owns(verifiedCaller, req.caller.consumer)
      return req
    })
  }

  async listRequests(): Promise<AuthorizationRequest[]> {
    return this.#transaction(async state => [...state.requests].sort((a, b) => b.createdAt - a.createdAt))
  }

  async markPrompted(requestId: string, expectedVersion?: number): Promise<void> {
    await this.#transaction(async state => {
      const req = this.#findRequest(state, requestId)
      if (expectedVersion !== undefined && req.version !== expectedVersion) fail('request_conflict')
      this.#replaceRequest(state, { ...req, prompted: true })
    })
  }

  async cancel(verifiedCaller: VerifiedCaller, requestId: string, expectedVersion: number): Promise<AuthorizationRequest> {
    return this.#transaction(async state => {
      const req = this.#findRequest(state, requestId)
      this.#owns(verifiedCaller, req.caller.consumer)
      this.#pending(req, expectedVersion)
      const next = { ...req, status: 'cancelled' as const, version: req.version + 1, decidedAt: this.#now() }
      this.#replaceRequest(state, next)
      return next
    })
  }

  async decide(input: AuthorizationDecision): Promise<AuthorizationRequest> {
    const decided = await this.#snapshotTransaction(async state => {
      const req = this.#findRequest(state, input.requestId)
      this.#pending(req, input.expectedVersion)
      if (input.decision === 'deny') {
        const next = { ...req, version: req.version + 1, status: 'denied' as const, decidedAt: this.#now() }
        this.#replaceRequest(state, next)
        state.suppressions.push({ consumer: req.caller.consumer, kind: req.kind, requestId: req.id,
          ...(req.kind === 'access' && req.identity !== undefined ? { identity: req.identity } : {}) })
        return next
      }
      if (input.decision !== 'approve') fail('invalid_decision')
      await this.options.validateCaller(req.caller)
      if (req.kind === 'create') {
        const next: CreateAuthorizationRequest = { ...req, version: req.version + 1, status: 'approved', decidedAt: this.#now(), operationId: randomUUID(), executionStatus: 'running' }
        this.#replaceRequest(state, next)
        return next
      }
      const selected = input.identity ?? req.identity
      if (selected === undefined) fail('identity_required')
      const identity = reference(selected)
      if (req.identity !== undefined && !equalIdentity(req.identity, identity)) fail('identity_mismatch')
      this.#identityAvailable(state, identity)
      const approvedSnapshot = snapshot(await this.options.resolveSnapshot(req.caller, identity))
      const mode = input.mode ?? 'once'
      if (mode !== 'once' && mode !== 'permanent') fail('invalid_authorization_mode')
      if (mode === 'once' && req.operation === undefined) fail('once_operation_required')
      if (req.operation !== undefined && !permits(approvedSnapshot, req.operation)) fail('operation_not_permitted')
      if (input.reviewedSnapshot === undefined) fail('review_snapshot_required')
      if (canonical(snapshot(input.reviewedSnapshot)) !== canonical(approvedSnapshot)) fail('review_snapshot_changed')
      const grant: AuthorizationGrant = {
        id: randomUUID(), requestId: req.id, caller: req.caller, identity, snapshot: approvedSnapshot,
        mode, version: 1, approvedAt: this.#now(), status: 'active',
        ...(mode === 'once' ? { expiresAt: this.#now() + (this.options.onceTtlMs ?? FIVE_MINUTES), operation: req.operation! } : {}),
      }
      const next: AccessAuthorizationRequest = { ...req, status: 'approved', version: req.version + 1, decidedAt: this.#now(), identity, mode, grantId: grant.id }
      state.grants.push(grant)
      this.#replaceRequest(state, next)
      return next
    })
    if (decided.kind !== 'create' || decided.status !== 'approved' || decided.operationId === undefined) return decided
    try {
      const result = await this.options.createIdentity(decided.operationId, decided.caller, copy(decided.parameters))
      return await this.#finishCreation(decided.id, result)
    } catch {
      // A native side effect may already exist. Never retry create or expose native error data.
      return this.#transaction(async state => {
        const req = this.#findRequest(state, decided.id) as CreateAuthorizationRequest
        if (req.executionStatus === 'succeeded' || req.executionStatus === 'deleted') return req
        const next: CreateAuthorizationRequest = { ...req, version: req.version + 1, executionStatus: 'unknown' }
        this.#replaceRequest(state, next)
        return next
      })
    }
  }

  async reconcileCreation(requestId: string): Promise<CreateAuthorizationRequest> {
    const req = await this.#transaction(async state => this.#findRequest(state, requestId))
    if (req.kind !== 'create' || req.status !== 'approved' || req.operationId === undefined) fail('creation_not_approved')
    if (req.executionStatus === 'succeeded' || req.executionStatus === 'deleted') return req
    const result = await this.options.reconcileCreation?.(req.operationId, req.caller, copy(req.parameters))
    return result === undefined ? req : this.#finishCreation(req.id, result)
  }

  async #finishCreation(requestId: string, result: CreateResult): Promise<CreateAuthorizationRequest> {
    const publicResult = { reference: reference(result.reference), label: text(result.label, 256) }
    return this.#transaction(async state => {
      const req = this.#findRequest(state, requestId)
      if (req.kind !== 'create' || req.status !== 'approved') fail('creation_not_approved')
      if (req.result !== undefined && !equalIdentity(req.result.reference, publicResult.reference)) fail('creation_result_conflict')
      if (req.executionStatus === 'deleted' || state.deletedIdentities.some(ref => equalIdentity(ref, publicResult.reference))) {
        const deleted: CreateAuthorizationRequest = { ...req, version: req.version + 1, executionStatus: 'deleted', result: publicResult }
        this.#replaceRequest(state, deleted); return deleted
      }
      const next: CreateAuthorizationRequest = { ...req, version: req.version + 1, executionStatus: 'succeeded', result: publicResult }
      this.#replaceRequest(state, next)
      return next
    })
  }

  async listGrants(identity?: IdentityReference): Promise<AuthorizationGrant[]> {
    return this.#transaction(async state => state.grants.filter(grant => identity === undefined || equalIdentity(identity, grant.identity)))
  }

  async revoke(grantId: string, expectedVersion: number): Promise<AuthorizationGrant> {
    return this.#transaction(async state => {
      const grant = this.#findGrant(state, grantId)
      if (grant.version !== expectedVersion) fail('grant_conflict')
      if (grant.status === 'revoked') return grant
      const next: AuthorizationGrant = { ...grant, status: 'revoked', version: grant.version + 1, revokedAt: this.#now() }
      this.#replaceGrant(state, next)
      state.suppressions.push({ consumer: grant.caller.consumer, kind: 'access', identity: grant.identity, requestId: grant.requestId })
      return next
    })
  }

  /** Manager-only explicit user retry. The old request and decision remain immutable history. */
  async reauthorize(requestId: string, expectedVersion: number): Promise<AuthorizationRequest> {
    return this.#transaction(async state => {
      const req = this.#findRequest(state, requestId)
      if (req.version !== expectedVersion) fail('request_conflict')
      if (req.status === 'pending' || (req.kind === 'create' && req.status === 'approved')) fail('request_not_retryable')
      await this.options.validateCaller(req.caller)
      const details = req.kind === 'create' ? { kind: 'create' as const, parameters: req.parameters }
        : { kind: 'access' as const, ...(req.identity === undefined ? {} : { identity: req.identity }), ...(req.operation === undefined ? {} : { operation: req.operation }) }
      state.suppressions = state.suppressions.filter(block => !(block.consumer === req.caller.consumer && block.kind === req.kind
        && (block.identity === undefined || req.kind === 'create' || req.identity === undefined || equalIdentity(block.identity, req.identity))))
      const fresh = this.#request(state, req.caller, randomUUID(), req.purpose, details)
      const next = { ...fresh, retryOf: req.id }
      this.#replaceRequest(state, next)
      return next
    })
  }

  /** Call only for an authoritative disable/uninstall, never for a transient connection loss. */
  async cancelPendingForConsumer(consumer: string): Promise<void> {
    text(consumer, 256)
    await this.#transaction(async state => {
      state.requests = state.requests.map(req => req.caller.consumer === consumer && req.status === 'pending'
        ? { ...req, status: 'cancelled', version: req.version + 1, decidedAt: this.#now() } : req)
    })
  }

  /** Host-only bridge for legacy catalog grants, serialized against deletion and ordinary approvals. */
  async withIdentityAccess<T>(identity: IdentityReference, callback: () => Promise<T>): Promise<T> {
    return this.#transaction(async state => {
      this.#identityAvailable(state, reference(identity))
      // Publish an epoch before catalog changes, including an uncertain callback failure.
      // Snapshot transactions must not commit ordinary use across a Host association change.
      state.generation += 1
      await this.#write(state)
      return callback()
    })
  }

  async open(verifiedCaller: VerifiedCaller, grantId: string): Promise<AuthorizedLease> {
    return this.#snapshotTransaction(async state => {
      const grant = this.#findGrant(state, grantId)
      this.#owns(verifiedCaller, grant.caller.consumer)
      if (grant.status !== 'active') fail('grant_inactive')
      this.#identityAvailable(state, grant.identity)
      await this.options.validateCaller(grant.caller)
      snapshot(await this.options.resolveSnapshot(grant.caller, grant.identity))
      return { grantId, consumer: grant.caller.consumer, identity: grant.identity, grantVersion: grant.version,
        expiresAt: Math.min(this.#now() + (this.options.leaseTtlMs ?? FIVE_MINUTES), grant.expiresAt ?? Infinity) }
    })
  }

  async admit(verifiedCaller: VerifiedCaller, lease: AuthorizedLease, requestedOperation: ControlledOperation, executionId: string): Promise<AuthorizationExecution> {
    const actual = operation(requestedOperation)
    text(executionId, 256)
    return this.#snapshotTransaction(async state => {
      // An execution ID is a query key, never permission to replay its side effects.
      if (state.executions.some(value => value.id === executionId)) fail('execution_already_admitted')
      const grant = await this.#checkLease(state, verifiedCaller, lease, actual)
      if (grant.status !== 'active') fail('grant_inactive')
      if (grant.mode === 'once' && grant.operation?.fingerprint !== actual.fingerprint) fail('operation_mismatch')
      const execution: AuthorizationExecution = {
        id: executionId, grantId: grant.id, consumer: grant.caller.consumer, fingerprint: actual.fingerprint,
        grantVersion: grant.version, operation: actual, admittedAt: this.#now(), status: 'admitted',
      }
      state.executions.push(execution)
      if (grant.mode === 'once') this.#replaceGrant(state, { ...grant, status: 'consumed', version: grant.version + 1, executionId })
      return execution
    }, lease.expiresAt)
  }

  async assertExecutionActive(verifiedCaller: VerifiedCaller, lease: AuthorizedLease, executionId: string): Promise<void> {
    await this.#snapshotTransaction(async state => {
      const execution = state.executions.find(value => value.id === executionId)
      if (execution === undefined || execution.grantId !== lease.grantId || execution.status !== 'admitted') fail('execution_inactive')
      this.#owns(verifiedCaller, execution.consumer)
      const grant = this.#findGrant(state, lease.grantId)
      if (execution.grantVersion !== lease.grantVersion) fail('grant_conflict')
      const expectedVersion = grant.mode === 'once' ? execution.grantVersion + 1 : execution.grantVersion
      if (grant.version !== expectedVersion || (grant.status !== 'active' && !(grant.status === 'consumed' && grant.executionId === executionId))) fail('grant_inactive')
      await this.#checkLease(state, verifiedCaller, { ...lease, grantVersion: expectedVersion }, execution.operation)
    }, lease.expiresAt)
  }

  async recordExecution(verifiedCaller: VerifiedCaller, executionId: string, status: 'succeeded' | 'failed' | 'unknown'): Promise<AuthorizationExecution> {
    if (!['succeeded', 'failed', 'unknown'].includes(status)) fail('invalid_execution_status')
    return this.#transaction(async state => {
      const index = state.executions.findIndex(value => value.id === executionId)
      const execution = state.executions[index]
      if (execution === undefined) fail('execution_not_found')
      this.#owns(verifiedCaller, execution.consumer)
      if (execution.status !== 'admitted') {
        if (execution.status !== status) fail('execution_result_conflict')
        return execution
      }
      const next = { ...execution, status, finishedAt: this.#now() }
      state.executions[index] = next
      return next
    })
  }

  async getExecution(verifiedCaller: VerifiedCaller, executionId: string): Promise<AuthorizationExecution> {
    return this.#transaction(async state => {
      const result = state.executions.find(value => value.id === executionId)
      if (result === undefined) fail('execution_not_found')
      this.#owns(verifiedCaller, result.consumer)
      return result
    })
  }

  /** Prepare checks associations and may set the catalog deletion fence before native execution. */
  async withIdentityDeletion(identity: IdentityReference, prepare: () => Promise<void>, execute: () => Promise<void>): Promise<void> {
    const target = reference(identity)
    // Serialize duplicate deletes of this identity without blocking the shared ledger
    // during native I/O. A crash releases this lock but leaves the durable fence.
    await this.#locked(async () => {
      const shouldExecute = await this.#locked(async () => {
        const state = await this.#read()
        this.#expire(state)
        if (state.grants.some(grant => equalIdentity(grant.identity, target) && grant.status === 'active')) fail('identity_has_grants')
        if (state.deletedIdentities.some(ref => equalIdentity(ref, target))) return false
        await prepare()
        if (!state.deletingIdentities.some(ref => equalIdentity(ref, target))) state.deletingIdentities.push(target)
        state.generation += 1
        await this.#write(state)
        return true
      })
      if (!shouldExecute) return
      // A failed/uncertain execute leaves the fence for explicit reconciliation; no grant can race in.
      await execute()
      await this.#transaction(async state => {
        this.#completeDeletion(state, target)
      })
    }, join(this.stateRoot, `authorization-delete-${digest(target)}.lock`))
    this.#notify()
  }

  /** Host-only recovery of previously fenced deletions; absence alone never authorizes deletion. */
  async reconcileDeletions(input: DeletionReconciliation): Promise<void> {
    const catalogFences = input.catalogFences.map(reference)
    await this.#snapshotTransaction(async state => {
      for (const target of catalogFences) {
        if (!state.deletedIdentities.some(ref => equalIdentity(ref, target))
          && !state.deletingIdentities.some(ref => equalIdentity(ref, target))) state.deletingIdentities.push(target)
      }
      for (const target of [...state.deletingIdentities]) {
        if (state.grants.some(grant => equalIdentity(grant.identity, target) && grant.status === 'active')) continue
        if (await input.isAbsent(copy(target))) this.#completeDeletion(state, target)
      }
    })
  }

  #completeDeletion(state: AuthorizationState, target: IdentityReference): void {
    state.deletingIdentities = state.deletingIdentities.filter(ref => !equalIdentity(ref, target))
    if (!state.deletedIdentities.some(ref => equalIdentity(ref, target))) state.deletedIdentities.push(target)
    state.requests = state.requests.map(req => req.kind === 'create' && req.result !== undefined
      && equalIdentity(req.result.reference, target) && req.executionStatus !== 'deleted'
      ? { ...req, executionStatus: 'deleted', version: req.version + 1 } : req)
  }

  async #checkLease(state: AuthorizationState, verifiedCaller: VerifiedCaller, lease: AuthorizedLease, actual: ControlledOperation): Promise<AuthorizationGrant> {
    const grant = this.#findGrant(state, lease.grantId)
    this.#owns(verifiedCaller, grant.caller.consumer)
    if (lease.consumer !== grant.caller.consumer || !equalIdentity(lease.identity, grant.identity)) fail('identity_mismatch')
    if (lease.expiresAt <= this.#now()) fail('lease_expired')
    if (grant.version !== lease.grantVersion) fail('grant_conflict')
    this.#identityAvailable(state, grant.identity)
    await this.options.validateCaller(grant.caller)
    const current = snapshot(await this.options.resolveSnapshot(grant.caller, grant.identity))
    if (lease.expiresAt <= this.#now()) fail('lease_expired')
    if (current.version !== grant.snapshot.version || !permits(grant.snapshot, actual) || !permits(current, actual)) fail('operation_not_permitted')
    return grant
  }

  #identityAvailable(state: AuthorizationState, identity: IdentityReference): void {
    if ([...state.deletingIdentities, ...state.deletedIdentities].some(ref => equalIdentity(ref, identity))) fail('identity_unavailable')
  }
  #owns(source: VerifiedCaller, consumer: string): void { if (source.consumer !== consumer) fail('caller_mismatch') }
  #findRequest(state: AuthorizationState, id: string): AuthorizationRequest {
    return state.requests.find(req => req.id === id) ?? fail('request_not_found')
  }
  #findGrant(state: AuthorizationState, id: string): AuthorizationGrant {
    return state.grants.find(grant => grant.id === id) ?? fail('grant_not_found')
  }
  #pending(req: AuthorizationRequest, version: number): void {
    if (req.version !== version) fail('request_conflict')
    if (req.status !== 'pending') fail('request_not_pending')
  }
  #replaceRequest(state: AuthorizationState, req: AuthorizationRequest): void {
    state.requests[state.requests.findIndex(value => value.id === req.id)] = req
  }
  #replaceGrant(state: AuthorizationState, grant: AuthorizationGrant): void {
    state.grants[state.grants.findIndex(value => value.id === grant.id)] = grant
  }
  #expire(state: AuthorizationState): void {
    const now = this.#now()
    state.requests = state.requests.map(req => req.status === 'pending' && req.expiresAt <= now
      ? { ...req, status: 'expired', version: req.version + 1, decidedAt: now } : req)
    state.grants = state.grants.map(grant => grant.status === 'active' && grant.mode === 'once' && grant.expiresAt! <= now
      ? { ...grant, status: 'expired', version: grant.version + 1 } : grant)
  }
  async #transaction<T>(action: (state: AuthorizationState) => Promise<T>): Promise<T> {
    let changed = false
    const result = await this.#locked(async () => {
      const state = await this.#read()
      const before = JSON.stringify(state)
      this.#expire(state)
      // Persist expiration even if the requested action subsequently fails.
      if (JSON.stringify(state) !== before) { state.generation += 1; await this.#write(state); changed = true }
      const current = JSON.stringify(state)
      const result = await action(state)
      if (JSON.stringify(state) !== current) { state.generation += 1; await this.#write(state); changed = true }
      return copy(result)
    })
    if (changed) this.#notify()
    return result
  }
  #notify(): void { for (const listener of this.#listeners) { try { listener() } catch { /* Notifications are advisory. */ } } }
  /** The callback may read native/catalog state but must not perform external mutations.
   * Re-evaluate on a ledger CAS conflict, including revocation, deletion and Host association
   * changes. Native waits never hold the shared authorization lock.
   */
  async #snapshotTransaction<T>(action: (state: AuthorizationState) => Promise<T>, leaseDeadline = Infinity): Promise<T> {
    for (let attempt = 0; attempt < 16; attempt++) {
      const state = await this.#transaction(async current => current)
      const generation = state.generation
      const before = JSON.stringify(state)
      const result = await action(state)
      const committed = await this.#locked(async () => {
        const current = await this.#read()
        if (current.generation !== generation) return false
        if (leaseDeadline <= this.#now()) fail('lease_expired')
        const unexpired = JSON.stringify(current)
        this.#expire(current)
        if (JSON.stringify(current) !== unexpired) {
          current.generation += 1
          await this.#write(current)
          return false
        }
        if (JSON.stringify(state) !== before) {
          state.generation = generation + 1
          await this.#write(state)
        }
        return true
      })
      if (committed) {
        if (JSON.stringify(state) !== before) this.#notify()
        return copy(result)
      }
    }
    return fail('authorization_conflict')
  }
  async #locked<T>(action: () => Promise<T>, path = this.#lockPath): Promise<T> {
    const release = await lockfile.lock(path, { realpath: false, stale: 30_000, update: 10_000, retries: { retries: 500, minTimeout: 20, maxTimeout: 20 } })
    try { return await action() } finally { await release() }
  }
  async #read(): Promise<AuthorizationState> {
    const raw = await readFile(this.statePath)
    if (raw.length > 16 * 1024 * 1024) fail('authorization_store_corrupt')
    try {
      const value = JSON.parse(raw.toString('utf8')) as AuthorizationState
      if (value.schema !== SCHEMA || !Number.isSafeInteger(value.generation) || value.generation < 0
        || !Array.isArray(value.requests) || !Array.isArray(value.grants) || !Array.isArray(value.executions)
        || !Array.isArray(value.deletedIdentities) || !Array.isArray(value.deletingIdentities) || !Array.isArray(value.suppressions)) fail('authorization_store_corrupt')
      if (new Set(value.requests.map(req => req.id)).size !== value.requests.length
        || new Set(value.grants.map(grant => grant.id)).size !== value.grants.length
        || new Set(value.executions.map(execution => execution.id)).size !== value.executions.length) fail('authorization_store_corrupt')
      for (const req of value.requests) {
        text(req.id, 256); caller(req.caller); text(req.purpose); text(req.fingerprint)
        if (!['create', 'access'].includes(req.kind) || !['pending', 'approved', 'denied', 'cancelled', 'expired'].includes(req.status)
          || !Number.isSafeInteger(req.version) || req.version < 1 || !Number.isFinite(req.expiresAt)) fail('authorization_store_corrupt')
        if (req.kind === 'access') { if (req.identity) reference(req.identity); if (req.operation) operation(req.operation) }
        if (req.kind === 'create') { text(req.parameters.label); text(req.parameters.domain); text(req.parameters.path, 2048); if (req.result) reference(req.result.reference) }
      }
      for (const grant of value.grants) {
        text(grant.id); caller(grant.caller); reference(grant.identity); snapshot(grant.snapshot)
        if (!['active', 'consumed', 'revoked', 'expired'].includes(grant.status) || !['once', 'permanent'].includes(grant.mode)
          || !Number.isSafeInteger(grant.version) || grant.version < 1) fail('authorization_store_corrupt')
        if (grant.mode === 'once') { if (!Number.isFinite(grant.expiresAt) || grant.operation === undefined) fail('authorization_store_corrupt'); operation(grant.operation) }
      }
      for (const execution of value.executions) {
        text(execution.id); text(execution.consumer); operation(execution.operation)
        if (!['admitted', 'succeeded', 'failed', 'unknown'].includes(execution.status)) fail('authorization_store_corrupt')
      }
      for (const identity of [...value.deletedIdentities, ...value.deletingIdentities]) reference(identity)
      for (const block of value.suppressions) {
        text(block.consumer, 256); text(block.requestId, 256)
        if (block.kind !== 'create' && block.kind !== 'access') fail('authorization_store_corrupt')
        if (block.identity !== undefined) reference(block.identity)
      }
      return value
    } catch { return fail('authorization_store_corrupt') }
  }
  async #write(state: AuthorizationState): Promise<void> {
    const serialized = JSON.stringify(state)
    if (Buffer.byteLength(serialized) > 16 * 1024 * 1024) fail('authorization_store_full')
    const temporary = `${this.statePath}.${randomUUID()}.tmp`
    const file = await open(temporary, 'wx', 0o600)
    try {
      await file.writeFile(serialized)
      await file.sync()
      await file.close()
      this.options.fault?.('before_rename')
      await rename(temporary, this.statePath)
      const directory = await open(this.stateRoot, 'r')
      try { await directory.sync() } finally { await directory.close() }
      this.options.fault?.('after_rename')
    } finally {
      await file.close()
      await unlink(temporary).catch(error => { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error })
    }
  }
}
