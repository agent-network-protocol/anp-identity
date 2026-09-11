import { spawn } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { AuthorizationEngine, freezeOperation } from '../src/authorization.js'
import type { AuthorizationOptions, CapabilitySnapshot, CreateResult, VerifiedCaller } from '../src/authorization-types.js'

const caller: VerifiedCaller = { consumer: 'documents', displayName: 'Documents' }
const identity = { storeId: 'store-1', identityId: 'identity-1', did: 'did:wba:example.test:alice' }
const policy: CapabilitySnapshot = { version: 'v1', capabilities: ['identity:read', 'identity:sign', 'identity:http-auth'], signingPurposes: ['assertion'], httpOrigins: ['https://api.example.test'] }
const readOperation = freezeOperation({ capability: 'identity:read', summary: 'Read public DID document' }, { method: 'publicIdentity' })
const parameters = { label: 'Work', domain: 'example.test', path: '/agents/work' }

describe('durable authorization admission and decisions', () => {
  it('requires independent creation and use decisions, preserves result across restart, and freezes request parameters', async () => {
    const created: string[] = []
    await using f = await fixture({ createIdentity: async operationId => { created.push(operationId); return { reference: identity, label: 'Work' } } })
    const request = await f.engine.requestCreate(caller, { requestId: 'create-one', purpose: 'Create work identity', parameters })
    expect(created).toEqual([])
    expect(await f.engine.listGrants()).toEqual([])
    await expect(f.engine.requestCreate(caller, { requestId: 'create-one', purpose: 'Create work identity', parameters: { ...parameters, path: '/different' } })).rejects.toMatchObject({ code: 'request_conflict' })
    const result = await f.engine.decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve' })
    expect(result).toMatchObject({ kind: 'create', executionStatus: 'succeeded', result: { reference: identity } })
    expect(created).toHaveLength(1)
    expect(await f.engine.listGrants()).toEqual([])
    const resumed = f.reopen()
    expect(await resumed.requestCreate(caller, { requestId: 'create-one', purpose: 'Create work identity', parameters })).toEqual(result)
    await expect(resumed.decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve' })).rejects.toMatchObject({ code: 'request_conflict' })
    expect(created).toHaveLength(1)
    const access = await resumed.requestAccess(caller, { requestId: 'use-one', purpose: 'Read public identity', identity, operation: readOperation })
    await resumed.decide({ requestId: access.id, expectedVersion: access.version, decision: 'deny' })
    expect(await resumed.listGrants()).toEqual([])
    expect(await resumed.getRequest(caller, request.id)).toMatchObject({ executionStatus: 'succeeded' })
  })

  it('reconciles native success with a lost response without calling create again', async () => {
    let calls = 0
    let nativeResult: CreateResult | undefined
    await using f = await fixture({
      createIdentity: async () => { calls += 1; nativeResult = { reference: identity, label: 'Work' }; throw new Error('response lost with sensitive-native-detail') },
      reconcileCreation: async () => nativeResult,
    })
    const request = await f.engine.requestCreate(caller, { requestId: 'create-lost', purpose: 'Create', parameters })
    expect(await f.engine.decide({ requestId: request.id, expectedVersion: 1, decision: 'approve' })).toMatchObject({ executionStatus: 'unknown' })
    expect(await f.reopen().reconcileCreation(request.id)).toMatchObject({ executionStatus: 'succeeded', result: { reference: identity } })
    expect(calls).toBe(1)
    expect(await readFile(f.engine.statePath, 'utf8')).not.toContain('sensitive-native-detail')
  })

  it('atomically competes approve versus cancel using the same persisted request version', async () => {
    await using f = await fixture()
    const req = await f.engine.requestAccess(caller, { requestId: 'race', purpose: 'Read', identity, operation: readOperation })
    const decisions = await Promise.allSettled([
      f.engine.decide({ requestId: req.id, expectedVersion: req.version, decision: 'approve', reviewedSnapshot: policy }),
      f.reopen().cancel(caller, req.id, req.version),
    ])
    expect(decisions.filter(result => result.status === 'fulfilled')).toHaveLength(1)
    const stored = await f.engine.getRequest(caller, req.id)
    expect(['approved', 'cancelled']).toContain(stored.status)
    expect(await f.engine.listGrants()).toHaveLength(stored.status === 'approved' ? 1 : 0)
  })

  it('deduplicates pending requests without replacing review text and persists prompt state', async () => {
    await using f = await fixture()
    const a = await f.engine.requestCreate(caller, { requestId: 'original', purpose: 'Create', parameters })
    const b = await f.engine.requestCreate(caller, { requestId: 'duplicate', purpose: 'Create', parameters })
    expect(b.id).toBe(a.id)
    await f.engine.markPrompted(a.id)
    expect((await f.reopen().listRequests()).filter(req => req.status === 'pending')).toHaveLength(1)
    expect(await f.reopen().getRequest(caller, a.id)).toMatchObject({ prompted: true, status: 'pending', version: 1 })
    await f.engine.decide({ requestId: a.id, expectedVersion: 1, decision: 'deny' })
    await expect(f.engine.requestCreate(caller, { requestId: 'spam', purpose: 'Create', parameters })).rejects.toMatchObject({ code: 'request_previously_denied' })
    await expect(f.engine.requestCreate(caller, { requestId: 'spam-reworded', purpose: 'Different wording', parameters: { ...parameters, path: '/changed' } })).rejects.toMatchObject({ code: 'request_previously_denied' })
    const retry = await f.engine.reauthorize(a.id, 2)
    expect(retry).toMatchObject({ status: 'pending', retryOf: a.id })
    expect(retry.id).not.toBe(a.id)
    expect(await f.engine.getRequest(caller, a.id)).toMatchObject({ status: 'denied' })
  })

  it('does not approve once without a concrete operation or while the caller is offline', async () => {
    let online = true
    await using f = await fixture({ validateCaller: async () => { if (!online) throw new Error('caller_offline') } })
    const req = await f.engine.requestAccess(caller, { requestId: 'no-operation', purpose: 'Use identity', identity })
    await expect(f.engine.decide({ requestId: req.id, expectedVersion: 1, decision: 'approve' })).rejects.toMatchObject({ code: 'once_operation_required' })
    online = false
    await expect(f.engine.decide({ requestId: req.id, expectedVersion: 1, decision: 'approve', mode: 'permanent' })).rejects.toThrow('caller_offline')
    expect(await f.engine.listGrants()).toEqual([])
    expect(await f.engine.getRequest(caller, req.id)).toMatchObject({ status: 'pending', version: 1 })
  })

  it('rejects changed operation, identity, or caller without consuming once; failure never refunds it', async () => {
    await using f = await fixture()
    const grant = await approve(f.engine)
    const lease = await f.engine.open(caller, grant.id)
    const changed = freezeOperation({ capability: 'identity:read', summary: 'Read public DID document' }, { method: 'different' })
    await expect(f.engine.admit(caller, lease, changed, 'changed')).rejects.toMatchObject({ code: 'operation_mismatch' })
    await expect(f.engine.admit({ consumer: 'other', displayName: 'Other' }, lease, readOperation, 'other')).rejects.toMatchObject({ code: 'caller_mismatch' })
    await expect(f.engine.admit(caller, { ...lease, identity: { ...identity, identityId: 'other' } }, readOperation, 'wrong-ref')).rejects.toMatchObject({ code: 'identity_mismatch' })
    expect((await f.engine.listGrants())[0]).toMatchObject({ status: 'active' })
    await f.engine.admit(caller, lease, readOperation, 'admission')
    await f.engine.assertExecutionActive(caller, lease, 'admission')
    await f.engine.recordExecution(caller, 'admission', 'failed')
    await expect(f.reopen().open(caller, grant.id)).rejects.toMatchObject({ code: 'grant_inactive' })
    await expect(f.engine.admit(caller, lease, readOperation, 'admission')).rejects.toMatchObject({ code: 'execution_already_admitted' })
    expect(await f.reopen().getExecution(caller, 'admission')).toMatchObject({ status: 'failed' })
  })

  it('permits only one admission across actual OS processes and never revives it on restart', async () => {
    await using f = await fixture()
    const grant = await approve(f.engine)
    const results = await Promise.all(Array.from({ length: 6 }, (_, n) => worker(f.root, grant.id, `process-${n}`)))
    expect(results.filter(result => result === 'admitted')).toHaveLength(1)
    expect(results.filter(result => result === 'denied')).toHaveLength(5)
    const stored = (await f.reopen().listGrants())[0]!
    expect(stored).toMatchObject({ status: 'consumed' })
    expect(await f.engine.getExecution(caller, stored.executionId!)).toMatchObject({ status: 'admitted' })
  })

  it('expires unused once without extending it on open/restart and distinguishes permanent leases', async () => {
    let now = 1000
    await using f = await fixture({ now: () => now })
    const once = await approve(f.engine)
    const initial = await f.engine.open(caller, once.id)
    now += 299_000
    expect((await f.reopen().open(caller, once.id)).expiresAt).toBe(initial.expiresAt)
    now += 1001
    await expect(f.reopen().open(caller, once.id)).rejects.toMatchObject({ code: 'grant_inactive' })
    const permanent = await approve(f.engine, 'permanent', 'permanent')
    const expiredLease = await f.engine.open(caller, permanent.id)
    now += 300_001
    await expect(f.engine.admit(caller, expiredLease, readOperation, 'old-lease')).rejects.toMatchObject({ code: 'lease_expired' })
    const newLease = await f.reopen().open(caller, permanent.id)
    await f.engine.admit(caller, newLease, readOperation, 'fresh-lease')
  })

  it('intersects current policy with the approval snapshot and rechecks revocation before transport', async () => {
    let current = policy
    await using f = await fixture({ resolveSnapshot: async () => current })
    const grant = await approve(f.engine, 'permanent')
    const lease = await f.engine.open(caller, grant.id)
    const expanded = freezeOperation({ capability: 'identity:http-auth', summary: 'GET https://new.example.test/profile', httpOrigin: 'https://new.example.test' }, { method: 'GET', url: 'https://new.example.test/profile' })
    current = { ...policy, version: 'v2', httpOrigins: [...policy.httpOrigins, 'https://new.example.test'] }
    await expect(f.engine.admit(caller, lease, expanded, 'expanded')).rejects.toMatchObject({ code: 'operation_not_permitted' })
    const http = freezeOperation({ capability: 'identity:http-auth', summary: 'GET https://api.example.test/profile', httpOrigin: 'https://api.example.test' }, { method: 'GET', url: 'https://api.example.test/profile' })
    current = { ...policy, httpOrigins: [] }
    await expect(f.engine.admit(caller, lease, http, 'tightened')).rejects.toMatchObject({ code: 'operation_not_permitted' })
    current = policy
    await f.engine.admit(caller, lease, http, 'network')
    await f.engine.revoke(grant.id, grant.version)
    await expect(f.engine.assertExecutionActive(caller, lease, 'network')).rejects.toMatchObject({ code: 'grant_inactive' })
    await expect(f.reopen().open(caller, grant.id)).rejects.toMatchObject({ code: 'grant_inactive' })
    await expect(f.engine.requestAccess(caller, { requestId: 'automatic-reprompt', purpose: 'Different wording', identity, operation: readOperation })).rejects.toMatchObject({ code: 'request_previously_denied' })
    const retry = await f.engine.reauthorize(grant.requestId, 2)
    const fresh = await f.engine.decide({ requestId: retry.id, expectedVersion: 1, decision: 'approve', mode: 'permanent', reviewedSnapshot: policy })
    expect(fresh.kind === 'access' && fresh.grantId).not.toBe(grant.id)
    await expect(f.engine.admit(caller, lease, readOperation, 'old-after-new')).rejects.toMatchObject({ code: 'grant_conflict' })
  })

  it('stores only host safe operation metadata and hashes, never payloads or credentials', async () => {
    await using f = await fixture()
    const sign = freezeOperation({ capability: 'identity:sign', summary: 'Sign assertion', signingPurpose: 'assertion' }, { content: 'SECRET-SIGNATURE-PAYLOAD', authorization: 'Bearer SECRET-TOKEN' })
    const request = await f.engine.requestAccess(caller, { requestId: 'private-sign', purpose: 'Sign statement', identity, operation: sign })
    await f.engine.decide({ requestId: request.id, expectedVersion: 1, decision: 'approve', reviewedSnapshot: policy })
    const raw = await readFile(f.engine.statePath, 'utf8')
    expect(raw).not.toContain('SECRET-SIGNATURE-PAYLOAD')
    expect(raw).not.toContain('SECRET-TOKEN')
    expect(raw).toContain(sign.fingerprint)
    expect(freezeOperation({ capability: 'identity:sign', summary: 'Sign assertion', signingPurpose: 'assertion' }, { authorization: 'Bearer SECRET-TOKEN', content: 'SECRET-SIGNATURE-PAYLOAD' })).toEqual(sign)
  })

  it('preserves atomic decisions at both sides of a rename fault', async () => {
    await using f = await fixture()
    const request = await f.engine.requestAccess(caller, { requestId: 'fault', purpose: 'Read', identity, operation: readOperation })
    let point: 'before_rename' | 'after_rename' = 'before_rename'
    const faulty = f.reopen({ fault: actual => { if (actual === point) throw new Error('injected_crash') } })
    await expect(faulty.decide({ requestId: request.id, expectedVersion: 1, decision: 'approve', reviewedSnapshot: policy })).rejects.toThrow('injected_crash')
    expect(await f.engine.listGrants()).toEqual([])
    expect(await f.engine.getRequest(caller, request.id)).toMatchObject({ status: 'pending' })
    point = 'after_rename'
    await expect(faulty.decide({ requestId: request.id, expectedVersion: 1, decision: 'approve', reviewedSnapshot: policy })).rejects.toThrow('injected_crash')
    const committed = await f.engine.getRequest(caller, request.id)
    expect(committed).toMatchObject({ status: 'approved' })
    expect(await f.engine.listGrants()).toHaveLength(1)
  })

  it('does not refund a consumed admission when the durable commit response is lost', async () => {
    await using f = await fixture()
    const grant = await approve(f.engine)
    const lease = await f.engine.open(caller, grant.id)
    const faulty = f.reopen({ fault: point => { if (point === 'after_rename') throw new Error('commit_response_lost') } })
    await expect(faulty.admit(caller, lease, readOperation, 'lost-admission')).rejects.toThrow('commit_response_lost')
    expect((await f.reopen().listGrants())[0]).toMatchObject({ status: 'consumed', executionId: 'lost-admission' })
    expect(await f.reopen().getExecution(caller, 'lost-admission')).toMatchObject({ status: 'admitted' })
    await expect(f.reopen().open(caller, grant.id)).rejects.toMatchObject({ code: 'grant_inactive' })
  })

  it('expires both request types durably and cancels pending requests only for authoritative disable', async () => {
    let now = 1000
    await using f = await fixture({ now: () => now, requestTtlMs: 100 })
    const created = await f.engine.requestCreate(caller, { requestId: 'expires-create', purpose: 'Create', parameters })
    const use = await f.engine.requestAccess(caller, { requestId: 'expires-use', purpose: 'Use', identity, operation: readOperation })
    now += 101
    expect((await f.reopen().listRequests()).every(req => req.status === 'expired')).toBe(true)
    await expect(f.engine.decide({ requestId: created.id, expectedVersion: 1, decision: 'approve' })).rejects.toMatchObject({ code: 'request_conflict' })
    expect(await f.engine.getRequest(caller, use.id)).toMatchObject({ status: 'expired', version: 2 })
    const pending = await f.engine.requestAccess(caller, { requestId: 'disabled', purpose: 'Use again', identity, operation: readOperation })
    await f.engine.cancelPendingForConsumer(caller.consumer)
    expect(await f.reopen().getRequest(caller, pending.id)).toMatchObject({ status: 'cancelled' })
    expect(await f.engine.listGrants()).toEqual([])
  })

  it('keeps no deletion fence after failed preflight and leaves a durable fence after uncertain deletion', async () => {
    await using f = await fixture()
    await expect(f.engine.withIdentityDeletion(identity, async () => { throw new Error('provider_managed') }, async () => {})).rejects.toThrow('provider_managed')
    const grant = await approve(f.engine)
    await expect(f.engine.withIdentityDeletion(identity, async () => {}, async () => {})).rejects.toMatchObject({ code: 'identity_has_grants' })
    await f.engine.revoke(grant.id, 1)
    await expect(f.engine.withIdentityDeletion(identity, async () => {}, async () => { throw new Error('native_outcome_unknown') })).rejects.toThrow('native_outcome_unknown')
    await expect(f.reopen().requestAccess(caller, { requestId: 'after-uncertain', purpose: 'Read', identity, operation: readOperation })).rejects.toMatchObject({ code: 'identity_unavailable' })
  })

  it('keeps a durable create tombstone after deletion rather than recreating on replay', async () => {
    let calls = 0
    await using f = await fixture({ createIdentity: async () => { calls += 1; return { reference: identity, label: 'Work' } } })
    const req = await f.engine.requestCreate(caller, { requestId: 'deleted-create', purpose: 'Create', parameters })
    await f.engine.decide({ requestId: req.id, expectedVersion: 1, decision: 'approve' })
    await f.engine.withIdentityDeletion(identity, async () => {}, async () => {})
    expect(await f.reopen().requestCreate(caller, { requestId: req.id, purpose: 'Create', parameters })).toMatchObject({ executionStatus: 'deleted' })
    expect(await f.reopen().reconcileCreation(req.id)).toMatchObject({ executionStatus: 'deleted' })
    expect(calls).toBe(1)
  })

  it('rejects scope changes between the displayed review and approval instead of silently expanding the grant', async () => {
    let current = policy
    await using f = await fixture({ resolveSnapshot: async () => current })
    const req = await f.engine.requestAccess(caller, { requestId: 'review-scope-race', purpose: 'Review permissions', identity, operation: readOperation })
    const reviewedSnapshot = structuredClone(current)
    current = { ...policy, httpOrigins: [...policy.httpOrigins, 'https://additional.example.test'] }
    const decision = { requestId: req.id, expectedVersion: req.version, decision: 'approve' as const, mode: 'permanent' as const, reviewedSnapshot }
    await expect(f.engine.decide(decision)).rejects.toMatchObject({ code: 'review_snapshot_changed' })
    expect(await f.engine.listGrants()).toEqual([])
    expect(await f.engine.getRequest(caller, req.id)).toMatchObject({ status: 'pending', version: 1 })
    await expect(f.engine.decide({ requestId: req.id, expectedVersion: 1, decision: 'approve', mode: 'permanent' })).rejects.toMatchObject({ code: 'review_snapshot_required' })
    await f.engine.decide({ ...decision, reviewedSnapshot: structuredClone(current) })
    expect((await f.engine.listGrants())[0]?.snapshot.httpOrigins).toEqual([...current.httpOrigins].sort())
  })

  it('reconciles a persisted deletion fence after the final ledger write fails without recreating the identity', async () => {
    let nativeExists = true
    let catalogExists = true
    let creates = 0
    await using f = await fixture({ createIdentity: async () => { creates += 1; return { reference: identity, label: 'Work' } } })
    const req = await f.engine.requestCreate(caller, { requestId: 'delete-final-write-lost', purpose: 'Create', parameters })
    await f.engine.decide({ requestId: req.id, expectedVersion: 1, decision: 'approve' })
    let writes = 0
    const faulting = f.reopen({ fault: point => { if (point === 'before_rename' && ++writes === 2) throw new Error('final_delete_write_failed') } })
    await expect(faulting.withIdentityDeletion(identity, async () => {}, async () => { nativeExists = false; catalogExists = false })).rejects.toThrow('final_delete_write_failed')
    const restarted = f.reopen()
    await restarted.reconcileDeletions({ catalogFences: [], isAbsent: async ref => {
      expect(ref).toEqual(identity)
      return !nativeExists && !catalogExists
    } })
    expect(await restarted.getRequest(caller, req.id)).toMatchObject({ executionStatus: 'deleted' })
    expect(await restarted.requestCreate(caller, { requestId: req.id, purpose: 'Create', parameters })).toMatchObject({ executionStatus: 'deleted' })
    expect(creates).toBe(1)
    const committed = await readFile(f.engine.statePath, 'utf8')
    await restarted.reconcileDeletions({ catalogFences: [], isAbsent: async () => { throw new Error('must_not_recheck_completed_deletion') } })
    expect(await readFile(f.engine.statePath, 'utf8')).toBe(committed)
  })

  it('uses prior catalog fence evidence when the first authorization fence write fails and retains uncertain absence', async () => {
    await using f = await fixture()
    const req = await f.engine.requestCreate(caller, { requestId: 'delete-initial-write-lost', purpose: 'Create', parameters })
    await f.engine.decide({ requestId: req.id, expectedVersion: 1, decision: 'approve' })
    const catalogFences: typeof identity[] = []
    let executed = false
    const faulting = f.reopen({ fault: point => { if (point === 'before_rename') throw new Error('first_delete_write_failed') } })
    await expect(faulting.withIdentityDeletion(identity, async () => { catalogFences.push(identity) }, async () => { executed = true })).rejects.toThrow('first_delete_write_failed')
    expect(executed).toBe(false)
    let nativeExists = true
    let catalogExists = true
    const absenceChecks: typeof identity[] = []
    const isAbsent = async (ref: typeof identity) => { absenceChecks.push(ref); return !nativeExists && !catalogExists }
    const restarted = f.reopen()
    await restarted.reconcileDeletions({ catalogFences, isAbsent })
    expect(absenceChecks).toEqual([identity])
    expect(await restarted.getRequest(caller, req.id)).toMatchObject({ executionStatus: 'succeeded' })
    await expect(restarted.requestAccess(caller, { requestId: 'cannot-use-deleting', purpose: 'Read', identity, operation: readOperation })).rejects.toMatchObject({ code: 'identity_unavailable' })
    nativeExists = false
    await restarted.reconcileDeletions({ catalogFences: [], isAbsent })
    expect(await restarted.getRequest(caller, req.id)).toMatchObject({ executionStatus: 'succeeded' })
    catalogExists = false
    await restarted.reconcileDeletions({ catalogFences: [], isAbsent })
    expect(await restarted.getRequest(caller, req.id)).toMatchObject({ executionStatus: 'deleted' })
  })

  it('never infers a deletion from an identity missing without a prior deletion fence', async () => {
    await using f = await fixture()
    const req = await f.engine.requestCreate(caller, { requestId: 'missing-without-fence', purpose: 'Create', parameters })
    await f.engine.decide({ requestId: req.id, expectedVersion: 1, decision: 'approve' })
    let queried = false
    await f.reopen().reconcileDeletions({ catalogFences: [], isAbsent: async () => { queried = true; return true } })
    expect(queried).toBe(false)
    expect(await f.engine.getRequest(caller, req.id)).toMatchObject({ executionStatus: 'succeeded' })
  })

  it('fails closed on corrupt or unsupported schema instead of silently resetting grants', async () => {
    await using f = await fixture()
    await writeFile(f.engine.statePath, JSON.stringify({ schema: 'anp-identity-authorization/999', generation: 0, requests: [], grants: [], executions: [] }))
    await expect(f.reopen().initialize()).rejects.toMatchObject({ code: 'authorization_store_corrupt' })
    await expect(f.engine.listGrants()).rejects.toMatchObject({ code: 'authorization_store_corrupt' })
  })
})

async function approve(engine: AuthorizationEngine, mode: 'once' | 'permanent' = 'once', id = 'read') {
  const request = await engine.requestAccess(caller, { requestId: id, purpose: `Read ${id}`, identity, operation: readOperation })
  const result = await engine.decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve', mode, reviewedSnapshot: policy })
  if (result.kind !== 'access' || result.grantId === undefined) throw new Error('grant_missing')
  return (await engine.listGrants()).find(grant => grant.id === result.grantId)!
}
async function fixture(overrides: Partial<AuthorizationOptions> = {}) {
  const root = await mkdtemp(join(tmpdir(), 'anp-authorization-'))
  const options: AuthorizationOptions = {
    validateCaller: async source => { if (source.consumer !== caller.consumer) throw new Error('unknown_caller') },
    resolveSnapshot: async (_source, ref) => { if (ref.storeId !== identity.storeId || ref.identityId !== identity.identityId || ref.did !== identity.did) throw new Error('missing_identity'); return policy },
    createIdentity: async () => ({ reference: identity, label: 'Work' }), ...overrides,
  }
  const engine = new AuthorizationEngine(root, options)
  await engine.initialize()
  return { root, engine, reopen: (extra: Partial<AuthorizationOptions> = {}) => new AuthorizationEngine(root, { ...options, ...extra }),
    async [Symbol.asyncDispose]() { await rm(root, { recursive: true, force: true }) },
  }
}
function worker(root: string, grantId: string, executionId: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(import.meta.dirname, 'authorization-worker.mjs'), root, grantId, executionId], { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''; let stderr = ''
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8')
    child.stdout.on('data', chunk => { stdout += chunk }); child.stderr.on('data', chunk => { stderr += chunk })
    child.once('error', reject)
    child.once('exit', code => code === 0 ? resolve(stdout) : reject(new Error(`Authorization worker exited ${code}: ${stderr}`)))
  })
}
