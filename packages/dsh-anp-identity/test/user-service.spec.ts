import { Context } from '@deepseek-ai/cordis'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it, vi } from 'vitest'
import AnpIdentityService, { type Config } from '../src/index.js'
import { openNativeProvider } from '../src/provider.js'
import type { NativeProviderRegistry } from '../src/provider-api.js'
import type { AuthorizationRequest, CreateAuthorizationRequest, AccessAuthorizationRequest } from '../src/authorization-types.js'
import type { UserIdentityClient } from '../src/user-client.js'
import type { UserIdentityService } from '../src/user-service.js'

const ORIGIN = 'https://api.example.com'
afterEach(() => { vi.restoreAllMocks() })

describe('ordinary plugin authorization with a real native Store', () => {
  it('waits for native startup recovery before a plugin request can acquire the authorization ledger', async () => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'startup-readiness')
    const recoveryEntered = latch()
    const releaseRecovery = latch()
    const readinessEntered = latch()
    const snapshotEntered = latch()
    try {
      await fixture.restart([ORIGIN], {
        beforeProvider(service) {
          const users = (service as unknown as { users: UserIdentityService }).users
          const reconcile = users.engine.reconcileDeletions.bind(users.engine)
          vi.spyOn(users.engine, 'reconcileDeletions').mockImplementation(async input => {
            recoveryEntered.resolve()
            await releaseRecovery.promise
            return reconcile(input)
          })
          const ensureReady = users.host.ensureReady.bind(users.host)
          vi.spyOn(users.host, 'ensureReady').mockImplementation(() => {
            readinessEntered.resolve()
            return ensureReady()
          })
          const snapshot = users.host.resolveSnapshot.bind(users.host)
          vi.spyOn(users.host, 'resolveSnapshot').mockImplementation((...args) => {
            snapshotEntered.resolve()
            return snapshot(...args)
          })
        },
        async afterProvider(service, first) {
          await recoveryEntered.promise
          const pending = first.requestAccess({ requestId: 'during-startup', purpose: 'Resume ordinary access after Host restart', identity: reference })
          const health = service.health()
          let timer: ReturnType<typeof setTimeout> | undefined
          try {
            const completed = (async () => {
              // Observe readiness entry rather than relying on arbitrary sleeps to schedule the caller.
              await readinessEntered.promise
              releaseRecovery.resolve()
              return Promise.all([health, pending])
            })()
            const watchdog = new Promise<never>((_, reject) => {
              timer = setTimeout(() => reject(new Error('Startup recovery and authorization request deadlocked')), 1500)
            })
            const [status, request] = await Promise.race([completed, watchdog])
            expect(status.status).toBe('ready')
            expect(request).toMatchObject({ kind: 'access', status: 'pending', identity: reference })
          } finally {
            if (timer) clearTimeout(timer)
            releaseRecovery.resolve()
            await Promise.allSettled([health, pending])
          }
        },
      })
      await snapshotEntered.promise
      expect(await fixture.host().list()).toHaveLength(1)
      expect((await fixture.first.getAccessRequest('during-startup')).status).toBe('pending')
    } finally { releaseRecovery.resolve() }
  }, 20_000)

  it.each([1, 2])('reconciles deletion after authorization write %s is lost', async failedWrite => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'delete-crash')
    const engine = (fixture.service as unknown as { users: { engine: { options: { fault?: (point: string) => void } } } }).users.engine
    let writes = 0
    engine.options.fault = point => {
      if (point === 'before_rename' && ++writes === failedWrite) throw new Error('simulated-final-ledger-write-loss')
    }
    await expect(fixture.service.acquireManagement().deleteIdentity({ reference, confirmationName: 'Identity delete-crash' }))
      .rejects.toThrow('simulated-final-ledger-write-loss')
    delete engine.options.fault
    await fixture.restart()
    expect(await fixture.service.acquireManagement().listIdentities()).toEqual([])
    expect(await fixture.first.getCreateRequest('create-delete-crash')).toMatchObject({ executionStatus: 'deleted' })
    const ledger = JSON.parse(await readFile(join(fixture.root, 'authorization-v1.json'), 'utf8'))
    expect(ledger.deletingIdentities).toEqual([])
    expect(ledger.deletedIdentities).toContainEqual(reference)
    await expect(fixture.service.acquireManagement().deleteIdentity({ reference, confirmationName: 'Identity delete-crash' })).resolves.toBeUndefined()
    expect(await fixture.host().list()).toEqual([])
  })

  it('rejects an old displayed permission snapshot after Host restart expands policy', async () => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'stale-review')
    const request = await fixture.first.requestAccess({ requestId: 'stale-scope', purpose: 'Review the original scope', identity: reference })
    const reviewed = await fixture.service.acquireManagement().getRequest(request.id)
    expect(reviewed.snapshot?.httpOrigins).toEqual([ORIGIN])
    await fixture.restart([ORIGIN, 'https://unseen.example'])
    const manager = fixture.service.acquireManagement()
    await expect(manager.decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve', identity: reference,
      mode: 'permanent', reviewedSnapshot: reviewed.snapshot! })).rejects.toMatchObject({ code: 'review_snapshot_changed' })
    expect(await manager.grants(reference)).toEqual([])
    expect((await manager.getRequest(request.id)).request.status).toBe('pending')
    const refreshed = await manager.getRequest(request.id)
    const approved = await manager.decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve', identity: reference,
      mode: 'permanent', reviewedSnapshot: refreshed.snapshot! }) as AccessAuthorizationRequest
    expect((await manager.getRequest(request.id)).grant?.id).toBe(approved.grantId)
  })

  it('reconciles an uncertain creation before deleting its native identity and catalog provenance', async () => {
    await using fixture = await userFixture()
    const request = await fixture.first.requestCreateIdentity(createInput('unknown-delete'))
    const engine = (fixture.service as unknown as { users: { engine: { options: { fault?: (point: string) => void } } } }).users.engine
    let writes = 0
    engine.options.fault = point => { if (point === 'before_rename' && ++writes === 2) throw new Error('lost-create-result') }
    const approved = await fixture.service.acquireManagement().decide({ requestId: request.id, expectedVersion: request.version, decision: 'approve' }) as CreateAuthorizationRequest
    delete engine.options.fault
    expect(approved.executionStatus).toBe('unknown')
    expect(approved.result).toBeUndefined()
    const identity = (await fixture.service.acquireManagement().listIdentities())[0]!
    await fixture.service.acquireManagement().deleteIdentity({ reference: identity.reference, confirmationName: 'Identity unknown-delete' })
    await fixture.restart()
    expect(await fixture.first.getCreateRequest(request.id)).toMatchObject({ executionStatus: 'deleted', result: { reference: identity.reference } })
    expect(await fixture.host().list()).toEqual([])
  })

  it('rejects legacy caller laundering through the installed plugin service proxy', async () => {
    await using fixture = await userFixture()
    const proxy = fixture.firstContext.anpIdentity as AnpIdentityService
    const proxyContext = (proxy as unknown as { ctx: Context }).ctx
    const rootContext = (fixture.service as unknown as { ctx: Context }).ctx
    expect(proxyContext.fiber).toBe(fixture.firstContext.fiber)
    expect(proxyContext.fiber).not.toBe(rootContext.fiber)
    await expect(proxy.acquireClient({
      consumer: 'host-fixture', capabilities: ['identity:read', 'identity:create', 'identity:delete', 'identity:recover'],
    })).rejects.toMatchObject({ code: 'consumer_forbidden' })
    expect(() => proxy.acquireProvider({
      consumer: 'host-fixture', capabilities: ['IDENTITY_READ', 'IDENTITY_CREATE', 'IDENTITY_DELETE'],
    })).toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))
    expect(() => proxy.acquireManagement()).toThrowError(expect.objectContaining({ code: 'consumer_forbidden' }))
    expect(await fixture.host().list()).toEqual([])
    expect(await fixture.service.acquireManagement().listIdentities()).toEqual([])
    const reference = await createApproved(fixture, 'root-manager')
    expect((await fixture.service.acquireManagement().listIdentities())[0]?.reference).toEqual(reference)
  })

  it('binds installation provenance and blocks the old self-claimed consumer API', async () => {
    await using fixture = await userFixture()
    await expect(fixture.service.acquireClient({ consumer: 'user-one', capabilities: ['identity:read', 'identity:create'] }))
      .rejects.toMatchObject({ code: 'capability_forbidden' })
    expect(() => fixture.service.bindUserConsumer(new Context())).toThrow()
    const request = await fixture.first.requestCreateIdentity(createInput('provenance'))
    expect(request.caller.consumer).toBe('user-one')
    await expect(fixture.second.getCreateRequest(request.id)).rejects.toThrow()
    await expect(fixture.second.cancelCreateRequest(request.id, request.version)).rejects.toThrow()
    expect((await fixture.first.getCreateRequest(request.id)).status).toBe('pending')
    await expect(fixture.host().list()).resolves.toEqual([])
  })

  it('persists a frozen creation request without creating an identity before approval', async () => {
    await using fixture = await userFixture()
    const input = createInput('pending')
    const request = await fixture.first.requestCreateIdentity(input)
    input.parameters.label = 'Changed after submission'
    const loaded = await fixture.first.getCreateRequest(request.id)
    expect(loaded).toMatchObject({ kind: 'create', status: 'pending', parameters: { label: 'Identity pending' } })
    await expect(fixture.host().list()).resolves.toEqual([])
    await fixture.restart()
    await expect(fixture.first.getCreateRequest(request.id)).resolves.toMatchObject({ id: request.id, status: 'pending' })
    await expect(fixture.host().list()).resolves.toEqual([])
    const cancelled = await fixture.first.cancelCreateRequest(request.id, request.version)
    expect(cancelled.status).toBe('cancelled')
    await expect(fixture.host().list()).resolves.toEqual([])
  })

  it('rejects parameter replacement under a stable creation request ID', async () => {
    await using fixture = await userFixture()
    const input = createInput('immutable')
    const original = await fixture.first.requestCreateIdentity(input)
    await expect(fixture.first.requestCreateIdentity({
      ...input, parameters: { ...input.parameters, domain: 'attacker.example' },
    })).rejects.toThrow()
    const unchanged = await fixture.first.getCreateRequest(original.id)
    expect(unchanged).toMatchObject({ parameters: { domain: 'example.com' }, status: 'pending' })
    await expect(fixture.host().list()).resolves.toEqual([])
  })

  it('creates exactly once and keeps creation and use as independent decisions across restart', async () => {
    await using fixture = await userFixture()
    const request = await fixture.first.requestCreateIdentity(createInput('approved'))
    const approved = await fixture.service.acquireManagement().decide({
      requestId: request.id, expectedVersion: request.version, decision: 'approve',
    }) as CreateAuthorizationRequest
    expect(approved.executionStatus).toBe('succeeded')
    expect(approved.result?.reference.did).toContain('did:wba:example.com:')
    expect(Object.keys(approved.result!).sort()).toEqual(['label', 'reference'])
    expect((await fixture.authorizationState()).grants).toEqual([])
    const catalog = JSON.parse(await readFile(join(fixture.root, 'catalog-v1.json'), 'utf8'))
    expect(catalog.entries).toHaveLength(1)
    expect(catalog.entries[0].grantedConsumers).toEqual([])
    const access = await fixture.first.requestAccess({
      requestId: 'declined-use', purpose: 'Read the created identity', identity: approved.result!.reference,
      operation: { action: 'read' },
    })
    await fixture.service.acquireManagement().decide({ requestId: access.id, expectedVersion: access.version, decision: 'deny' })
    expect((await fixture.authorizationState()).grants).toEqual([])
    await fixture.restart()
    const retried = await fixture.first.requestCreateIdentity(createInput('approved')) as CreateAuthorizationRequest
    expect(retried.result?.reference).toEqual(approved.result?.reference)
    expect(await fixture.host().list()).toHaveLength(1)
    expect((await fixture.authorizationState()).grants).toEqual([])
  })

  it('signs only the approved payload once, without leaking management capabilities or replaying after restart', async () => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'once-sign')
    const signing = { purpose: 'authentication' as const, kid: `${reference.did}#request`, payload: Buffer.from('approved native payload') }
    const request = await fixture.first.requestAccess({
      requestId: 'once-sign-access', purpose: 'Sign one immutable authentication payload', identity: reference,
      operation: { action: 'sign', request: signing },
    })
    const approved = await fixture.service.acquireManagement().decide({
      requestId: request.id, expectedVersion: request.version, decision: 'approve', identity: reference, mode: 'once',
      reviewedSnapshot: (await fixture.service.acquireManagement().getRequest(request.id)).snapshot!,
    }) as AccessAuthorizationRequest
    const identity = await fixture.first.openAuthorizedIdentity(approved.grantId!)
    for (const forbidden of ['create', 'delete', 'recover', 'setHandle', 'acquireProvider', 'prepareDocumentChange', 'exportPrivateKey']) {
      expect(forbidden in identity).toBe(false)
    }
    await expect(identity.sign({ ...signing, payload: Buffer.from('different payload') }, 'wrong-sign')).rejects.toThrow()
    await expect(identity.publicIdentity('wrong-read')).rejects.toThrow()
    const secondObject = await fixture.first.openAuthorizedIdentity(approved.grantId!)
    const attempts = await Promise.allSettled([
      identity.sign(signing, 'approved-sign-a'), secondObject.sign(signing, 'approved-sign-b'),
    ])
    expect(attempts.filter(result => result.status === 'fulfilled')).toHaveLength(1)
    expect(attempts.filter(result => result.status === 'rejected')).toHaveLength(1)
    const successIndex = attempts.findIndex(result => result.status === 'fulfilled')
    const success = attempts[successIndex]!
    if (success.status !== 'fulfilled') throw new Error('No native signature was admitted')
    const signature = success.value
    const executionId = successIndex === 0 ? 'approved-sign-a' : 'approved-sign-b'
    expect(signature.bytes).toHaveLength(64)
    await expect(fixture.host().verify(reference, { ...signing, kid: signature.kid, signature: signature.bytes })).resolves.toBe('valid')
    await expect(identity.sign(signing, 'second-sign')).rejects.toThrow()
    await fixture.restart()
    await expect(fixture.first.openAuthorizedIdentity(approved.grantId!)).rejects.toThrow()
    await expect(fixture.first.getExecution(executionId)).resolves.toMatchObject({ status: 'succeeded' })
    await expect(fixture.second.getExecution(executionId)).rejects.toThrow()
  })

  it('binds once HTTP to exact body and URL, adds native signatures, and never refunds a transport failure', async () => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'once-http')
    const makeRequest = (body = 'approved-body', path = '/profile') => new Request(`${ORIGIN}${path}`, { method: 'POST', body })
    const request = await fixture.first.requestAccess({
      requestId: 'once-http-access', purpose: 'Send one authenticated profile operation', identity: reference,
      operation: { action: 'http', request: makeRequest() },
    })
    const approved = await fixture.service.acquireManagement().decide({
      requestId: request.id, expectedVersion: request.version, decision: 'approve', identity: reference, mode: 'once',
      reviewedSnapshot: (await fixture.service.acquireManagement().getRequest(request.id)).snapshot!,
    }) as AccessAuthorizationRequest
    const identity = await fixture.first.openAuthorizedIdentity(approved.grantId!)
    let calls = 0
    const transport = vi.spyOn(globalThis, 'fetch').mockImplementation(async input => {
      if (!(input instanceof Request)) throw new Error('Host did not supply a signed Request')
      const sent = input
      calls += 1
      expect(sent.redirect).toBe('manual')
      expect(sent.headers.get('signature')).toBeTruthy()
      expect(sent.headers.get('signature-input')).toBeTruthy()
      expect(await sent.text()).toBe('approved-body')
      throw new Error('Simulated connection loss after admission')
    })
    await expect(identity.authenticatedHttp.dispatch(makeRequest('changed'), 'wrong-body')).rejects.toThrow()
    await expect(identity.authenticatedHttp.dispatch(makeRequest('approved-body', '/elsewhere'), 'wrong-url')).rejects.toThrow()
    const hostileTransport = vi.fn(async () => new Response('consumer-controlled transport'))
    await expect(identity.authenticatedHttp.dispatch(makeRequest(), hostileTransport as unknown as string))
      .rejects.toMatchObject({ code: 'invalid_request' })
    expect(hostileTransport).not.toHaveBeenCalled()
    expect(calls).toBe(0)
    await expect(identity.authenticatedHttp.dispatch(makeRequest(), 'approved-http')).rejects.toThrow('Simulated connection loss')
    expect(calls).toBe(1)
    await expect(identity.authenticatedHttp.dispatch(makeRequest(), 'retry-http')).rejects.toThrow()
    expect(calls).toBe(1)
    expect(transport).toHaveBeenCalledTimes(1)
    await fixture.restart()
    await expect(fixture.first.openAuthorizedIdentity(approved.grantId!)).rejects.toThrow()
    await expect(fixture.first.getExecution('approved-http')).resolves.toMatchObject({ status: 'unknown' })
    const persisted = await readFile(join(fixture.root, 'authorization-v1.json'), 'utf8')
    expect(persisted).not.toContain('approved-body')
    expect(persisted).not.toContain('approved native payload')
  })

  it('preserves a permanent snapshot across restart and revokes old objects without granting another consumer access', async () => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'permanent')
    const request = await fixture.first.requestAccess({ requestId: 'permanent-access', purpose: 'Use this identity until revoked', identity: reference })
    const manager = fixture.service.acquireManagement()
    const approved = await manager.decide({
      requestId: request.id, expectedVersion: request.version, decision: 'approve', identity: reference, mode: 'permanent',
      reviewedSnapshot: (await fixture.service.acquireManagement().getRequest(request.id)).snapshot!,
    }) as AccessAuthorizationRequest
    const original = await fixture.first.openAuthorizedIdentity(approved.grantId!)
    await expect(original.publicIdentity()).resolves.toMatchObject({ reference })
    await expect(fixture.second.openAuthorizedIdentity(approved.grantId!)).rejects.toThrow()
    const grants = await manager.grants(reference)
    expect(grants).toHaveLength(1)
    expect(grants[0]).toMatchObject({
      mode: 'permanent', identity: reference,
      snapshot: { capabilities: ['identity:read', 'identity:sign', 'identity:http-auth'], httpOrigins: [ORIGIN] },
    })
    await fixture.restart([ORIGIN, 'https://new.example.com'])
    const reopened = await fixture.first.openAuthorizedIdentity(approved.grantId!)
    await expect(reopened.publicIdentity()).resolves.toMatchObject({ reference })
    const transported = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('A forbidden Origin reached transport'))
    await expect(reopened.authenticatedHttp.dispatch(new Request('https://new.example.com/profile'), 'new-origin')).rejects.toThrow()
    expect(transported).not.toHaveBeenCalled()
    const currentManager = fixture.service.acquireManagement()
    const current = (await currentManager.grants(reference))[0]!
    expect(current.snapshot.httpOrigins).toEqual([ORIGIN])
    await currentManager.revoke({ grantId: current.id, expectedVersion: current.version })
    await expect(reopened.publicIdentity()).rejects.toThrow()
    await expect(fixture.first.openAuthorizedIdentity(approved.grantId!)).rejects.toThrow()
    expect(await fixture.host().list()).toHaveLength(1)
    expect(await currentManager.listIdentities()).toHaveLength(1)
  })

  it('lists grant-free identities and saved handles without inventing a verified binding', async () => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'handle')
    const manager = fixture.service.acquireManagement()
    let identities = await manager.listIdentities()
    expect(identities).toHaveLength(1)
    expect(identities[0]).toMatchObject({ reference })
    expect(identities[0]?.handle).toBeUndefined()
    // Simulate existing trusted integration metadata, not a Handle registration API.
    const { CatalogStore } = await import('../src/catalog.js')
    await new CatalogStore(fixture.root).mutate(catalog => ({
      ...catalog, entries: catalog.entries.map(entry => entry.identityId === reference.identityId ? { ...entry, handle: 'saved.handle' } : entry),
    }))
    identities = await manager.listIdentities()
    expect(identities[0]?.handle).toBe('saved.handle')
    expect(await manager.grants(reference)).toEqual([])
    const document = await manager.publicDocument(reference) as { id: string }
    expect(document.id).toBe(reference.did)
    expect(JSON.stringify(document)).not.toContain('grantedConsumers')
    expect(JSON.stringify(document)).not.toContain('privateKey')
    await fixture.restart()
    expect((await fixture.service.acquireManagement().listIdentities())[0]?.handle).toBe('saved.handle')
  })

  it('blocks deletion while granted and preserves a creation tombstone after confirmed deletion', async () => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'deletion')
    const manager = fixture.service.acquireManagement()
    const request = await fixture.first.requestAccess({ requestId: 'delete-grant', purpose: 'Read until revoked', identity: reference })
    const approved = await manager.decide({
      requestId: request.id, expectedVersion: request.version, decision: 'approve', identity: reference, mode: 'permanent',
      reviewedSnapshot: (await fixture.service.acquireManagement().getRequest(request.id)).snapshot!,
    }) as AccessAuthorizationRequest
    await expect(manager.deleteIdentity({ reference, confirmationName: 'Identity deletion' })).rejects.toThrow()
    expect(await fixture.host().list()).toHaveLength(1)
    const grant = (await manager.grants(reference)).find(value => value.id === approved.grantId)!
    await manager.revoke({ grantId: grant.id, expectedVersion: grant.version })
    await expect(manager.deleteIdentity({ reference, confirmationName: 'incorrect name' })).rejects.toThrow()
    await manager.deleteIdentity({ reference, confirmationName: 'Identity deletion' })
    expect(await manager.listIdentities()).toEqual([])
    expect(await fixture.host().list()).toEqual([])
    await fixture.restart()
    const retry = await fixture.first.requestCreateIdentity(createInput('deletion')) as CreateAuthorizationRequest
    expect(retry.executionStatus).toBe('deleted')
    expect(await fixture.host().list()).toEqual([])
  })

  it('requires a concrete operation for default once approval and preserves pending requests when merely prompted', async () => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'explicit-operation')
    const manager = fixture.service.acquireManagement()
    const request = await fixture.first.requestAccess({ requestId: 'missing-operation', purpose: 'Request ordinary identity access', identity: reference })
    await manager.markPrompted({ requestId: request.id, expectedVersion: request.version })
    const pending = await manager.listRequests()
    expect(pending).toHaveLength(1)
    expect(pending[0]).toMatchObject({ id: request.id, status: 'pending', prompted: true })
    await expect(manager.decide({ requestId: request.id, expectedVersion: pending[0]!.version, decision: 'approve', identity: reference }))
      .rejects.toMatchObject({ code: 'once_operation_required' })
    expect(await manager.grants(reference)).toEqual([])
    expect(await manager.listRequests()).toHaveLength(1)
    const approved = await manager.decide({ requestId: request.id, expectedVersion: pending[0]!.version, decision: 'approve', identity: reference, mode: 'permanent', reviewedSnapshot: (await manager.getRequest(request.id)).snapshot! })
    expect(approved).toMatchObject({ status: 'approved', mode: 'permanent' })
    expect(await manager.listRequests()).toEqual([])
  })

  it('never turns corrupt Handle metadata into an empty identity list or a missing Handle', async () => {
    await using fixture = await userFixture()
    await createApproved(fixture, 'corrupt-metadata')
    await writeFile(join(fixture.root, 'catalog-v1.json'), '{invalid catalog', 'utf8')
    await expect(fixture.service.acquireManagement().listIdentities()).rejects.toMatchObject({ code: 'catalog_corrupt' })
    expect(await fixture.host().list()).toHaveLength(1)
  })

  it('cancels both pending request kinds when their installed consumer is disabled and disposed', async () => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'lifecycle')
    const creation = await fixture.first.requestCreateIdentity(createInput('disabled-pending'))
    const access = await fixture.first.requestAccess({
      requestId: 'disabled-access', purpose: 'Pending use during plugin disable', identity: reference, operation: { action: 'read' },
    })
    const manager = fixture.service.acquireManagement()
    expect(await manager.listRequests()).toHaveLength(2)
    await fixture.disableFirst()
    await expect.poll(async () => (await manager.listRequests()).length, { timeout: 4000, interval: 25 }).toBe(0)
    const history = await manager.listRequests(true)
    expect(history.find(request => request.id === creation.id)?.status).toBe('cancelled')
    expect(history.find(request => request.id === access.id)?.status).toBe('cancelled')
    await expect(manager.decide({ requestId: creation.id, expectedVersion: creation.version, decision: 'approve' })).rejects.toThrow()
    expect(await fixture.host().list()).toHaveLength(1)
    expect(await manager.grants(reference)).toEqual([])
  })

  it('rejects a missing native signing key before consuming a matching once operation', async () => {
    await using fixture = await userFixture()
    const reference = await createApproved(fixture, 'invalid-native-kid')
    const signing = { purpose: 'authentication' as const, kid: `${reference.did}#missing`, payload: Buffer.from('native key validation') }
    const request = await fixture.first.requestAccess({
      requestId: 'missing-kid-access', purpose: 'Validate a native key before execution', identity: reference,
      operation: { action: 'sign', request: signing },
    })
    const manager = fixture.service.acquireManagement()
    const approved = await manager.decide({
      requestId: request.id, expectedVersion: request.version, decision: 'approve', identity: reference, mode: 'once',
      reviewedSnapshot: (await fixture.service.acquireManagement().getRequest(request.id)).snapshot!,
    }) as AccessAuthorizationRequest
    const identity = await fixture.first.openAuthorizedIdentity(approved.grantId!)
    await expect(identity.sign(signing, 'missing-kid-execution')).rejects.toThrow()
    const grants = await manager.grants(reference)
    expect(grants.find(grant => grant.id === approved.grantId)?.status).toBe('active')
    await expect(fixture.first.getExecution('missing-kid-execution')).rejects.toThrow()
    await fixture.restart()
    expect((await fixture.service.acquireManagement().grants(reference)).find(grant => grant.id === approved.grantId)?.status).toBe('active')
  })
})

async function createApproved(fixture: Awaited<ReturnType<typeof userFixture>>, name: string) {
  const request = await fixture.first.requestCreateIdentity(createInput(name))
  const approved = await fixture.service.acquireManagement().decide({
    requestId: request.id, expectedVersion: request.version, decision: 'approve',
  }) as CreateAuthorizationRequest
  expect(approved.executionStatus).toBe('succeeded')
  return approved.result!.reference
}

function createInput(name: string) {
  return {
    requestId: `create-${name}`, purpose: 'Create an identity for the isolated test consumer',
    parameters: { label: `Identity ${name}`, domain: 'example.com', path: `/dsh/${name}` },
  }
}

async function userFixture() {
  const root = await mkdtemp(join(tmpdir(), 'dsh-anp-identity-user-'))
  let runtime: Awaited<ReturnType<typeof start>>
  try { runtime = await start(root) } catch (error) {
    await rm(root, { recursive: true, force: true })
    throw error
  }
  return {
    root,
    get ctx() { return runtime.ctx },
    get service() { return runtime.service },
    get first() { return runtime.first },
    get firstContext() { return runtime.firstContext },
    get second() { return runtime.second },
    async disableFirst() {
      const entry = runtime.installations.find(value => value.options.name === 'user-one')!
      entry.disabled = true
      await runtime.firstContext.fiber.dispose()
    },
    host() { return runtime.service.acquireProvider({ consumer: 'host-fixture', capabilities: ['IDENTITY_READ', 'IDENTITY_SIGN'] }) },
    async authorizationState(): Promise<{ requests: AuthorizationRequest[]; grants: unknown[] }> {
      return JSON.parse(await readFile(join(root, 'authorization-v1.json'), 'utf8'))
    },
    async restart(origins: string[] = [ORIGIN], hooks?: StartupHooks) {
      await runtime.ctx.fiber.dispose()
      runtime = await start(root, origins, hooks)
    },
    async [Symbol.asyncDispose]() {
      await runtime.ctx.fiber.dispose()
      await rm(root, { recursive: true, force: true })
    },
  }
}

interface StartupHooks {
  beforeProvider?(service: AnpIdentityService, first: UserIdentityClient): void
  afterProvider?(service: AnpIdentityService, first: UserIdentityClient): Promise<void>
}

function latch() {
  let resolve!: () => void
  const promise = new Promise<void>(done => { resolve = done })
  return { promise, resolve }
}

async function start(root: string, origins = [ORIGIN], hooks?: StartupHooks) {
  const ctx = new Context()
  const installations: Array<{ options: { name: string }; fiber: Context['fiber']; disabled: boolean }> = []
  const contexts = new Map<string, Context>()
  // Only installation metadata is a fixture; policy, native keys and storage are real.
  ctx.provide('loader', { *entries() { yield* installations } })
  const config: Config = {
    stateRoot: root, allowConsumers: ['user-one', 'user-two', 'host-fixture'], userConsumers: ['user-one', 'user-two'],
    allowProviderConsumers: ['host-fixture'],
    httpAllowedOrigins: { 'user-one': origins, 'user-two': origins },
  }
  await ctx.plugin(AnpIdentityService, config)
  const service = ctx.anpIdentity as AnpIdentityService
  async function install(name: string): Promise<UserIdentityClient> {
    let context: Context | undefined
    await ctx.plugin(Object.assign((pluginContext: Context) => { context = pluginContext }, { inject: ['anpIdentity'] }))
    if (!context) throw new Error('Consumer context was not created')
    installations.push({ options: { name }, fiber: context.fiber, disabled: false })
    contexts.set(name, context)
    return service.bindUserConsumer(context)
  }
  const first = await install('user-one')
  const second = await install('user-two')
  try {
    hooks?.beforeProvider?.(service, first)
    const registration = await openNativeProvider({
      stateRoot: root, rootKeyProvider: 'injected', rootKeyProviderId: 'v7-service-test-root',
      injectedRootKey: Buffer.alloc(32, 71),
    })
    ;(service as unknown as NativeProviderRegistry).registerProvider(registration)
    await hooks?.afterProvider?.(service, first)
    for (let attempt = 0; attempt < 100; attempt += 1) {
      if ((await service.health()).status === 'ready') break
      if (attempt === 99) throw new Error('Native Provider did not become ready')
      await new Promise(resolve => setTimeout(resolve, 10))
    }
  } catch (error) {
    await ctx.fiber.dispose()
    throw error
  }
  return { ctx, service, first, second, firstContext: contexts.get('user-one')!, installations }
}
