'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')

const { IdentityManager, IdentityTransitionSession } = require('..')

test('IdentityTransitionSession reuses one candidate and reconciles response loss', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-identity-transition-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const manager = await IdentityManager.initialize(config(root))
  const predecessor = await (await manager.create(identitySpec())).reference()
  const successor = await (await manager.create(identitySpec())).reference()

  const session = await manager.prepareIdentityTransition({
    expectedCurrentDid: predecessor.did,
    operationId: 'node-transition-response-loss',
    successor,
  })
  assert.ok(session instanceof IdentityTransitionSession)
  const candidate = await session.candidate()
  assert.equal(candidate.expectedCurrentDid, predecessor.did)
  assert.equal(candidate.successorDid, successor.did)
  assert.equal(candidate.assurance, 'verified')
  assert.equal(candidate.predecessorDocument.deactivated, true)
  assert.equal(candidate.predecessorDocument.successorDid, successor.did)
  assert.doesNotMatch(JSON.stringify(candidate), /private|secret|BEGIN PRIVATE KEY/i)

  const attempt = await session.beginPublication()
  assert.equal(
    (await session.complete(attempt, { result: 'unknown' })).outcome,
    'publication_uncertain',
  )

  const reopened = await IdentityManager.open(config(root))
  const resumed = await reopened.resumeIdentityTransition(predecessor.did)
  assert.deepEqual(await resumed.candidate(), candidate)
  const committed = await resumed.reconcile({
    observation: 'published',
    predecessorDocument: candidate.predecessorDocument,
    successorDocument: candidate.successorDocument,
  })
  assert.deepEqual(committed, { outcome: 'committed', currentDid: successor.did })
  assert.equal(await reopened.resumeIdentityTransition(predecessor.did), undefined)
})

function config(stateRoot) {
  return {
    stateRoot,
    rootKeyKind: 'injected',
    keyId: 'transition-node-test',
    rootKey: Buffer.alloc(32, 0x41),
  }
}

function identitySpec() {
  return {
    profile: 'e1',
    domain: 'example.com',
    pathSegments: ['node', 'transition'],
    capabilities: { didWba: true },
    managedKeys: [
      { fragment: 'root', role: 'root_control' },
      { fragment: 'request', role: 'request_signing' },
    ],
  }
}
