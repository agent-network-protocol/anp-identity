'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')

const binding = require('..')
const { IdentityManager } = binding

test('default Node Facade manages multiple identities and purpose-scoped signing', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-identity-node-facade-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const rootKey = Buffer.alloc(32, 7)
  const manager = await IdentityManager.initialize({
    stateRoot: root,
    rootKeyKind: 'injected',
    keyId: 'node-test',
    rootKey,
  })
  assert.ok(rootKey.every((byte) => byte === 0), 'native boundary must overwrite rootKey')

  const alice = await manager.create(identitySpec('alice'))
  await manager.create(identitySpec('bob'))
  assert.equal((await manager.info()).identityCount, 2)
  assert.equal((await manager.list()).length, 2)

  const snapshot = await alice.publicIdentity()
  assert.equal(snapshot.state, 'active')
  assert.equal(snapshot.activeKeys.length, 5)
  assert.equal(snapshot.capabilities.didWba, true)
  assert.equal(Object.hasOwn(snapshot, 'rootKeyFingerprint'), false)

  const message = Buffer.from('hello from the Facade')
  const signature = await alice.sign({
    purpose: 'authentication',
    kid: `${snapshot.reference.did}#request`,
    payload: message,
  })
  assert.equal(signature.algorithm, 'ed25519')
  assert.equal(
    await alice.verify({
      purpose: 'authentication',
      kid: signature.kid,
      payload: message,
      signature: signature.bytes,
    }),
    'valid',
  )
  assert.equal(
    await alice.verify({
      purpose: 'authentication',
      kid: signature.kid,
      payload: Buffer.from('tampered'),
      signature: signature.bytes,
    }),
    'invalid',
  )
  await assert.rejects(
    alice.sign({ purpose: 'authentication', kid: `${snapshot.reference.did}#root`, payload: message }),
    (error) => error.code === 'key_purpose_violation',
  )

  const proof = await alice.signOriginProof({
    method: 'message.send',
    meta: {
      sender_did: snapshot.reference.did,
      timestamp: Math.floor(Date.now() / 1000),
      target: { kind: 'agent', did: 'did:wba:example.com:node:peer' },
      operation_id: 'operation-1',
      message_id: 'message-1',
      content_type: 'application/json',
    },
    body: { text: 'hello' },
    kid: `${snapshot.reference.did}#request`,
    options: {
      created: Math.floor(Date.now() / 1000),
      expires: Math.floor(Date.now() / 1000) + 300,
      nonce: 'node-facade',
    },
  })
  assert.match(proof.contentDigest, /^sha-256=/)
  assert.match(proof.signatureInput, /node-facade/)

  const change = await alice.prepareDocumentChange({
    changes: [
      {
        change: 'rotate_signing_key',
        oldKid: '#request',
        newFragment: 'request-v2',
      },
    ],
  })
  const candidate = await change.candidate()
  const attempt = await change.beginPublication()
  const outcome = await change.complete(attempt, {
    result: 'confirmed',
    evidence: {
      documentVersion: 2,
      registryVersion: 2,
      documentDigest: candidate.candidateDigest,
    },
  })
  assert.equal(outcome.outcome, 'committed')
  assert.equal(outcome.identity.revision, 2)
  assert.equal(await alice.resumeDocumentChange(), undefined)

  const reopenedKey = Buffer.alloc(32, 7)
  const reopened = await IdentityManager.open({
    stateRoot: root,
    rootKeyKind: 'injected',
    keyId: 'node-test',
    rootKey: reopenedKey,
  })
  assert.ok(reopenedKey.every((byte) => byte === 0))
  const reopenedAlice = await reopened.get(snapshot.reference)
  assert.equal((await reopenedAlice.publicIdentity()).revision, 2)
  assert.deepEqual(Object.keys(binding).sort(), [
    'DocumentChangeSession',
    'IdentityManager',
    'IdentityTransitionSession',
    'ManagedIdentity',
  ])
  assert.equal('DidStore' in binding, false)
  assert.equal('ecdh' in Object.getPrototypeOf(alice), false)
})

function identitySpec(name) {
  return {
    profile: 'e1',
    domain: 'example.com',
    pathSegments: ['node', name],
    capabilities: { didWba: true },
    managedKeys: [
      { fragment: 'root', role: 'root_control' },
      { fragment: 'request', role: 'request_signing' },
      { fragment: 'device', role: 'device_signing' },
      { fragment: 'application', role: 'e2ee_signing' },
      { fragment: 'agreement', role: 'e2ee_agreement' },
    ],
    extensions: [
      {
        type: 'device_manifest',
        value: {
          devices: [
            {
              deviceId: `${name}-device`,
              signingKeyId: '#device',
              e2eeKeyId: '#agreement',
              profiles: ['anp.core.binding.v1'],
            },
          ],
        },
      },
    ],
  }
}
