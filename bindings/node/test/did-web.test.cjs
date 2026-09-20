'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')
const { IdentityManager } = require('..')
const { IdentityProvider } = require('../provider')

function request() {
  return {
    profile: 'web', domain: 'identity.example', pathSegments: ['awiki', 'web', 'node-test'],
    capabilities: { didWba: true },
    managedKeys: [
      { fragment: 'device-sign', role: 'device_signing' },
      { fragment: 'device-ka', role: 'e2ee_agreement' },
    ],
    extensions: [{ type: 'device_manifest', value: { devices: [{
      deviceId: 'device-a', signingKeyId: '#device-sign', e2eeKeyId: '#device-ka',
      profiles: ['anp.core.binding.v1', 'anp.identity.discovery.v1', 'anp.direct.base.v1',
        'anp.group.base.v2', 'anp.direct.e2ee.v2', 'anp.group.e2ee.v2'],
    }] } }],
  }
}

function config(root) {
  return { stateRoot: root, rootKeyKind: 'injected', keyId: 'web-node', rootKey: Buffer.alloc(32, 53) }
}

test('Web facade reopens rootless identity and retains uncertain publication', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-web-node-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const manager = await IdentityManager.initialize(config(root))
  const identity = await manager.create(request())
  const before = await identity.publicIdentity()
  assert.equal(before.reference.did, 'did:web:identity.example:awiki:web:node-test')
  assert.equal(before.document.proof, undefined)
  assert.equal(before.activeKeys.length, 2)
  const signature = await identity.sign({ purpose: 'device_assertion', payload: Buffer.from('Web custody') })
  const change = await identity.prepareDocumentChange({ changes: [{ change: 'replace_services', services: [{
    id: 'api', serviceType: 'API', serviceEndpoint: 'https://api.example',
  }] }] })
  const candidate = await change.candidate()
  const attempt = await change.beginPublication()
  assert.equal((await change.complete(attempt, { result: 'unknown' })).outcome, 'publication_uncertain')
  const reopened = await IdentityManager.open(config(root))
  const restored = await reopened.get(before.reference)
  assert.equal(await restored.verify({ purpose: 'device_assertion', kid: signature.kid,
    payload: Buffer.from('Web custody'), signature: signature.bytes }), 'valid')
  const pending = await restored.resumeDocumentChange()
  assert.deepEqual(await pending.candidate(), candidate)
  await assert.rejects(pending.beginPublication())
})

test('Web provider exposes no DID root and rejects legacy WBA and root export', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-web-provider-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const provider = await IdentityProvider.initialize(config(root))
  const lease = await provider.acquireLease({ consumer: 'web-test', ttlSeconds: 60,
    capabilities: ['IDENTITY_CREATE', 'IDENTITY_READ', 'IDENTITY_HTTP_SIGNATURE', 'AWIKI_LEGACY_ROOT_TRANSFER_V1'] })
  const identity = await lease.create(request())
  const status = await lease.hostStatus(identity.reference)
  assert.equal(status.rootCapability, 'absent')
  assert.equal(status.rootKeyFingerprint, null)
  const signed = await lease.prepareHttpSignature({ identity: identity.reference,
    url: 'https://identity.example/user/rpc', method: 'POST', headers: [], body: Buffer.from('{}') })
  assert.ok(signed.headerPatch.some(header => header.name === 'Signature'))
  await assert.rejects(lease.prepareLegacyDidWba(identity.reference, { serviceDomain: 'identity.example', version: '1.1' }))
  const { publicKey } = crypto.generateKeyPairSync('x25519')
  await assert.rejects(lease.exportRootKeySealed({ identity: identity.reference,
    kid: `${identity.reference.did}#root`, recipientPublicKey: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url'),
    requestId: 'web-root-export', userPresenceConfirmed: true }))
})


test('Web provider reconciles terminal CAS rejection through native custody', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-web-conflict-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const provider = await IdentityProvider.initialize(config(root))
  const lease = await provider.acquireLease({ consumer: 'web-conflict', ttlSeconds: 60,
    capabilities: ['IDENTITY_CREATE', 'IDENTITY_READ', 'IDENTITY_DOCUMENT_UPDATE'] })
  const identity = await lease.create(request())
  const status = await lease.hostStatus(identity.reference)
  const observation = { document: identity.document, evidence: {
    documentVersion: status.checkpoint.documentVersion,
    registryVersion: status.checkpoint.registryVersion,
    documentDigest: status.checkpoint.documentDigest,
  } }
  const change = await lease.prepareDocumentChange(identity.reference, { changes: [{ change: 'replace_services', services: [] }] })
  const attempt = await change.beginPublication()
  await change.complete(attempt, { result: 'unknown' })
  await assert.rejects(change.reconcileRejected(observation))
  observation.evidence.registryVersion += 1
  assert.deepEqual(await change.reconcileRejected(observation), { outcome: 'aborted' })
  assert.equal(await lease.resumeDocumentChange(identity.reference), undefined)
  assert.deepEqual((await lease.publicIdentity(identity.reference)).document, identity.document)
})
