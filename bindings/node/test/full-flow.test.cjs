'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')

const binding = require('..')
const { DidStore } = binding

test('Node binding runs the complete E1 store and peer crypto flow', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-did-node-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const rootKey = Buffer.alloc(32, 7)
  const store = await DidStore.initializeInjected(root, 'node-test', rootKey)
  assert.ok(rootKey.every((byte) => byte === 0), 'native boundary must overwrite the input Buffer')
  assert.deepEqual(Object.keys(store), [], 'the native store handle must remain private')

  const invalidRootKey = Buffer.alloc(31, 9)
  await assert.rejects(
    DidStore.openInjected(root, 'node-test', invalidRootKey),
    (error) => error.code === 'invalid_root_key',
  )
  assert.ok(invalidRootKey.every((byte) => byte === 0))

  const alice = await store.createIdentity(identitySpec('alice'))
  const bob = await store.createIdentity(identitySpec('bob'))
  const aliceSnapshot = await alice.snapshot()
  assert.equal(aliceSnapshot.state, 'active')
  assert.equal(aliceSnapshot.keys.length, 4)
  assert.equal((await store.listIdentities()).length, 2)

  const message = Buffer.from('hello from Node')
  const signature = await alice.sign('#request', message)
  assert.equal(await alice.verify('#request', message, signature), true)
  assert.equal(await alice.verify('#request', Buffer.from('tampered'), signature), false)
  await assert.rejects(alice.sign('#root', message), (error) => error.code === 'key_role_violation')

  const alicePublic = await alice.publicKeyBytes('#agreement')
  const bobPublic = await bob.publicKeyBytes('#agreement')
  const aliceShared = await alice.ecdh('#agreement', bobPublic)
  const bobShared = await bob.ecdh('#agreement', alicePublic)
  assert.deepEqual(aliceShared, bobShared)
  aliceShared.fill(0)
  bobShared.fill(0)

  const legacy = await alice.legacyDidWbaHeader('#request', 'api.example.com', '1.1')
  assert.match(legacy, /^DIDWba /)
  const httpHeaders = await alice.httpSignatureHeaders(
    '#request',
    'https://api.example.com/messages',
    'POST',
    [],
    Buffer.from('{"message":"hello"}'),
  )
  assert.ok(httpHeaders.some((header) => header.name === 'Signature'))

  const prepared = await alice.prepareUpdate({
    requestSigningRotation: { oldKid: '#request', newFragment: 'request-v2' },
    services: [],
  })
  assert.equal((await alice.pendingRevision()).state, 'prepared')
  await alice.beginPublication(prepared.revisionId)
  await alice.markPublished(prepared.revisionId)
  await alice.commitUpdate(prepared.revisionId)
  const rotated = await alice.snapshot()
  assert.equal(rotated.revision, 2)
  assert.equal(rotated.keys.find((key) => key.kid.endsWith('#request')).state, 'retired')
  assert.equal(rotated.keys.find((key) => key.kid.endsWith('#request-v2')).state, 'active')
  assert.equal(await alice.pendingRevision(), undefined)

  const uncertain = await alice.prepareUpdate({
    requestSigningRotation: { oldKid: '#request-v2', newFragment: 'request-v3' },
  })
  await alice.beginPublication(uncertain.revisionId)
  await alice.markPublicationUncertain(uncertain.revisionId)
  await assert.rejects(
    alice.abortUpdate(uncertain.revisionId),
    (error) => error.code === 'invalid_publication_state',
  )
  assert.equal(
    await alice.reconcileUpdate(uncertain.revisionId, uncertain.candidateDocument),
    'committed',
  )
  assert.equal((await alice.snapshot()).revision, 3)

  const reopenKey = Buffer.alloc(32, 7)
  const reopened = await DidStore.openInjected(root, 'node-test', reopenKey)
  assert.ok(reopenKey.every((byte) => byte === 0))
  assert.equal((await reopened.listIdentities()).length, 2)
  const reopenedAlice = await reopened.openIdentity(aliceSnapshot.did)
  assert.equal((await reopenedAlice.snapshot()).revision, 3)

  const privateJwkSpec = identitySpec('invalid-jwk')
  privateJwkSpec.externalKeys.push({
    kid: '#external',
    role: 'e2ee_signing',
    material: {
      format: 'jwk',
      publicKeyJwk: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: '11qYAYLefK3DUy1zSvP1cptC7Zb7e7S9F9ZAR4c7D0k',
        d: 'must-be-rejected',
      },
    },
  })
  await assert.rejects(
    store.createIdentity(privateJwkSpec),
    (error) => error.code === 'invalid_public_key',
  )

  const publicJwkSpec = identitySpec('public-jwk')
  const { publicKey } = crypto.generateKeyPairSync('ed25519')
  const publicJwk = publicKey.export({ format: 'jwk' })
  publicJwkSpec.externalKeys.push({
    kid: '#external',
    role: 'e2ee_signing',
    material: {
      format: 'jwk',
      publicKeyJwk: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: publicJwk.x,
      },
    },
  })
  const publicJwkIdentity = await store.createIdentity(publicJwkSpec)
  const external = (await publicJwkIdentity.snapshot()).keys.find((key) =>
    key.kid.endsWith('#external'),
  )
  assert.equal(external.origin, 'external')

  assert.deepEqual(Object.keys(binding).sort(), ['DidIdentity', 'DidStore'])
  const serialized = JSON.stringify(rotated)
  assert.doesNotMatch(serialized, /private[_A-Z]?key|BEGIN PRIVATE KEY/i)
})

function identitySpec(name) {
  return {
    profile: 'e1',
    domain: 'example.com',
    pathSegments: ['agents', name],
    capabilities: { didWba: true },
    managedKeys: [
      { fragment: 'root', role: 'root_control' },
      { fragment: 'request', role: 'request_signing' },
      { fragment: 'e2ee-signing', role: 'e2ee_signing' },
      { fragment: 'agreement', role: 'e2ee_agreement' },
    ],
    externalKeys: [],
    services: [
      {
        id: 'message',
        serviceType: 'ANPMessageService',
        serviceEndpoint: 'https://example.com/im',
        profiles: ['anp.core.binding.v1'],
        securityProfiles: ['transport-protected'],
      },
    ],
    agentDescriptionUrl: 'https://example.com/agent.json',
    extensions: [
      {
        extensionType: 'device_manifest',
        deviceManifest: {
          devices: [
            {
              deviceId: 'device-1',
              signingKeyId: '#e2ee-signing',
              e2eeKeyId: '#agreement',
              profiles: ['anp.core.binding.v1'],
            },
          ],
        },
      },
    ],
  }
}
