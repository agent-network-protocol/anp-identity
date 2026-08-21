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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-identity-node-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const rootKey = Buffer.alloc(32, 7)
  const store = await DidStore.initializeInjected(root, 'node-test', rootKey)
  assert.ok(rootKey.every((byte) => byte === 0), 'native boundary must overwrite the input Buffer')
  assert.deepEqual(Object.keys(store), [], 'the native store handle must remain private')
  assert.equal((await store.manifest()).provider.kind, 'injected')

  const invalidRootKey = Buffer.alloc(31, 9)
  await assert.rejects(
    DidStore.openInjected(root, 'node-test', invalidRootKey),
    (error) => error.code === 'invalid_root_key',
  )
  assert.ok(invalidRootKey.every((byte) => byte === 0))

  const missingKey = Buffer.alloc(32, 7)
  await assert.rejects(
    DidStore.openInjected(path.join(root, 'missing'), 'node-test', missingKey),
    (error) => error.code === 'store_not_found',
  )
  assert.ok(missingKey.every((byte) => byte === 0))

  const alice = await store.createIdentity(identitySpec('alice'))
  const bob = await store.createIdentity(identitySpec('bob'))
  const aliceSnapshot = await alice.snapshot()
  assert.equal(aliceSnapshot.state, 'active')
  assert.equal(aliceSnapshot.rootCapability, 'active')
  assert.match(aliceSnapshot.rootKeyFingerprint, /^sha256:/)
  assert.equal(aliceSnapshot.checkpoint.documentVersion, 1)
  assert.equal(aliceSnapshot.keys.length, 5)
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
    {
      nonce: 'node-challenge',
      created: 1700000000,
      expires: 1700000300,
      coveredComponents: ['@method', '@target-uri', 'content-digest'],
    },
  )
  assert.ok(httpHeaders.some((header) => header.name === 'Signature'))
  assert.match(
    httpHeaders.find((header) => header.name === 'Signature-Input').value,
    /nonce="node-challenge"/,
  )
  const wrappedRoot = await alice.exportWrappedRoot({
    targetDid: aliceSnapshot.did,
    senderDeviceId: 'device-1',
    recipientDeviceId: 'device-1',
    recipientAgreementKid: `${aliceSnapshot.did}#agreement`,
    recipientAgreementPublic: await alice.publicKeyBytes('#agreement'),
    rootKid: `${aliceSnapshot.did}#root`,
    ttlSeconds: 300,
  })
  assert.equal(wrappedRoot.type, 'anp.identity.root-transfer.wrapped')
  assert.equal(wrappedRoot.version, 1)
  assert.equal(await alice.importWrappedRoot(wrappedRoot), 'active')
  await store.reload()

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
  await alice.endRetirement('#request')
  await alice.deleteRevokedKey('#request')
  assert.equal(
    (await alice.snapshot()).keys.find((key) => key.kid.endsWith('#request')).materialErased,
    true,
  )
  await assert.rejects(
    alice.deleteRevokedKey('#request'),
    (error) => error.code === 'key_material_erased',
  )

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
  const publicJwkDid = (await publicJwkIdentity.snapshot()).did
  await store.deleteIdentityNamespace(publicJwkDid, await store.generation())
  await assert.rejects(
    store.openIdentity(publicJwkDid),
    (error) => error.code === 'identity_not_found',
  )

  assert.deepEqual(Object.keys(binding).sort(), ['DidIdentity', 'DidStore'])
  const serialized = JSON.stringify(rotated)
  assert.doesNotMatch(serialized, /private[_A-Z]?key|BEGIN PRIVATE KEY/i)
})

test('reload makes store and identity handles reusable after a conflict', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-identity-node-reload-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const envVar = `ANP_IDENTITY_NODE_ROOT_${process.pid}_${Date.now()}`
  process.env[envVar] = Buffer.alloc(32, 14).toString('base64url')
  t.after(() => delete process.env[envVar])

  const first = await DidStore.initializeEnv(root, 'node-env', envVar)
  const staleStore = await DidStore.openEnv(root, 'node-env', envVar)
  const current = await first.createIdentity(identitySpec('reload-current'))
  await assert.rejects(
    staleStore.createIdentity(identitySpec('reload-conflict')),
    (error) => error.code === 'conflict',
  )
  await staleStore.reload()
  await staleStore.createIdentity(identitySpec('reload-success'))
  assert.equal((await staleStore.listIdentities()).length, 2)

  const staleIdentity = await staleStore.openIdentity((await current.snapshot()).did)
  const prepared = await current.prepareUpdate({
    requestSigningRotation: { oldKid: '#request', newFragment: 'request-v2' },
  })
  await assert.rejects(
    staleIdentity.prepareUpdate({
      requestSigningRotation: { oldKid: '#request', newFragment: 'stale-request' },
    }),
    (error) => error.code === 'conflict',
  )
  await current.abortUpdate(prepared.revisionId)
  await staleIdentity.reload()
  const retried = await staleIdentity.prepareUpdate({
    requestSigningRotation: { oldKid: '#request', newFragment: 'reloaded-request' },
  })
  await staleIdentity.abortUpdate(retried.revisionId)
})

test('rootless enrollment adopts and revokes one exact device', async (t) => {
  const primaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-identity-node-primary-'))
  const secondaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-identity-node-secondary-'))
  t.after(() => fs.rmSync(primaryRoot, { recursive: true, force: true }))
  t.after(() => fs.rmSync(secondaryRoot, { recursive: true, force: true }))
  const primary = await DidStore.initializeInjected(primaryRoot, 'primary', Buffer.alloc(32, 31))
  const secondary = await DidStore.initializeInjected(
    secondaryRoot,
    'secondary',
    Buffer.alloc(32, 32),
  )
  const owner = await primary.createIdentity(identitySpec('enrollment-owner'))
  const initial = await owner.snapshot()
  const initialEvidence = {
    documentVersion: 1,
    registryVersion: 1,
    documentDigest: DidStore.canonicalDocumentDigest(initial.document),
  }
  const prepared = await secondary.prepareEnrollment({
    verifiedDocument: initial.document,
    evidence: initialEvidence,
    deviceId: 'device-secondary',
    deviceSigningFragment: 'device-secondary-sign',
    deviceE2eeFragment: 'device-secondary-e2ee',
    profiles: ['anp.core.binding.v1'],
    capabilities: { didWba: true },
  })
  const added = await owner.prepareUpdate({
    deviceMutations: [
      {
        operation: 'add',
        device: {
          deviceId: prepared.device_id,
          signingKey: {
            kid: prepared.device_signing_key.kid,
            publicKeyMultibase: prepared.device_signing_key.public_key_multibase,
          },
          e2eeKey: {
            kid: prepared.device_e2ee_key.kid,
            publicKeyMultibase: prepared.device_e2ee_key.public_key_multibase,
          },
          profiles: prepared.profiles,
        },
      },
    ],
  })
  await owner.beginPublication(added.revisionId)
  await owner.markPublished(added.revisionId)
  await owner.commitUpdate(added.revisionId)
  const secondaryIdentity = await secondary.openIdentity(prepared.did)
  assert.equal(
    await secondaryIdentity.adoptVerifiedDocument(added.candidateDocument, {
      documentVersion: 2,
      registryVersion: 2,
      documentDigest: DidStore.canonicalDocumentDigest(added.candidateDocument),
    }),
    'activated',
  )
  await secondaryIdentity.sign(
    prepared.device_signing_key.kid,
    Buffer.from('device assertion'),
  )

  const removed = await owner.prepareUpdate({
    deviceMutations: [{ operation: 'remove', deviceId: prepared.device_id }],
  })
  await owner.beginPublication(removed.revisionId)
  await owner.markPublished(removed.revisionId)
  await owner.commitUpdate(removed.revisionId)
  assert.equal(
    await secondaryIdentity.adoptVerifiedDocument(removed.candidateDocument, {
      documentVersion: 3,
      registryVersion: 3,
      documentDigest: DidStore.canonicalDocumentDigest(removed.candidateDocument),
    }),
    'revoked',
  )
  await assert.rejects(
    secondaryIdentity.sign(prepared.device_signing_key.kid, Buffer.from('revoked')),
    (error) => error.code === 'key_not_usable',
  )
})

function identitySpec(name) {
  return {
    profile: 'e1',
    domain: 'example.com',
    pathSegments: ['agents', name],
    capabilities: { didWba: true },
    managedKeys: [
      { fragment: 'root', role: 'root_control' },
      { fragment: 'device', role: 'device_signing' },
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
