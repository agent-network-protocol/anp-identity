'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')

const publicApi = require('..')
const providerApi = require('../provider')

test('Host-only provider enforces leases and returns secrets only as ciphertext', async (t) => {
  assert.equal('IdentityProvider' in publicApi, false)
  assert.deepEqual(Object.keys(providerApi), ['IdentityProvider'])

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-identity-node-provider-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const rootKey = Buffer.alloc(32, 41)
  const provider = await providerApi.IdentityProvider.initialize({
    stateRoot: root,
    rootKeyKind: 'injected',
    keyId: 'provider-test',
    rootKey,
  })
  assert.ok(rootKey.every((byte) => byte === 0))

  const lease = await provider.acquireLease({
    consumer: 'dsh-awiki',
    capabilities: [
      'IDENTITY_READ',
      'IDENTITY_CREATE',
      'IDENTITY_SIGN',
      'IDENTITY_ECDH_SEALED',
      'IDENTITY_DOCUMENT_UPDATE',
      'IDENTITY_DELETE',
      'IDENTITY_HTTP_SIGNATURE',
      'IDENTITY_IMPORT',
      'AWIKI_LEGACY_ROOT_TRANSFER_V1',
    ],
    ttlSeconds: 600,
  })
  const created = await lease.create(identitySpec('provider'))
  assert.equal((await lease.info()).identityCount, 1)
  assert.equal((await lease.recover()).identityCount, 1)
  assert.equal((await lease.list()).length, 1)
  assert.equal((await lease.publicIdentity(created.reference)).revision, 1)

  const signature = await lease.sign(created.reference, {
    purpose: 'authentication',
    kid: `${created.reference.did}#request`,
    payload: Buffer.from('provider-signature'),
  })
  assert.equal(signature.bytes.length, 64)
  assert.equal(
    await lease.verify(created.reference, {
      purpose: 'authentication',
      kid: signature.kid,
      payload: Buffer.from('provider-signature'),
      signature: signature.bytes,
    }),
    'valid',
  )
  const sourceStatus = await lease.hostStatus(created.reference)
  assert.equal(sourceStatus.rootCapability, 'active')
  assert.equal(sourceStatus.checkpoint.documentVersion, 1)

  const objectProof = await lease.signObjectProof(created.reference, {
    kid: `${created.reference.did}#device`,
    document: { id: 'urn:example:provider-object' },
    issuerDid: created.reference.did,
    created: '2026-08-23T00:00:00Z',
  })
  assert.ok(objectProof.proof)

  const now = Math.floor(Date.now() / 1000)
  const http = await lease.prepareHttpSignature({
    identity: created.reference,
    kid: `${created.reference.did}#request`,
    url: 'https://api.example.com/messages',
    method: 'POST',
    headers: [],
    body: Buffer.from('{"message":"hello"}'),
    nonce: 'provider-http',
    created: now,
    expires: now + 300,
    coveredComponents: ['@method', '@target-uri', 'content-digest'],
  })
  assert.match(http.bindingDigest, /^sha256:/)
  assert.ok(http.headerPatch.some((header) => header.name === 'Signature'))
  assert.match(
    await lease.prepareLegacyDidWba(created.reference, {
      kid: `${created.reference.did}#request`,
      serviceDomain: 'api.example.com',
      version: '1.1',
    }),
    /^DIDWba /,
  )

  const { publicKey } = crypto.generateKeyPairSync('x25519')
  const recipientPublic = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url')
  const ecdh = await lease.ecdhSealed({
    identity: created.reference,
    kid: `${created.reference.did}#agreement`,
    peerPublic: recipientPublic,
    recipientPublicKey: recipientPublic,
    requestId: 'provider-ecdh-1',
  })
  assert.equal(ecdh.envelope.protocol, 'anp-sealed-secret/1')
  assert.ok(ecdh.envelope.ciphertext.length > 32)
  assert.equal(ecdh.authorization.consumer, 'dsh-awiki')
  assert.equal(ecdh.authorization.capability, 'IDENTITY_ECDH_SEALED')
  assert.ok(Buffer.from(ecdh.aad, 'base64url').length > 0)
  assert.equal(Object.hasOwn(ecdh, 'sharedSecret'), false)

  await assert.rejects(
    lease.exportRootKeySealed({
      identity: created.reference,
      kid: `${created.reference.did}#root`,
      recipientPublicKey: recipientPublic,
      requestId: 'root-transfer-1',
      userPresenceConfirmed: false,
    }),
    (error) => error.code === 'capability_denied',
  )
  const rootEnvelope = await lease.exportRootKeySealed({
    identity: created.reference,
    kid: `${created.reference.did}#root`,
    recipientPublicKey: recipientPublic,
    requestId: 'root-transfer-1',
    userPresenceConfirmed: true,
  })
  assert.equal(rootEnvelope.envelope.protocol, 'anp-sealed-secret/1')
  assert.equal(rootEnvelope.authorization.capability, 'AWIKI_LEGACY_ROOT_TRANSFER_V1')
  assert.ok(Buffer.from(rootEnvelope.aad, 'base64url').length > 0)
  assert.equal(Object.hasOwn(rootEnvelope, 'rootKey'), false)

  const targetRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-identity-node-enrollment-'))
  t.after(() => fs.rmSync(targetRoot, { recursive: true, force: true }))
  const targetProvider = await providerApi.IdentityProvider.initialize({
    stateRoot: targetRoot,
    rootKeyKind: 'injected',
    keyId: 'enrollment-target',
    rootKey: Buffer.alloc(32, 42),
  })
  const targetLease = await targetProvider.acquireLease({
    consumer: 'dsh-awiki',
    capabilities: [
      'IDENTITY_READ',
      'IDENTITY_CREATE',
      'IDENTITY_SIGN',
      'IDENTITY_ECDH_SEALED',
      'IDENTITY_DOCUMENT_UPDATE',
    ],
    ttlSeconds: 600,
  })
  const enrollment = await targetLease.beginDeviceEnrollment({
    remote: {
      document: created.document,
      evidence: sourceStatus.checkpoint,
    },
    deviceId: 'joined-device',
    deviceSigningFragment: 'joined-signing',
    deviceAgreementFragment: 'joined-agreement',
    profiles: ['anp.core.binding.v1'],
    capabilities: { didWba: true },
  })
  const proposal = await enrollment.proposal()
  assert.equal(proposal.kind.kind, 'device')
  assert.equal((await enrollment.signDeviceAssertion(Buffer.from('join'))).length, 64)
  const enrollmentEcdh = await enrollment.deriveDeviceSharedSecretSealed({
    peerPublic: recipientPublic,
    recipientPublicKey: recipientPublic,
    requestId: 'enrollment-ecdh-1',
  })
  assert.equal(enrollmentEcdh.envelope.protocol, 'anp-sealed-secret/1')
  assert.equal(enrollmentEcdh.authorization.capability, 'IDENTITY_ECDH_SEALED')
  assert.ok(Buffer.from(enrollmentEcdh.aad, 'base64url').length > 0)
  assert.equal(Object.hasOwn(enrollmentEcdh, 'sharedSecret'), false)

  const change = await lease.prepareDocumentChange(created.reference, {
    changes: [
      {
        change: 'add_device',
        device: {
          deviceId: proposal.kind.deviceId,
          signingKey: proposal.kind.signingKey,
          agreementKey: proposal.kind.agreementKey,
          profiles: proposal.kind.profiles,
        },
      },
    ],
  })
  assert.equal(await change.hostPhase(), 'prepared')
  const candidate = await change.candidate()
  const attempt = await change.beginPublication()
  const changed = await change.complete(attempt, {
    result: 'confirmed',
    evidence: {
      documentVersion: 2,
      registryVersion: 2,
      documentDigest: candidate.candidateDigest,
    },
  })
  assert.equal(changed.outcome, 'committed')
  const acceptedCheckpoint = (await lease.hostStatus(created.reference)).checkpoint
  assert.equal(
    await enrollment.activate({
      document: candidate.candidateDocument,
      evidence: acceptedCheckpoint,
    }),
    'activated',
  )
  assert.equal((await targetLease.publicIdentity(proposal.identity)).state, 'active')
  assert.equal(
    await lease.adoptVerifiedDocument(created.reference, {
      document: candidate.candidateDocument,
      evidence: acceptedCheckpoint,
    }),
    'unchanged',
  )
  await targetLease.recoverIdentity(proposal.identity)

  const denied = await provider.acquireLease({
    consumer: 'viewer',
    capabilities: ['IDENTITY_READ'],
    ttlSeconds: 600,
  })
  await assert.rejects(
    denied.sign(created.reference, {
      purpose: 'authentication',
      payload: Buffer.from('denied'),
    }),
    (error) => error.code === 'capability_denied',
  )
  denied.dispose()
  await assert.rejects(denied.list(), (error) => error.code === 'provider_disposed')
})

function identitySpec(name) {
  return {
    profile: 'e1',
    domain: 'example.com',
    pathSegments: ['provider', name],
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
