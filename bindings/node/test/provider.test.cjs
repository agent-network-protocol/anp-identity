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
      'IDENTITY_HTTP_SIGNATURE',
      'IDENTITY_IMPORT',
      'AWIKI_LEGACY_ROOT_TRANSFER_V1',
    ],
    ttlSeconds: 600,
  })
  const created = await lease.create(identitySpec('provider'))
  assert.equal((await lease.list()).length, 1)
  assert.equal((await lease.publicIdentity(created.reference)).revision, 1)

  const signature = await lease.sign(created.reference, {
    purpose: 'authentication',
    kid: `${created.reference.did}#request`,
    payload: Buffer.from('provider-signature'),
  })
  assert.equal(signature.bytes.length, 64)

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

  const { publicKey } = crypto.generateKeyPairSync('x25519')
  const recipientPublic = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url')
  const ecdh = await lease.ecdhSealed({
    identity: created.reference,
    kid: `${created.reference.did}#agreement`,
    peerPublic: recipientPublic,
    recipientPublicKey: recipientPublic,
    requestId: 'provider-ecdh-1',
  })
  assert.equal(ecdh.protocol, 'anp-sealed-secret/1')
  assert.ok(ecdh.ciphertext.length > 32)
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
  assert.equal(rootEnvelope.protocol, 'anp-sealed-secret/1')
  assert.equal(Object.hasOwn(rootEnvelope, 'rootKey'), false)

  const adoption = await lease.prepareProviderAdoption({
    stateRoot: root,
    target: { kind: 'local_private_file' },
    requestId: 'adoption-1',
  })
  const offer = adoption.offer()
  assert.equal(offer.recipientPublicKey.length, 32)
  assert.match(offer.rootKeyFingerprint, /^[A-Za-z0-9_-]{43}$/)
  assert.equal(Object.hasOwn(offer, 'rootKey'), false)

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
