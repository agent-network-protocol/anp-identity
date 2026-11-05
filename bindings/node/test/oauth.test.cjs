'use strict'
const assert = require('node:assert/strict')
const { createPublicKey, verify } = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')
const { IdentityManager } = require('..')

// Node/OpenSSL independently verifies the Rust JOSE output.
test('OAuth assertions cross the native boundary with exact claims and active keys', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-oauth-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const config = () => ({ stateRoot: root, rootKeyKind: 'injected', keyId: 'oauth-test', rootKey: Buffer.alloc(32, 19) })
  const manager = await IdentityManager.initialize(config())
  const identity = await manager.create({
    profile: 'e1', domain: 'example.test', pathSegments: ['oauth'],
    capabilities: { didWba: true },
    managedKeys: [
      { fragment: 'root', role: 'root_control' },
      { fragment: 'request', role: 'request_signing' },
    ],
  })
  const request = { client_id: 'https://id.example:443/agents/one/client.json', audience: 'https://issuer.example/token', key: 'default' }
  const jwk = await identity.oauthPublicJwk()
  assert.deepEqual(Object.keys(jwk).sort(), ['alg', 'crv', 'kid', 'kty', 'use', 'x'])
  const token = await identity.signOAuthClientAssertion(request)
  const [header, payload, signature] = token.split('.')
  const claims = JSON.parse(Buffer.from(payload, 'base64url'))
  assert.equal(claims.iss, request.client_id)
  assert.equal(claims.sub, request.client_id)
  assert.equal(claims.aud, request.audience)
  assert.equal(claims.exp - claims.iat, 60)
  assert.equal(JSON.parse(Buffer.from(header, 'base64url')).kid, jwk.kid)
  const key = createPublicKey({ key: jwk, format: 'jwk' })
  assert.ok(verify(null, Buffer.from(`${header}.${payload}`), key, Buffer.from(signature, 'base64url')))
  assert.equal(verify(null, Buffer.from(`${header}.${payload}x`), key, Buffer.from(signature, 'base64url')), false)
  await assert.rejects(identity.signOAuthClientAssertion({ ...request, exp: 9999999999 }), { code: 'invalid_request' })
  await assert.rejects(identity.signOAuthClientAssertion({ ...request, audience: 'http://issuer.example' }), { code: 'invalid_request' })
  await assert.rejects(identity.oauthPublicJwk('#root'), { code: 'key_purpose_violation' })
  const reference = await identity.reference()
  const reopened = await IdentityManager.open(config())
  const sameIdentity = await reopened.get(reference)
  assert.deepEqual(await sameIdentity.oauthPublicJwk(), jwk)
  assert.notEqual(await sameIdentity.signOAuthClientAssertion(request), token)
  const change = await sameIdentity.prepareDocumentChange({ changes: [{ change: 'rotate_signing_key', oldKid: '#request', newFragment: 'request-v2' }] })
  const candidate = await change.candidate()
  const attempt = await change.beginPublication()
  await change.complete(attempt, { result: 'confirmed', evidence: { documentVersion: 2, registryVersion: 2, documentDigest: candidate.candidateDigest } })
  await assert.rejects(sameIdentity.oauthPublicJwk(jwk.kid))
  await assert.rejects(sameIdentity.signOAuthClientAssertion({ ...request, key: { kid: jwk.kid } }))
  assert.notEqual((await sameIdentity.oauthPublicJwk()).kid, jwk.kid)
  await assert.rejects(identity.oauthPublicJwk(), { code: 'conflict' })
  await assert.rejects(identity.signOAuthClientAssertion(request), { code: 'conflict' })
})


test('CIMD binding is prepared and committed through a signed document change', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-cimd-binding-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const manager = await IdentityManager.initialize({ stateRoot:root, rootKeyKind:'injected',keyId:'cimd',rootKey:Buffer.alloc(32,25) })
  const identity = await manager.create({profile:'e1',domain:'example.test',pathSegments:['cimd'],capabilities:{didWba:true},managedKeys:[{fragment:'root',role:'root_control'},{fragment:'request',role:'request_signing'}]})
  const jwk = await identity.oauthPublicJwk()
  const clientId = 'https://id.example/agent/client.json'
  const metadataSha256 = 'ab'.repeat(32)
  const session = await identity.prepareDocumentChange({changes:[{change:'bind_oauth_client',clientId,kid:jwk.kid,metadataSha256}]})
  const candidate = await session.candidate()
  const binding = candidate.candidateDocument.service.find(s => s.type === 'ANPCIMD')
  assert.equal(binding.serviceEndpoint,clientId)
  assert.deepEqual(binding.anp_oauth_keys,[jwk.kid])
  assert.equal(binding.anp_metadata_sha256,metadataSha256)
  assert.ok(candidate.candidateDocument.proof)
  const attempt = await session.beginPublication()
  await session.complete(attempt,{result:'confirmed',evidence:{documentVersion:2,registryVersion:2,documentDigest:candidate.candidateDigest}})
  assert.deepEqual((await identity.publicIdentity()).document.service.find(s => s.type==='ANPCIMD'),binding)
})


test('Host Provider OAuth methods enforce native lease capabilities and disposal', async (t) => {
  const { IdentityProvider } = require('../provider')
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-oauth-provider-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'injected', keyId: 'host-oauth', rootKey: Buffer.alloc(32, 23) })
  const admin = provider.acquireLease({ consumer:'test/host',capabilities:['IDENTITY_READ','IDENTITY_CREATE','IDENTITY_SIGN'],ttlSeconds:60 })
  const publicIdentity = await admin.create({ profile:'web',domain:'example.test',pathSegments:['oauth-host'],capabilities:{didWba:true},managedKeys:[{fragment:'request',role:'request_signing'}] })
  const reference = publicIdentity.reference
  const jwk = await admin.oauthPublicJwk(reference)
  const request = {client_id:'https://id.example/host/client.json',audience:'https://issuer.example',key:'default'}
  const token = await admin.signOAuthClientAssertion(reference, request)
  const [h,p,s] = token.split('.')
  assert.ok(verify(null,Buffer.from(`${h}.${p}`),createPublicKey({key:jwk,format:'jwk'}),Buffer.from(s,'base64url')))
  const readOnly = provider.acquireLease({ consumer:'test/reader',capabilities:['IDENTITY_READ'],ttlSeconds:60 })
  assert.deepEqual(await readOnly.oauthPublicJwk(reference),jwk)
  await assert.rejects(readOnly.signOAuthClientAssertion(reference,request))
  admin.dispose()
  await assert.rejects(admin.signOAuthClientAssertion(reference,request))
  readOnly.dispose()
})
