'use strict'
const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const test = require('node:test')
const { IdentityProvider } = require('../provider')
const owner = 'local-signer-test-host'
const scope = { owner, company_id: 'https://company.example', user_id: 'pairwise-user', account_slot: 'account-one' }
const config = root => ({ stateRoot: root, rootKeyKind: 'injected', keyId: 'local-signer', rootKey: Buffer.alloc(32, 89) })
const capabilities = ['IDENTITY_READ', 'IDENTITY_CREATE', 'IDENTITY_SIGN', 'IDENTITY_DOCUMENT_UPDATE', 'IDENTITY_KEY_LIFECYCLE', 'IDENTITY_PAP_SESSION', 'IDENTITY_PAP_DPOP']
const spec = profile => ({ profile, domain: 'example.test', pathSegments: ['local-signer'], capabilities: { didWba: true }, managedKeys: [...(profile === 'e1' ? [{ fragment: 'root', role: 'root_control' }] : []), { fragment: 'device', role: 'device_signing' }, { fragment: 'request', role: 'request_signing' }, { fragment: 'oauth', role: 'oauth_authentication' }] })
function decode(token) { const [h, c, s] = token.split('.'); return { header: JSON.parse(Buffer.from(h, 'base64url')), claims: JSON.parse(Buffer.from(c, 'base64url')), signature: Buffer.from(s, 'base64url'), input: Buffer.from(`${h}.${c}`) } }
function verify(token, jwk) { const value = decode(token); assert.equal(value.signature.length, 64); assert.ok(crypto.verify('sha256', value.input, { key: crypto.createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, value.signature)); return value }
function canonical(value) { if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'; if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}'; return JSON.stringify(value) }
async function setup(t, profile = 'e1') { const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-signer-v2-')); t.after(() => fs.rmSync(root, { recursive: true, force: true })); const provider = await IdentityProvider.initialize(config(root)); const lease = provider.acquireLease({ consumer: owner, capabilities, ttlSeconds: 600 }); const identity = await lease.create(spec(profile)); return { root, provider, lease, reference: identity.reference } }

test('local v2 signer produces independently verified ES256 assertion, delegation, session and DPoP', async t => {
  const { root, lease, reference } = await setup(t)
  assert.equal((await lease.providerCapabilities()).api_version, 2)
  const jwk = await lease.oauthPublicJwk(reference, '#oauth')
  assert.deepEqual(Object.keys(jwk).sort(), ['alg', 'crv', 'kid', 'kty', 'use', 'x', 'y'])
  assert.equal(jwk.alg, 'ES256')
  const client_id = 'https://id.example/client.json'
  const assertion = await lease.signOAuthClientAssertion(reference, { client_id, audience: 'https://issuer.example', key: { kid: '#oauth' } })
  const { claims } = verify(assertion, jwk)
  assert.equal(claims.iss, client_id); assert.equal(claims.sub, client_id); assert.equal(claims.aud, 'https://issuer.example'); assert.equal(claims.exp - claims.iat, 60)
  const delegated = await lease.createDelegatedKey(reference, { operation_id: 'delegated-one', scope })
  assert.deepEqual(await lease.createDelegatedKey(reference, { operation_id: 'delegated-one', scope }), delegated)
  const thumbprint = crypto.createHash('sha256').update(canonical({ crv: 'P-256', kty: 'EC', x: delegated.public_jwk.x, y: delegated.public_jwk.y })).digest('base64url')
  assert.equal(delegated.thumbprint, thumbprint)
  const delegation = await lease.issuePapDelegation(reference, { client_id, key: { kid: '#oauth' }, delegated_key: { handle: delegated.handle, generation: delegated.generation }, scope, ttl_seconds: 300 })
  const d = verify(delegation, jwk)
  assert.equal(d.header.typ, 'poppy-delegation+jwt'); assert.deepEqual(Object.keys(d.claims).sort(), ['cnf', 'exp', 'iat', 'iss', 'jti']); assert.deepEqual(d.claims.cnf.jwk, delegated.public_jwk)
  const sessionRequest = { handle: delegated.handle, generation: 1, scope, delegation, client_id, sid: 'stable-session', sub: scope.user_id, agent_id: 'pairwise-agent', http_method: 'POST', http_uri: 'https://api.company.example/tools?x=one', access_token: 'exact-account-token' }
  const session = await lease.signPapSessionRequest(reference, sessionRequest)
  const s = verify(session, delegated.public_jwk)
  assert.equal(s.header.typ, 'poppy-session+jwt'); assert.equal(s.header.kid, thumbprint); assert.equal(s.header.poppy_dlg, delegation); assert.equal(s.claims.htu, 'https://api.company.example/tools'); assert.equal(s.claims.aud, scope.company_id); assert.equal(s.claims.sid, 'stable-session'); assert.equal(s.claims.ath, crypto.createHash('sha256').update('exact-account-token').digest('base64url')); assert.equal('exp' in s.claims, false)
  const dpop = await lease.createDpopKey(reference, { operation_id: 'dpop-one', scope })
  assert.notDeepEqual(dpop.public_jwk, delegated.public_jwk)
  const proof = await lease.signDpopProof(reference, { handle: dpop.handle, generation: 1, scope, http_method: 'GET', http_uri: 'https://api.company.example/tools?q=1', nonce: 'nonce-one', access_token: 'exact-account-token' })
  const p = verify(proof, dpop.public_jwk); assert.equal(p.header.typ, 'dpop+jwt'); assert.deepEqual(p.header.jwk, dpop.public_jwk); assert.equal(p.claims.nonce, 'nonce-one')
  await assert.rejects(lease.signDpopProof(reference, { handle: delegated.handle, generation: 1, scope, http_method: 'GET', http_uri: 'https://api.company.example/tools' }), { code: 'key_purpose_violation' })
  await assert.rejects(lease.signPapSessionRequest(reference, { ...sessionRequest, sub: 'other-user' }), { code: 'key_purpose_violation' })
  await assert.rejects(lease.signPapSessionRequest(reference, { ...sessionRequest, scope: { ...scope, company_id: 'https://other.example' } }), { code: 'key_purpose_violation' })
  await assert.rejects(lease.issuePapDelegation(reference, { client_id, key: { kid: '#oauth' }, delegated_key: delegated, scope, ttl_seconds: 300, aud: 'injected' }), { code: 'invalid_request' })
  const reopened = await IdentityProvider.open(config(root)); const resumed = reopened.acquireLease({ consumer: owner, capabilities, ttlSeconds: 600 })
  assert.deepEqual(await resumed.describeTemporaryKey(reference, { handle: delegated.handle, generation: 1, scope, purpose: 'pap_session' }), delegated)
  verify(await resumed.signPapSessionRequest(reference, sessionRequest), delegated.public_jwk)
  await resumed.retireTemporaryKey(reference, { handle: delegated.handle, generation: 1, scope })
  await assert.rejects(resumed.signPapSessionRequest(reference, sessionRequest), { code: 'key_unavailable' })
  const pending = resumed.signDpopProof(reference, { handle: dpop.handle, generation: 1, scope, http_method: 'GET', http_uri: 'https://api.company.example/tools' }); resumed.dispose(); await assert.rejects(pending)
})

test('P256 candidate enrollment commits through real native session for E1 and Web', async t => {
  for (const profile of ['e1', 'web']) {
    const { root, lease, reference } = await setup(t, profile)
    const request = { fragment: 'oauth-next', operation_id: 'oauth-enrollment-one', expected_revision: 1 }
    const session = await lease.prepareOAuthKeyChange(reference, request)
    const candidate = await session.candidate()
    assert.equal(candidate.baseEvidence.documentVersion, 1)
    assert.equal(candidate.baseEvidence.registryVersion, 1)
    assert.match(candidate.baseEvidence.documentDigest, /^sha256:[A-Za-z0-9_-]{43}$/u)
    assert.equal(candidate.operationId, request.operation_id)
    const method = candidate.candidateDocument.verificationMethod.find(key => key.id.endsWith('#oauth-next'))
    assert.equal(method.type, 'JsonWebKey2020'); assert.equal(method.publicKeyJwk.crv, 'P-256')
    const publicJwk = await lease.exportCandidateOAuthPublicJwk(reference, '#oauth-next')
    await assert.rejects(lease.oauthPublicJwk(reference, '#oauth-next'))
    const resumed = await lease.prepareOAuthKeyChange(reference, request); assert.deepEqual(await resumed.candidate(), candidate)
    const attempt = await session.beginPublication()
    await session.complete(attempt, { result: 'confirmed', evidence: { documentVersion: 2, registryVersion: 2, documentDigest: candidate.candidateDigest } })
    assert.deepEqual(await lease.oauthPublicJwk(reference, '#oauth-next'), publicJwk)
    assert.deepEqual((await session.candidate()).baseEvidence, candidate.baseEvidence)
    const reopened = await IdentityProvider.open(config(root)); const reloaded = reopened.acquireLease({ consumer: owner, capabilities, ttlSeconds: 600 }); assert.deepEqual(await reloaded.oauthPublicJwk(reference, '#oauth-next'), publicJwk)
  }
})

test('management device proof matches existing JCS transcript and caller lease is enforced', async t => {
  const { lease, provider, reference } = await setup(t)
  const params = { operation_id: 'prepare-one', http_path: '/user-service/v1/agent-clients/device/prepare', target_did: reference.did, publication: { schema_version: 2 } }
  const proof = await lease.signManagementProof(reference, { key: { kid: '#device' }, method: 'agent_client_prepare', params })
  const transcript = { type: proof.type, purpose: 'awiki.agent-client.prepare.v2', method: 'agent_client_prepare', key_id: proof.key_id, created_at: proof.created_at, expires_at: proof.expires_at, nonce: proof.nonce, params }
  const identity = await lease.publicIdentity(reference); const method = identity.document.verificationMethod.find(key => key.id === proof.key_id)
  // Existing Ed25519 Multikey public material is decoded only in this independent test.
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; let n = 0n; for (const ch of method.publicKeyMultibase.slice(1)) n = n * 58n + BigInt(alphabet.indexOf(ch)); let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex; const raw = Buffer.from(hex, 'hex').subarray(2)
  assert.ok(crypto.verify(null, Buffer.from(canonical(transcript)), crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' }), Buffer.from(proof.signature, 'base64url')))
  await assert.rejects(lease.signManagementProof(reference, { key: { kid: '#device' }, method: 'arbitrary', params }), { code: 'invalid_request' })
  const other = provider.acquireLease({ consumer: 'other-host', capabilities, ttlSeconds: 600 })
  await assert.rejects(other.createDelegatedKey(reference, { operation_id: 'other', scope }))
  const readOnly = provider.acquireLease({ consumer: owner, capabilities: ['IDENTITY_READ'], ttlSeconds: 600 })
  await assert.rejects(readOnly.createDpopKey(reference, { operation_id: 'read-only', scope }))
})

test('Web registration proof binds the complete local bootstrap projection', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-web-bootstrap-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const provider = await IdentityProvider.initialize(config(root))
  const lease = provider.acquireLease({ consumer: owner, capabilities, ttlSeconds: 600 })
  const identity = await lease.create({ profile: 'web', domain: 'identity.example', pathSegments: ['awiki', 'web', '123e4567e89b42d3a456426614174000'], capabilities: { didWba: true }, managedKeys: [{ fragment: 'device', role: 'device_signing' }, { fragment: 'agreement', role: 'e2ee_agreement' }], extensions: [{ type: 'device_manifest', value: { devices: [{ deviceId: 'web-device', signingKeyId: '#device', e2eeKeyId: '#agreement', profiles: ['anp.core.binding.v1'] }] } }] })
  const reference = identity.reference
  const projection = { contract: 'awiki.register.web.v1', audience: 'awiki-user-service', registration_operation_id: 'register-web-one', full_handle: 'user.identity.example', did: reference.did, bootstrap_device: { device_id: 'web-device', signing_key_id: `${reference.did}#device`, e2ee_key_id: `${reference.did}#agreement` }, document_hash: 'sha256:' + crypto.createHash('sha256').update(canonical(identity.document)).digest('base64url'), account: { phone: null, email: 'user@example.invalid' }, profile: { name: 'User', avatar: null, role: null, endpoint_url: null, description: null, is_public: false, is_agent: true }, invite_code_hash: null }
  const proof = await lease.signWebRegistrationProof(reference, { key: { kid: '#device' }, business_projection: projection })
  const transcript = { type: proof.type, purpose: 'awiki.identity.register.web.v1', method: 'register', audience: projection.audience, operation_id: projection.registration_operation_id, request_hash: crypto.createHash('sha256').update(canonical(projection)).digest('hex'), key_id: proof.key_id, created_at: proof.created_at, expires_at: proof.expires_at, nonce: proof.nonce }
  const method = identity.document.verificationMethod.find(key => key.id === proof.key_id)
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; let n = 0n; for (const ch of method.publicKeyMultibase.slice(1)) n = n * 58n + BigInt(alphabet.indexOf(ch)); let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex; const raw = Buffer.from(hex, 'hex').subarray(2)
  assert.ok(crypto.verify(null, Buffer.from(canonical(transcript)), crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' }), Buffer.from(proof.signature, 'base64url')))
  await assert.rejects(lease.signWebRegistrationProof(reference, { key: { kid: '#device' }, business_projection: { ...projection, document_hash: 'sha256:wrong' } }), { code: 'invalid_request' })
  await assert.rejects(lease.signWebRegistrationProof(reference, { key: { kid: '#device' }, business_projection: { ...projection, bootstrap_device: { ...projection.bootstrap_device, device_id: 'wrong' } } }), { code: 'key_purpose_violation' })
})
