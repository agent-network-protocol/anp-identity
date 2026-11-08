'use strict'
// Produce public interoperability material; the temporary encrypted Store is removed.
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { IdentityProvider } = require('../bindings/node/provider')
async function main() {
  const output = process.argv[2]
  if (!output) throw new Error('an output path is required')
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-public-vector-'))
  try {
    const provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'local_private_file' })
    const lease = provider.acquireLease({ consumer: 'interop-vector', capabilities: ['IDENTITY_READ', 'IDENTITY_CREATE', 'IDENTITY_SIGN', 'IDENTITY_PAP_SESSION', 'IDENTITY_PAP_DPOP'], ttlSeconds: 600 })
    const identity = await lease.create({ profile: 'e1', domain: 'identity.example', pathSegments: ['public-vector'], capabilities: { didWba: true }, managedKeys: [{ fragment: 'root', role: 'root_control' }, { fragment: 'request', role: 'request_signing' }, { fragment: 'oauth', role: 'oauth_authentication' }] })
    const reference = identity.reference
    const client_id = 'https://identity.example/client.json'
    const scope = { owner: 'interop-vector', company_id: 'https://company.example', user_id: 'urn:example:user:pairwise', account_slot: 'account-vector' }
    const jwk = await lease.oauthPublicJwk(reference, '#oauth')
    const delegated = await lease.createDelegatedKey(reference, { operation_id: 'delegated-vector', scope })
    const delegation = await lease.issuePapDelegation(reference, { client_id, key: { kid: '#oauth' }, delegated_key: { handle: delegated.handle, generation: 1 }, scope, ttl_seconds: 300 })
    const session = await lease.signPapSessionRequest(reference, { handle: delegated.handle, generation: 1, scope, delegation, client_id, sid: 'session-vector', sub: scope.user_id, agent_id: 'urn:example:agent:pairwise', http_method: 'POST', http_uri: 'https://company.example/api/tools?ignored=value' })
    const dpopKey = await lease.createDpopKey(reference, { operation_id: 'dpop-vector', scope })
    const dpop = await lease.signDpopProof(reference, { handle: dpopKey.handle, generation: 1, scope, http_method: 'POST', http_uri: 'https://company.example/api/tools?ignored=value', access_token: 'public-test-token', nonce: 'public-test-nonce' })
    const assertion = await lease.signOAuthClientAssertion(reference, { client_id, audience: 'https://issuer.example', key: { kid: '#oauth' } })
    const claims = JSON.parse(Buffer.from(session.split('.')[1], 'base64url'))
    const vector = { schema_version: 1, description: 'Public, locally generated ANP Identity ES256/PAP/DPoP interoperability vector; no private material.', jwks: { keys: [jwk] }, did_document: identity.document, assertion, delegation, delegated_jwk: delegated.public_jwk, delegated_thumbprint: delegated.thumbprint, session, dpop, dpop_jwk: dpopKey.public_jwk, request: { company_id: scope.company_id, method: 'POST', target: 'https://company.example/api/tools?ignored=value', access_token: null, now: claims.iat }, assertion_request: { client_id, audience: 'https://issuer.example' }, dpop_request: { method: 'POST', target: 'https://company.example/api/tools?ignored=value', access_token: 'public-test-token', nonce: 'public-test-nonce' } }
    fs.writeFileSync(output, JSON.stringify(vector, null, 2) + '\n')
    lease.dispose()
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
}
main().catch(error => { process.stderr.write(`${error.code || 'vector_generation_failed'}\n`); process.exitCode = 1 })
