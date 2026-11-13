'use strict'
// Public Web bootstrap material for independently exercising the server validator.
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { IdentityProvider } = require('../bindings/node/provider')
function canonical(value) { if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'; if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}'; return JSON.stringify(value) }
async function main() {
  if (!process.argv[2]) throw new Error('an output path is required')
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'anp-web-bootstrap-vector-'))
  try {
    const provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'local_private_file' })
    const lease = provider.acquireLease({ consumer: 'web-bootstrap-vector', capabilities: ['IDENTITY_READ', 'IDENTITY_CREATE', 'IDENTITY_DOCUMENT_UPDATE'], ttlSeconds: 600 })
    const identity = await lease.create({ profile: 'web', domain: 'identity.example', pathSegments: ['awiki', 'web', '123e4567e89b42d3a456426614174000'], capabilities: { didWba: true }, managedKeys: [{ fragment: 'device', role: 'device_signing' }, { fragment: 'agreement', role: 'e2ee_agreement' }], extensions: [{ type: 'device_manifest', value: { devices: [{ deviceId: 'web-device', signingKeyId: '#device', e2eeKeyId: '#agreement', profiles: ['anp.core.binding.v1', 'anp.identity.discovery.v1'] }] } }] })
    const reference = identity.reference
    const business_projection = { contract: 'awiki.register.web.v1', audience: 'awiki-user-service', registration_operation_id: '576130a8-8331-4b32-8701-9a82626b559e', full_handle: 'fixture-user.identity.example', did: reference.did, bootstrap_device: { device_id: 'web-device', signing_key_id: `${reference.did}#device`, e2ee_key_id: `${reference.did}#agreement` }, document_hash: 'sha256:' + crypto.createHash('sha256').update(canonical(identity.document)).digest('base64url'), account: { phone: null, email: 'fixture-user@example.invalid' }, profile: { name: 'Fixture User', avatar: null, role: null, endpoint_url: null, description: null, is_public: false, is_agent: true }, invite_code_hash: null }
    const bootstrap_proof = await lease.signWebRegistrationProof(reference, { key: { kid: '#device' }, business_projection })
    const registration_request = { did_document: identity.document, handle: 'fixture-user', registration_operation_id: business_projection.registration_operation_id, phone: null, email: 'fixture-user@example.invalid', name: 'Fixture User', avatar: null, role: null, endpoint_url: null, description: null, is_public: false, is_agent: true, invite_code: null, bootstrap_proof }
    fs.writeFileSync(process.argv[2], JSON.stringify({ schema_version: 1, description: 'Public ANP Identity native Web bootstrap output; temporary Store removed.', fixed_now: bootstrap_proof.created_at, did_document: identity.document, business_projection, request_hash: crypto.createHash('sha256').update(canonical(business_projection)).digest('hex'), bootstrap_proof, registration_request }, null, 2) + '\n')
    lease.dispose()
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
}
main().catch(error => { process.stderr.write(`${error.code || 'vector_generation_failed'}\n`); process.exitCode = 1 })
