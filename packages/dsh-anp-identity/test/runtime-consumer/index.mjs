import { createServer } from 'node:http'
import { createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto'
import { mkdir, open, readFile, rename, unlink } from 'node:fs/promises'
import { dirname, isAbsolute } from 'node:path'
import { bindIdentityClient } from '@agent-network-protocol/dsh-anp-identity/user-client'

export const name = 'anp-identity-runtime-consumer'
export const inject = ['anpIdentity']
const SCHEMA = 'anp-identity-runtime-control/1'
const PAYLOAD = Buffer.from('ANP Identity v7 local ordinary plugin acceptance\n', 'utf8')
const CREATE = Object.freeze({ label: 'Runtime acceptance identity', domain: 'example.com', path: '/anp-identity/runtime-acceptance' })

/** Test-only loopback control; all approvals still belong to the real DSH UI. */
export async function apply(ctx, config) {
  if (!config || typeof config.evidencePath !== 'string' || !isAbsolute(config.evidencePath)) throw new Error('An absolute isolated evidencePath is required')
  const evidencePath = config.evidencePath
  const nonce = randomBytes(32).toString('hex')
  const nonceBytes = Buffer.from(nonce)
  const leases = new Map()
  const documents = new Map()
  let client
  let disposed = false
  const ordinary = () => {
    if (disposed) throw new Error('Fixture is disposed')
    // Binding is lazy so the real Loader has finished publishing the installed fiber.
    return client ??= bindIdentityClient(ctx)
  }
  const resolved = {
    userClient: import.meta.resolve('@agent-network-protocol/dsh-anp-identity/user-client'),
    nativeProvider: import.meta.resolve('@agent-network-protocol/anp-identity/provider'),
  }
  const lease = async grantId => {
    const key = token(grantId)
    if (!leases.has(key)) leases.set(key, await ordinary().openAuthorizedIdentity(key))
    return leases.get(key)
  }
  const server = createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('Content-Type', 'application/json; charset=utf-8')
    response.setHeader('X-Content-Type-Options', 'nosniff')
    try {
      const supplied = request.headers['x-anp-test-control']
      if (request.headers.origin !== undefined || typeof supplied !== 'string'
        || Buffer.byteLength(supplied) !== nonceBytes.length || !timingSafeEqual(Buffer.from(supplied), nonceBytes)) {
        return send(response, 403, { ok: false, code: 'control_forbidden' })
      }
      if (request.headers.host !== `127.0.0.1:${server.address().port}`) return send(response, 403, { ok: false, code: 'host_forbidden' })
      const url = new URL(request.url, 'http://127.0.0.1')
      if (url.origin !== 'http://127.0.0.1') return send(response, 400, { ok: false, code: 'invalid_control_path' })
      const body = request.method === 'POST' ? await readJson(request) : undefined
      if (request.method === 'GET' && url.pathname === '/status') {
        ordinary()
        return send(response, 200, { ok: true, schema: SCHEMA, plugin: name, resolved, retainedLeaseCount: leases.size, cachedPublicDocumentCount: documents.size })
      }
      if (request.method === 'POST' && url.pathname === '/create') {
        only(body, ['requestId'])
        const result = await ordinary().requestCreateIdentity({ requestId: token(body.requestId), purpose: 'Create one identity for local runtime acceptance', parameters: CREATE })
        return send(response, 200, { ok: true, request: result })
      }
      if (request.method === 'POST' && ['/read-access', '/sign-access'].includes(url.pathname)) {
        only(body, ['requestId', 'reference'])
        const identity = reference(body.reference)
        const sign = url.pathname === '/sign-access'
        const operation = sign ? { action: 'sign', request: signing(identity) } : { action: 'read' }
        const result = await ordinary().requestAccess({ requestId: token(body.requestId), purpose: sign ? 'Sign the fixed runtime acceptance payload' : 'Read the identity public document for runtime acceptance', identity, operation })
        return send(response, 200, { ok: true, request: result })
      }
      if (request.method === 'GET' && url.pathname === '/request/create') {
        return send(response, 200, { ok: true, request: await ordinary().getCreateRequest(token(url.searchParams.get('id'))) })
      }
      if (request.method === 'GET' && url.pathname === '/request/access') {
        return send(response, 200, { ok: true, request: await ordinary().getAccessRequest(token(url.searchParams.get('id'))) })
      }
      if (request.method === 'POST' && url.pathname === '/executeRead') {
        only(body, ['grantId', 'executionId'])
        const result = await (await lease(body.grantId)).publicIdentity(token(body.executionId))
        documents.set(identityKey(result.reference), result.document)
        return send(response, 200, { ok: true, reference: result.reference, document: result.document, activeKeys: result.activeKeys })
      }
      if (request.method === 'POST' && url.pathname === '/executeSign') {
        only(body, ['grantId', 'executionId', 'reference'])
        const identity = reference(body.reference)
        const signature = await (await lease(body.grantId)).sign(signing(identity), token(body.executionId))
        const document = documents.get(identityKey(identity))
        const checked = document === undefined ? { verified: null, verification: 'public_document_not_read' }
          : { verified: verifySignature(document, signature), verification: 'node_crypto_ed25519' }
        return send(response, 200, { ok: true, ...checked, signatureBytes: signature.bytes.length, kid: signature.kid })
      }
      if (request.method === 'GET' && url.pathname === '/execution') {
        return send(response, 200, { ok: true, execution: await ordinary().getExecution(token(url.searchParams.get('id'))) })
      }
      return send(response, 404, { ok: false, code: 'unknown_control_route' })
    } catch (error) {
      // Do not return exception messages, stacks, control tokens or native internals.
      const code = typeof error?.code === 'string' && /^[a-z][a-z0-9_]{0,80}$/u.test(error.code) ? error.code : 'control_operation_failed'
      return send(response, 409, { ok: false, code })
    }
  })
  server.requestTimeout = 5000
  server.headersTimeout = 5000
  server.keepAliveTimeout = 1000
  const close = async () => {
    disposed = true
    leases.clear()
    documents.clear()
    server.closeAllConnections()
    await new Promise(resolve => server.close(() => resolve()))
    try {
      const current = JSON.parse(await readFile(evidencePath, 'utf8'))
      if (current.schema === SCHEMA && current.nonce === nonce) await unlink(evidencePath)
    } catch (error) { if (error?.code !== 'ENOENT') throw error }
  }
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve() })
    })
    const port = server.address().port
    await mkdir(dirname(evidencePath), { recursive: true, mode: 0o700 })
    try {
      const existing = JSON.parse(await readFile(evidencePath, 'utf8'))
      if (existing.schema !== SCHEMA || existing.plugin !== name) throw new Error('Refusing to overwrite unrelated evidence')
    } catch (error) { if (error?.code !== 'ENOENT') throw error }
    const temporary = `${evidencePath}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`
    const file = await open(temporary, 'wx', 0o600)
    try {
      await file.writeFile(JSON.stringify({ schema: SCHEMA, plugin: name, host: '127.0.0.1', port, nonce, resolved, status: 'listening', pid: process.pid }))
      await file.sync()
    } finally { await file.close() }
    await rename(temporary, evidencePath)
    ctx.effect(() => close, 'runtime acceptance: close ordinary consumer control')
  } catch (error) { await close(); throw error }
}

function send(response, status, value) {
  response.statusCode = status
  response.end(JSON.stringify(value))
}
async function readJson(request) {
  if (request.headers['content-type']?.split(';')[0] !== 'application/json') throw new Error('JSON content type required')
  const chunks = []
  let length = 0
  for await (const chunk of request) {
    length += chunk.length
    if (length > 16_384) throw new Error('Control body is too large')
    chunks.push(chunk)
  }
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8'))
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Control object required')
  return value
}
function only(value, keys) {
  if (Object.keys(value).some(key => !keys.includes(key))) throw new Error('Unknown control field')
}
function token(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/u.test(value)) throw new Error('Invalid public identifier')
  return value
}
function reference(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Identity reference required')
  only(value, ['storeId', 'identityId', 'did'])
  if (typeof value.did !== 'string' || !value.did.startsWith('did:wba:example.com:') || value.did.length > 4096) throw new Error('Fixture DID required')
  return { storeId: token(value.storeId), identityId: token(value.identityId), did: value.did }
}
function identityKey(value) { return JSON.stringify([value.storeId, value.identityId, value.did]) }
function signing(identity) { return { purpose: 'authentication', kid: `${identity.did}#request`, payload: Buffer.from(PAYLOAD) } }
function verifySignature(document, signature) {
  const method = document?.verificationMethod?.find(item => item.id === signature.kid)
  if (!method || signature.algorithm !== 'ed25519') return false
  let key
  if (method.publicKeyJwk?.kty === 'OKP' && method.publicKeyJwk.crv === 'Ed25519') {
    key = createPublicKey({ key: method.publicKeyJwk, format: 'jwk' })
  } else if (typeof method.publicKeyMultibase === 'string' && method.publicKeyMultibase.startsWith('z')) {
    const encoded = decodeBase58(method.publicKeyMultibase.slice(1))
    if (encoded.length !== 34 || encoded[0] !== 0xed || encoded[1] !== 1) return false
    key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), encoded.subarray(2)]), format: 'der', type: 'spki' })
  } else return false
  return verify(null, PAYLOAD, key, signature.bytes)
}
function decodeBase58(value) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let integer = 0n
  for (const character of value) {
    const digit = alphabet.indexOf(character)
    if (digit < 0) throw new Error('Invalid public multibase value')
    integer = integer * 58n + BigInt(digit)
  }
  let hex = integer.toString(16)
  if (hex.length % 2) hex = `0${hex}`
  const zeroes = value.match(/^1*/u)[0].length
  return Buffer.concat([Buffer.alloc(zeroes), integer === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex')])
}
