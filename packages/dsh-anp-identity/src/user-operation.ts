import { createHash } from 'node:crypto'
import type { SignRequest } from './types.js'
import type { ControlledOperation } from './authorization-types.js'
import type { UserOperation } from './user-client.js'
import { pluginError } from './errors.js'
import { ANP_IDENTITY_HTTP_MAX_BODY_BYTES } from './http-auth.js'

export async function normalizeOperation(operation: UserOperation): Promise<{
  readonly frozen: ControlledOperation
  readonly input: UserOperation
}> {
  if (operation?.action === 'read') return {
    frozen: fingerprint('identity:read', 'Read public identity', { action: 'read' }),
    input: { action: 'read' },
  }
  if (operation?.action === 'sign') {
    const original = operation.request
    if (!original || !Buffer.isBuffer(original.payload)
      || original.payload.length > ANP_IDENTITY_HTTP_MAX_BODY_BYTES
      || !['authentication', 'application_assertion'].includes(original.purpose)
      || (original.kid !== undefined && typeof original.kid !== 'string')
      || (original.purpose === 'application_assertion' && (typeof original.domain !== 'string' || !original.domain))) {
      throw pluginError('invalid_request')
    }
    const request: SignRequest = original.purpose === 'application_assertion'
      ? { purpose: original.purpose, domain: original.domain, payload: Buffer.from(original.payload), ...(original.kid === undefined ? {} : { kid: original.kid }) }
      : { purpose: 'authentication', payload: Buffer.from(original.payload), ...(original.kid === undefined ? {} : { kid: original.kid }) }
    return {
      frozen: { ...fingerprint('identity:sign', `Sign: ${request.purpose}`, {
        action: 'sign', purpose: request.purpose, kid: request.kid ?? null,
        domain: request.purpose === 'application_assertion' ? request.domain : null,
        payload: request.payload.toString('base64'),
      }), signingPurpose: request.purpose },
      input: { action: 'sign', request },
    }
  }
  if (operation?.action !== 'http' || !(operation.request instanceof Request) || operation.request.bodyUsed) {
    throw pluginError('invalid_request')
  }
  const original = operation.request
  const url = new URL(original.url)
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw pluginError('http_origin_forbidden')
  for (const header of ['authorization', 'signature', 'signature-input', 'content-digest']) {
    if (original.headers.has(header)) throw pluginError('invalid_request')
  }
  const clone = original.clone()
  const reader = clone.body?.getReader()
  let body: Uint8Array | undefined
  if (reader) {
    const chunks: Uint8Array[] = []
    let size = 0
    try {
      for (;;) {
        const result = await reader.read()
        if (result.done) break
        size += result.value.length
        if (size > ANP_IDENTITY_HTTP_MAX_BODY_BYTES) {
          void reader.cancel().catch(() => {})
          throw pluginError('http_body_too_large')
        }
        chunks.push(Uint8Array.from(result.value))
      }
      body = Buffer.concat(chunks)
    } finally { reader.releaseLock() }
  }
  const request = new Request(original.url, {
    method: original.method, headers: new Headers(original.headers), redirect: 'manual',
    signal: original.signal, credentials: original.credentials, cache: original.cache,
    mode: original.mode, referrer: original.referrer, referrerPolicy: original.referrerPolicy,
    integrity: original.integrity, keepalive: original.keepalive,
    ...(body === undefined ? {} : { body: Uint8Array.from(body) }),
  })
  return {
    frozen: { ...fingerprint('identity:http-auth', `${request.method} ${url.origin}${url.pathname}${url.href.includes('?') ? '（包含查询参数，内容未展示）' : ''}`, {
      action: 'http', url: request.url, method: request.method, headers: [...request.headers],
      body: body === undefined ? null : Buffer.from(body).toString('base64'),
      credentials: request.credentials, cache: request.cache, mode: request.mode,
      referrer: request.referrer, referrerPolicy: request.referrerPolicy,
      integrity: request.integrity, keepalive: request.keepalive,
    }), httpOrigin: url.origin },
    input: { action: 'http', request },
  }
}

function fingerprint(capability: ControlledOperation['capability'], summary: string, payload: unknown): ControlledOperation {
  return { capability, summary, fingerprint: createHash('sha256').update(JSON.stringify(payload)).digest('hex') }
}
