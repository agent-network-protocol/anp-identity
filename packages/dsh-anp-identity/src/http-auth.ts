import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import { pluginError } from './errors.js'
import type { AuthenticatedHttp, HttpTransport } from './types.js'

export const ANP_IDENTITY_HTTP_MAX_BODY_BYTES = 4 * 1024 * 1024
const CALLER_MANAGED_HEADERS = [
  'authorization',
  'signature-input',
  'signature',
  'content-digest',
] as const
const PROVIDER_PATCH_HEADERS = new Set(['signature-input', 'signature', 'content-digest'])

export function createAuthenticatedHttp(
  reference: IdentityReference,
  lease: ProviderLease,
  allowedOrigins: ReadonlySet<string>,
  assertActive: () => Promise<void>,
  requestSigningKid: () => Promise<string>,
): AuthenticatedHttp {
  return Object.freeze({
    async dispatch(request: Request, transport: HttpTransport): Promise<Response> {
      validateInput(request, transport, allowedOrigins)
      await assertActive()
      const body = await readReplayableBody(request)
      await assertActive()
      const kid = await requestSigningKid()
      await assertActive()
      const attempt = await lease.prepareHttpSignature({
        identity: reference,
        kid,
        url: request.url,
        method: request.method,
        headers: [...request.headers].map(([name, value]) => ({ name, value })),
        ...(body === undefined ? {} : { body: Buffer.from(body) }),
      })
      await assertActive()
      return transport(authenticatedRequest(request, body, attempt.headerPatch))
    },
  })
}

function validateInput(
  request: Request,
  transport: HttpTransport,
  allowedOrigins: ReadonlySet<string>,
): void {
  if (!(request instanceof Request) || typeof transport !== 'function' || request.bodyUsed) {
    throw pluginError('invalid_request')
  }
  let origin: string
  try {
    const url = new URL(request.url)
    if (url.protocol !== 'https:' || url.username !== '' || url.password !== '' || url.hash !== '') {
      throw pluginError('http_origin_forbidden')
    }
    origin = url.origin
  } catch (error) {
    if (isPluginError(error)) throw error
    throw pluginError('invalid_request')
  }
  if (!allowedOrigins.has(origin)) throw pluginError('http_origin_forbidden')
  for (const name of CALLER_MANAGED_HEADERS) {
    if (request.headers.has(name)) throw pluginError('invalid_request')
  }
}

async function readReplayableBody(request: Request): Promise<Uint8Array | undefined> {
  if (request.body === null) return undefined
  let clone: Request
  try {
    clone = request.clone()
  } catch {
    throw pluginError('http_body_unsupported')
  }
  const reader = clone.body?.getReader()
  if (reader === undefined) return new Uint8Array()
  const chunks: Uint8Array[] = []
  let length = 0
  try {
    while (true) {
      const result = await reader.read()
      if (result.done) break
      length += result.value.byteLength
      if (length > ANP_IDENTITY_HTTP_MAX_BODY_BYTES) {
        void reader.cancel().catch(() => {})
        void request.body?.cancel().catch(() => {})
        throw pluginError('http_body_too_large')
      }
      chunks.push(Uint8Array.from(result.value))
    }
  } catch (error) {
    if (isPluginError(error)) throw error
    throw pluginError('http_body_unsupported')
  } finally {
    reader.releaseLock()
  }
  const output = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    output.set(chunk, offset)
    offset += chunk.byteLength
  }
  return output
}

function authenticatedRequest(
  original: Request,
  body: Uint8Array | undefined,
  patch: readonly { readonly name: string; readonly value: string }[],
): Request {
  const headers = new Headers(original.headers)
  const seen = new Set<string>()
  for (const entry of patch) {
    const name = entry.name.toLowerCase()
    if (!PROVIDER_PATCH_HEADERS.has(name)
      || seen.has(name)
      || /[\r\n]/u.test(entry.name)
      || /[\r\n]/u.test(entry.value)) {
      throw pluginError('provider_incompatible')
    }
    seen.add(name)
    headers.set(name, entry.value)
  }
  if (!seen.has('signature-input') || !seen.has('signature')) {
    throw pluginError('provider_incompatible')
  }
  try {
    return new Request(original.url, {
      method: original.method,
      headers,
      redirect: 'manual',
      signal: original.signal,
      cache: original.cache,
      credentials: original.credentials,
      integrity: original.integrity,
      keepalive: original.keepalive,
      mode: original.mode,
      referrer: original.referrer,
      referrerPolicy: original.referrerPolicy,
      ...(body === undefined ? {} : { body: Uint8Array.from(body) }),
    })
  } catch {
    throw pluginError('invalid_request')
  }
}

function isPluginError(error: unknown): boolean {
  return typeof error === 'object' && error !== null && 'name' in error
    && error.name === 'AnpIdentityPluginError'
}
