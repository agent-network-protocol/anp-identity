/** User Service transport. The Host supplies its existing authenticated management channel. */
import type { PublicationBackend, PreparedClientMaterials } from './publication-types.js'
import { pluginError } from './errors.js'

export function exactHttps(value: string, requirePath = false): string {
  if (typeof value !== 'string' || !value.startsWith('https://') || value.length > 2048 || /[\s\\\u0000-\u001f\u007f-\uffff]/u.test(value)
    || /%(?![a-f0-9]{2})/iu.test(value) || value.includes('?') || value.includes('#')) throw pluginError('invalid_request')
  let url: URL
  try { url = new URL(value) } catch { throw pluginError('invalid_request') }
  const authority = value.slice(8).split('/')[0]
  const path = value.slice(8).split('/').slice(1)
  if (!authority || authority.includes('@') || !url.hostname || (requirePath && !value.slice(8).includes('/'))
    || path.some(segment => ['.', '..'].includes(segment.replace(/%2e/giu, '.')))) throw pluginError('invalid_request')
  return value
}

export function createPublicationBackend(input: {
  origin: string
  /** Credentials stay inside this Host function; outgoing redirects must not be followed. */
  authenticatedFetch(request: Request): Promise<Response>
  publicFetch?: (request: Request) => Promise<Response>
  publishDocument: PublicationBackend['publishDocument']
}): PublicationBackend {
  const origin = exactHttps(input.origin)
  if (new URL(origin).origin !== origin) throw pluginError('invalid_request')
  const base = (id: string) => {
    if (!/^[A-Za-z0-9_-]{1,128}$/u.test(id)) throw pluginError('invalid_request')
    return `${origin}/user-service/v1/agent-clients/${id}`
  }
  const body = async (response: Response): Promise<string> => {
    if (response.status !== 200 || response.redirected
      || !(response.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) {
      await response.body?.cancel().catch(() => {})
      throw pluginError('provider_unavailable')
    }
    const reader = response.body?.getReader()
    const chunks: Uint8Array[] = []
    let length = 0
    try {
      while (reader) {
        const result = await reader.read()
        if (result.done) break
        length += result.value.byteLength
        if (length > 32768) throw pluginError('provider_incompatible')
        chunks.push(result.value)
      }
      return new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))
    } finally { await reader?.cancel().catch(() => {}); reader?.releaseLock() }
  }
  const command = async (id: string, action: string, value: unknown): Promise<PreparedClientMaterials> => {
    try {
    const response = await input.authenticatedFetch(new Request(`${base(id)}/${action}`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify(value), redirect: 'manual', signal: AbortSignal.timeout(15000),
    }))
    return parsePublicJson(await body(response)) as PreparedClientMaterials
    } catch { throw pluginError('provider_unavailable') }
  }
  return Object.freeze({
    origin, clientId: (id: string) => `${base(id)}/client.json`,
    prepare: (id, value) => command(id, 'prepare', value),
    activate: (id, operationId) => command(id, 'activate', { operation_id: operationId }),
    readPublic: async (id, part) => {
      try {
        return await body(await (input.publicFetch ?? fetch)(new Request(`${base(id)}/${part}`, {
          redirect: 'manual', signal: AbortSignal.timeout(15000),
        })))
      } catch { throw pluginError('provider_unavailable') }
    },
    publishDocument: input.publishDocument,
  } satisfies PublicationBackend)
}


/** Reject duplicate JSON members, including escaped aliases, before using metadata. */
export function parsePublicJson(text: string): unknown {
  if (text.length > 32768) throw pluginError('provider_incompatible')
  let result: unknown
  try { result = JSON.parse(text) } catch { throw pluginError('provider_incompatible') }
  let index = 0
  const whitespace = () => { while (/\s/u.test(text[index] ?? '') && index < text.length) index++ }
  const string = (): string => {
    const start = index++
    while (index < text.length) {
      const c = text[index++]
      if (c === '\\') index++
      else if (c === '"') return JSON.parse(text.slice(start, index)) as string
    }
    throw pluginError('provider_incompatible')
  }
  const visit = (depth: number): void => {
    if (depth > 32) throw pluginError('provider_incompatible')
    whitespace()
    if (text[index] === '{') {
      index++; whitespace()
      const keys = new Set<string>()
      while (text[index] !== '}') {
        const key = string()
        if (keys.has(key)) throw pluginError('provider_incompatible')
        keys.add(key); whitespace(); index++
        visit(depth + 1); whitespace()
        if (text[index] !== ',') break
        index++; whitespace()
      }
      index++
    } else if (text[index] === '[') {
      index++; whitespace()
      while (text[index] !== ']') {
        visit(depth + 1); whitespace()
        if (text[index] !== ',') break
        index++; whitespace()
      }
      index++
    } else if (text[index] === '"') string()
    else while (index < text.length && !/[\s,}\]]/u.test(text[index]!)) index++
  }
  visit(0)
  return result
}
