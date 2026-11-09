/** Public-network HTTPS transport for explicitly enabled domain access. */
import { lookup } from 'node:dns/promises'
import { request } from 'node:https'
import { BlockList, isIP } from 'node:net'
import { Readable } from 'node:stream'

const denied = new BlockList()
for (const [address, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4]] as const) denied.addSubnet(address, prefix)
const globalV6 = new BlockList()
globalV6.addSubnet('2000::', 3, 'ipv6')
for (const [address, prefix] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]] as const) denied.addSubnet(address, prefix, 'ipv6')
export function isPublicDomainAddress(address: string): boolean {
  return isIP(address) === 4 ? !denied.check(address, 'ipv4')
    : isIP(address) === 6 && globalV6.check(address, 'ipv6') && !denied.check(address, 'ipv6')
}
/** Pin all public DNS answers before sending; no redirects, cookies, proxies or retry. */
export async function publicHttps(requestValue: Request, assertBeforeSend?: () => Promise<void>): Promise<Response> {
  const url = new URL(requestValue.url)
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || requestValue.headers.has('host')) throw new Error('unsafe_target')
  const signal = AbortSignal.any([requestValue.signal, AbortSignal.timeout(10000)])
  const addresses = await abortable(lookup(url.hostname.replace(/^\[|\]$/gu, ''), { all: true, verbatim: true }), signal)
  signal.throwIfAborted()
  if (!addresses.length || addresses.length > 32 || addresses.some(value => !isPublicDomainAddress(value.address))) throw new Error('unsafe_target')
  const selected = addresses[0]!
  const bytes = await requestValue.arrayBuffer()
  if (bytes.byteLength > 4 * 1024 * 1024) throw new Error('request_too_large')
  await assertBeforeSend?.()
  signal.throwIfAborted()
  return new Promise<Response>((resolve, reject) => {
    const outgoing = request(url, { method: requestValue.method, headers: Object.fromEntries(requestValue.headers), signal,
      agent: false, rejectUnauthorized: true, maxHeaderSize: 16384,
      lookup: (_host, options, callback) => {
        if (options.all) {
          // Node uses the array overload when automatic family selection is enabled.
          Reflect.apply(callback, undefined, [null, [selected]])
        } else callback(null, selected.address, selected.family)
      },
    }, incoming => {
      const headers = new Headers()
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (Array.isArray(value)) for (const item of value) headers.append(name, item)
        else if (value !== undefined) headers.set(name, value)
      }
      const status = incoming.statusCode ?? 500
      if ([204, 205, 304].includes(status) || requestValue.method === 'HEAD') { incoming.resume(); resolve(new Response(null, { status, headers })); return }
      resolve(new Response(Readable.toWeb(incoming) as ReadableStream<Uint8Array>, { status, headers }))
    })
    outgoing.on('error', () => reject(new Error('network_failure')))
    outgoing.end(Buffer.from(bytes))
  })
}

/** Bound DNS waits without leaving a rejected lookup promise unobserved. */
async function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const abort = () => { signal.removeEventListener('abort', abort); reject(signal.reason) }
    signal.addEventListener('abort', abort, {once:true})
    promise.then(value => { signal.removeEventListener('abort', abort); resolve(value) }, error => { signal.removeEventListener('abort', abort); reject(error) })
    if (signal.aborted) abort()
  })
}
