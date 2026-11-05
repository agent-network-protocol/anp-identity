/** Production B middleware/factors/SQL; only the independently held test-user control can confirm captured mail. */
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { join } from 'node:path'
import { readFile, readlink, stat } from 'node:fs/promises'

interface Pending { resolve(value: unknown): void; reject(error: Error): void; timer: ReturnType<typeof setTimeout> }
interface Reply { status: number; headers: Record<string, string>; body: string }

export async function strictBootstrapBridge(source: string, python: string, options: { publicationOrigin?: string } = {}) {
  const origin = options.publicationOrigin ?? 'https://identity.example'
  const localhost = /^https:\/\/localhost:([1-9][0-9]{0,4})$/u.exec(origin)
  if (origin !== 'https://identity.example' && origin !== 'https://agent.test:29443'
    && (!localhost || Number(localhost[1]) > 65535)) throw new Error('strict_bootstrap_publication_origin_not_allowed')
  const child = spawn(python, [join(source, 'tests/app/cimd/management_bridge.py')], {
    cwd: source, env: { ...process.env, PYTHONPATH: join(source, 'src'), CIMD_TEST_REAL_MANAGEMENT_BRIDGE: '1', CIMD_TEST_STRICT_BOOTSTRAP: '1', CIMD_TEST_PUBLICATION_ORIGIN: origin },
    stdio: ['pipe', 'pipe', 'pipe'],
  })
  const queue: Pending[] = []
  const facts: Array<{ method: string; path: string; rpc?: string; clientVersion: string | null;
    registrationOperationId?: string; webBootstrapProofPresent?: boolean }> = []
  const internalCredentials = new Set<string>()
  const observations = { deviceCredentialReceivedInternally: false, deviceAuthorizationRequests: 0 }
  const resources: Array<{ kind: 'mysql' | 'redis'; pid: number; root: string }> = []
  const cleanup = { complete: false, childExited: false, exitCode: null as number | null, resources }
  let stopped = false
  let ready!: (handle: string) => void
  let rejectReady!: (error: Error) => void
  const control = new Promise<string>((resolve, reject) => { ready = resolve; rejectReady = reject })
  void control.catch(() => {})
  const fail = () => {
    rejectReady(new Error('strict_bootstrap_bridge_unavailable'))
    for (const pending of queue.splice(0)) { clearTimeout(pending.timer); pending.reject(new Error('strict_bootstrap_bridge_unavailable')) }
  }
  child.stderr.resume()
  child.stdin.on('error', fail)
  const exited = new Promise<void>((resolve) => {
    child.once('error', () => { stopped = true; fail(); resolve() })
    child.once('exit', code => { stopped = true; cleanup.childExited = true; cleanup.exitCode = code; fail(); resolve() })
  })
  createInterface({ input: child.stdout }).on('line', line => {
    let value: { control?: { kind?: string; handle?: string }; error?: unknown }
    try { value = JSON.parse(line) } catch { fail(); return }
    if (value.control) {
      if (value.control.kind !== 'strict-identity-bootstrap-v1' || !value.control.handle) { fail(); return }
      ready(value.control.handle); return
    }
    const pending = queue.shift()
    if (!pending) return
    clearTimeout(pending.timer)
    if (value.error) pending.reject(new Error('strict_bootstrap_bridge_unavailable'))
    else pending.resolve(value)
  })
  const call = (command: unknown, timeout = 15000) => new Promise<unknown>((resolve, reject) => {
    if (stopped) { reject(new Error('strict_bootstrap_bridge_unavailable')); return }
    const timer = setTimeout(() => { fail(); child.kill('SIGTERM') }, timeout)
    queue.push({ resolve, reject, timer })
    child.stdin.write(JSON.stringify(command) + '\n', error => { if (error) fail() })
  })
  let disposal: Promise<void> | undefined
  const dispose = () => disposal ??= (async () => {
    if (!stopped) await call({ action: 'close' }, 30000).catch(() => {})
    child.stdin.end()
    const timer = setTimeout(() => child.kill('SIGKILL'), 10000)
    try { await exited } finally { clearTimeout(timer) }
    internalCredentials.clear()
    for (const resource of resources) {
      try { process.kill(resource.pid, 0); throw new Error('strict_bootstrap_child_cleanup_incomplete') }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error }
      try { await stat(resource.root); throw new Error('strict_bootstrap_root_cleanup_incomplete') }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error }
    }
    if (cleanup.exitCode !== 0) throw new Error('strict_bootstrap_bridge_exit_failed')
    cleanup.complete = true
  })()
  const timer = setTimeout(() => { fail(); child.kill('SIGTERM') }, 120000)
  let userControl: string
  try { userControl = await control } catch (error) { await dispose(); throw error } finally { clearTimeout(timer) }
  // Read only direct children of this exact owned bridge. No shared-process
  // lookup, arbitrary PID signaling or prefix cleanup is performed.
  try {
    const children = (await readFile(`/proc/${child.pid}/task/${child.pid}/children`, 'utf8')).trim().split(/\s+/u).filter(Boolean)
    for (const text of children) {
      const pid = Number(text)
      const command = await readFile(`/proc/${pid}/cmdline`, 'utf8')
      const mysql = /(?:^|\0)--datadir=(\/tmp\/cimd-mysql-[^\0/]+)\/data(?:\0|$)/u.exec(command)
      if (mysql) { resources.push({ kind: 'mysql', pid, root: mysql[1]! }); continue }
      const cwd = await readlink(`/proc/${pid}/cwd`)
      if (/(?:^|\/)redis-server(?:\0| )/u.test(command) && /^\/tmp\/cimd-redis-[^/]+$/u.test(cwd)) resources.push({ kind: 'redis', pid, root: cwd })
    }
    if (resources.length !== 2 || new Set(resources.map(value => value.kind)).size !== 2) throw new Error('strict_bootstrap_resource_observation_unavailable')
  } catch (error) { await dispose(); throw error }
  return {
    origin,
    facts,
    observations,
    cleanup,
    /** Public projections may be checked without exposing the internal device credential. */
    excludesInternalCredentials(value: unknown): boolean {
      const text = JSON.stringify(value)
      return [...internalCredentials].every(token => !text.includes(token))
    },
    fetch: (async (input, init) => {
      const request = new Request(input, init)
      if (new URL(request.url).origin !== new URL(origin).origin) throw new Error('strict_bootstrap_origin_mismatch')
      const body = request.body ? await request.text() : null
      const envelope = body && request.url.endsWith('/did-auth/rpc') ? JSON.parse(body) as { method?: string; params?: Record<string, unknown> } : undefined
      const rpc = envelope?.method
      const operation = rpc === 'register' ? envelope?.params?.registration_operation_id : undefined
      facts.push({ method: request.method, path: new URL(request.url).pathname, ...(rpc ? { rpc } : {}), clientVersion: request.headers.get('X-AWiki-Client-Version'),
        ...(typeof operation === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(operation)
          ? { registrationOperationId: operation, webBootstrapProofPresent: typeof envelope?.params?.bootstrap_proof === 'object' && envelope.params.bootstrap_proof !== null } : {}) })
      const reply = await call({ action: 'request', method: request.method, url: request.url, headers: Object.fromEntries(request.headers), body }) as Reply
      const authorization = request.headers.get('authorization')
      if (authorization?.startsWith('Bearer ') && internalCredentials.has(authorization.slice(7))) observations.deviceAuthorizationRequests++
      if (rpc === 'register') {
        const envelope = JSON.parse(reply.body) as { result?: { access_token?: unknown } }
        if (typeof envelope.result?.access_token === 'string') {
          internalCredentials.add(envelope.result.access_token)
          observations.deviceCredentialReceivedInternally = true
        }
      }
      return new Response(reply.body, { status: reply.status, headers: reply.headers })
    }) as typeof fetch,
    /** Test user only; this capability is never passed to C's production transport or configuration. */
    async confirmEmail(email: string, mode: 'valid' | 'invalid-email-token' = 'valid'): Promise<boolean> {
      return (await call({ action: 'confirm_email', control_handle: userControl, email, mode }) as { confirmed?: boolean }).confirmed === true
    },
    dispose,
  }
}
