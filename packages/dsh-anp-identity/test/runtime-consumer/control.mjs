import { readFile } from 'node:fs/promises'

const [file, method, route, json] = process.argv.slice(2)
if (!file || !['GET', 'POST'].includes(method) || !route?.startsWith('/') || route.startsWith('//')) {
  throw new Error('Usage: node control.mjs CONTROL_FILE GET|POST /route [JSON]')
}
const control = JSON.parse(await readFile(file, 'utf8'))
if (control.schema !== 'anp-identity-runtime-control/1' || control.host !== '127.0.0.1'
  || !Number.isInteger(control.port) || control.port < 1 || control.port > 65535
  || typeof control.nonce !== 'string' || !/^[a-f0-9]{64}$/u.test(control.nonce)) throw new Error('Invalid local control descriptor')
const response = await fetch(`http://127.0.0.1:${control.port}${route}`, {
  method, redirect: 'error', signal: AbortSignal.timeout(15_000),
  headers: { 'X-Anp-Test-Control': control.nonce, ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) },
  ...(method === 'POST' ? { body: JSON.stringify(JSON.parse(json ?? '{}')) } : {}),
})
const value = await response.json()
process.stdout.write(`${JSON.stringify({ httpStatus: response.status, ...value }, null, 2)}\n`)
if (!response.ok) process.exitCode = 1
