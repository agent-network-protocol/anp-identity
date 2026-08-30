import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'

function fail(message) {
  throw new Error(message)
}

function argument(name) {
  const index = process.argv.indexOf(`--${name}`)
  if (index === -1 || !process.argv[index + 1]) fail(`missing --${name}`)
  return resolve(process.cwd(), process.argv[index + 1])
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 120_000, ...options })
  if (result.status !== 0) fail(result.error?.message || result.stderr || result.stdout)
  return result.stdout.trim()
}

async function verify(path) {
  const expected = (await readFile(`${path}.sha256`, 'utf8')).trim().split(/\s+/u)[0]
  const actual = createHash('sha256').update(await readFile(path)).digest('hex')
  if (actual !== expected) fail(`tarball checksum mismatch: ${path}`)
}

const wrapper = argument('wrapper')
const expectMissing = process.argv.includes('--expect-missing')
const platform = expectMissing ? undefined : argument('platform')
const workspace = await mkdtemp(join(tmpdir(), 'anp-identity-packed-'))
try {
  await verify(wrapper)
  if (platform) await verify(platform)
  run('npm', [
    'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false',
    wrapper, ...(platform ? [platform] : []),
  ], { cwd: workspace, env: { ...process.env, CARGO: 'unavailable', RUSTC: 'unavailable' } })
  const script = expectMissing
    ? `
      try { require('@agent-network-protocol/anp-identity'); throw new Error('expected missing addon') }
      catch (error) {
        if (!String(error.message).includes('Cannot find native binding')) throw error
      }
      console.log('packed-missing-ok')
    `
    : `
      const { IdentityManager } = require('@agent-network-protocol/anp-identity')
      const rootKey = Buffer.alloc(32, 23)
      const manager = await IdentityManager.initialize({
        stateRoot: ${JSON.stringify(join(workspace, 'state'))},
        rootKeyKind: 'injected', keyId: 'packed-smoke', rootKey,
      })
      if ((await manager.info()).identityCount !== 0) throw new Error('expected empty Store')
      if (!rootKey.every((byte) => byte === 0)) throw new Error('native boundary did not consume root key')
      console.log('packed-smoke-ok')
    `
  const output = run(process.execPath, ['-e', `(async () => { ${script} })().catch((error) => { console.error(error); process.exit(1) })`], { cwd: workspace })
  const expected = expectMissing ? 'packed-missing-ok' : 'packed-smoke-ok'
  if (output !== expected) fail(`unexpected smoke output: ${output}`)
  process.stdout.write(`${output}\n`)
} finally {
  await rm(workspace, { recursive: true, force: true })
}
