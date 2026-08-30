import { spawn } from 'node:child_process'
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDirectory = dirname(fileURLToPath(import.meta.url))
const packageRoot = resolve(scriptDirectory, '..')
const repositoryRoot = resolve(packageRoot, '../..')
const bindingRoot = join(repositoryRoot, 'bindings/node')
const releaseScript = join(repositoryRoot, 'scripts/release/stage-node-package.mjs')
const anpPythonRoot = resolve(repositoryRoot, '../anp')
const consumerRoot = join(packageRoot, 'test/functional/consumer')
const verifierScript = join(packageRoot, 'test/functional/http_verifier.py')

const temporaryRoot = await mkdtemp(join(tmpdir(), 'dsh-anp-http-functional-e2e-'))
const packRoot = join(temporaryRoot, 'packs')
const dshHome = join(temporaryRoot, 'dsh-home')
const stateRoot = join(temporaryRoot, 'identity-state')
const didDocumentPath = join(temporaryRoot, 'did-document.json')
const resultPath = join(temporaryRoot, 'result.json')
const readyPath = join(temporaryRoot, 'verifier-ready.json')
const certificatePath = join(temporaryRoot, 'localhost-cert.pem')
const privateKeyPath = join(temporaryRoot, 'localhost-key.pem')
const profileName = 'anp-http-functional-e2e'
let verifier

try {
  requireSupportedNode()
  await mkdir(packRoot, { recursive: true })
  await run('npm', ['--prefix', bindingRoot, 'run', 'build:debug'])
  const target = currentTarget()
  const wrapperStage = join(repositoryRoot, 'dist/node-release/staged/functional-wrapper')
  const platformStage = join(repositoryRoot, `dist/node-release/staged/functional-${target}`)
  await run('node', [
    releaseScript, '--kind', 'wrapper', '--output', wrapperStage,
  ])
  await run('node', [
    releaseScript,
    '--kind', 'platform',
    '--package-dir', join(bindingRoot, 'npm', target),
    '--target', target,
    '--binary', join(bindingRoot, `anp-identity.${target}.node`),
    '--output', platformStage,
  ])
  const nativeTarball = await pack(wrapperStage, packRoot)
  const platformTarball = await pack(platformStage, packRoot)
  const pluginTarball = await pack(packageRoot, packRoot)
  const consumerTarball = await pack(consumerRoot, packRoot)

  await run('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-keyout', privateKeyPath,
    '-out', certificatePath,
    '-days', '1',
    '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost',
  ], { quiet: true })

  verifier = spawn('uv', [
    'run', '--project', anpPythonRoot, 'python', verifierScript,
    '--certificate', certificatePath,
    '--private-key', privateKeyPath,
    '--document', didDocumentPath,
    '--ready-file', readyPath,
  ], { stdio: ['ignore', 'pipe', 'pipe'] })
  pipeWithPrefix(verifier.stdout, 'verifier:stdout')
  pipeWithPrefix(verifier.stderr, 'verifier:stderr')
  const { origin } = await waitForJson(readyPath, verifier, 10_000)

  const dshEnvironment = {
    ...process.env,
    DSH_HOME: dshHome,
    NODE_EXTRA_CA_CERTS: certificatePath,
    DSH_TELEMETRY_DISABLED: '1',
  }
  await run('dsh', [
    'plugin', '--profile', profileName, 'add', nativeTarball, platformTarball,
  ], { env: dshEnvironment })
  const profileRoot = join(dshHome, 'profiles', profileName)
  await writeFile(
    join(profileRoot, 'pnpm-workspace.yaml'),
    `overrides:\n  '@agent-network-protocol/anp-identity': file:${nativeTarball}\n`,
  )
  await run('dsh', [
    'plugin', '--profile', profileName, 'add', pluginTarball, consumerTarball,
  ], { env: dshEnvironment })

  const patchPath = join(profileRoot, 'cordis.patch.yml')
  await writeFile(patchPath, patch({
    stateRoot,
    origin,
    didDocumentPath,
    resultPath,
  }))

  await run('dsh', ['--profile', profileName], { env: dshEnvironment })
  const result = JSON.parse(await readFile(resultPath, 'utf8'))
  validateResult(result)
  process.stdout.write(`${JSON.stringify({
    status: 'passed',
    dsh: 'real-profile',
    installation: 'tarballs',
    https: true,
    getStatus: result.get.verified ? 200 : undefined,
    postStatus: result.post.verified ? 200 : undefined,
    tamperedPostStatus: result.tamperedPost.verified ? undefined : 401,
    tarballs: [nativeTarball, platformTarball, pluginTarball, consumerTarball]
      .map(value => value.split('/').at(-1)),
  }, null, 2)}\n`)
} finally {
  if (verifier !== undefined && verifier.exitCode === null) {
    verifier.kill('SIGTERM')
    await Promise.race([
      new Promise(resolveExit => verifier.once('exit', resolveExit)),
      new Promise(resolveTimeout => setTimeout(resolveTimeout, 2_000)),
    ])
  }
  await rm(temporaryRoot, { recursive: true, force: true })
}

async function pack(directory, destination) {
  const before = new Set(await readdir(destination))
  await run('npm', ['pack', '--pack-destination', destination], { cwd: directory })
  const after = await readdir(destination)
  const created = after.filter(value => value.endsWith('.tgz') && !before.has(value))
  if (created.length !== 1) {
    throw new Error(`npm pack in ${directory} created ${created.length} tarballs`)
  }
  return join(destination, created[0])
}

function patch(config) {
  const value = key => JSON.stringify(config[key])
  return `- insert:
    - id: anp-identity
      name: '@agent-network-protocol/dsh-anp-identity'
      config:
        stateRoot: ${value('stateRoot')}
        allowConsumers: [anp-http-functional-e2e]
        allowProviderConsumers: []
        httpAllowedOrigins:
          anp-http-functional-e2e: [${value('origin')}]
        recoveryOnOpen: true
    - id: anp-identity-provider
      name: '@agent-network-protocol/dsh-anp-identity/provider'
      config:
        stateRoot: ${value('stateRoot')}
        rootKeyProvider: local-file
        rootKeyProviderId: functional-e2e-local-file
        keyringFallbackToLocalFile: false
    - id: anp-identity-functional-e2e-consumer
      name: '@agent-network-protocol/dsh-anp-identity-functional-e2e-consumer'
      inject: [anpIdentity]
      config:
        verifierOrigin: ${value('origin')}
        didDocumentPath: ${value('didDocumentPath')}
        resultPath: ${value('resultPath')}
`
}

function validateResult(result) {
  if (result.get?.verified !== true || result.get?.method !== 'GET') {
    throw new Error('signed GET was not verified')
  }
  if (result.post?.verified !== true || result.post?.method !== 'POST'
    || result.post?.contentDigestPresent !== true) {
    throw new Error('signed POST did not verify with Content-Digest')
  }
  if (result.tamperedPost?.verified !== false
    || result.tamperedPost?.reason !== 'Content-Digest verification failed') {
    throw new Error('tampered POST was not rejected by Content-Digest verification')
  }
}

async function waitForJson(path, processHandle, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (processHandle.exitCode !== null) {
      throw new Error(`HTTPS verifier exited before becoming ready with code ${processHandle.exitCode}`)
    }
    try {
      return JSON.parse(await readFile(path, 'utf8'))
    } catch (error) {
      if (error?.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error
    }
    await new Promise(resolveWait => setTimeout(resolveWait, 50))
  }
  throw new Error('HTTPS verifier did not become ready')
}

function pipeWithPrefix(stream, prefix) {
  stream?.on('data', chunk => process.stderr.write(`${prefix}: ${chunk}`))
}

function requireSupportedNode() {
  const [major, minor] = process.versions.node.split('.').map(Number)
  if (!((major === 22 && minor >= 19) || major >= 24)) {
    throw new Error(`Node ${process.versions.node} is unsupported; use Node 22.19+ or 24+`)
  }
}

function currentTarget() {
  const target = new Map([
    ['darwin-arm64', 'darwin-arm64'],
    ['darwin-x64', 'darwin-x64'],
    ['linux-arm64', 'linux-arm64-gnu'],
    ['linux-x64', 'linux-x64-gnu'],
    ['win32-x64', 'win32-x64-msvc'],
  ]).get(`${process.platform}-${process.arch}`)
  if (target === undefined) {
    throw new Error(`unsupported functional E2E platform: ${process.platform}-${process.arch}`)
  }
  return target
}

function run(command, args, options = {}) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? repositoryRoot,
      env: options.env ?? process.env,
      stdio: options.quiet ? ['ignore', 'ignore', 'pipe'] : 'inherit',
    })
    let stderr = ''
    child.stderr?.on('data', chunk => { stderr += chunk })
    child.once('error', rejectRun)
    child.once('exit', (code, signal) => {
      if (code === 0) resolveRun()
      else rejectRun(new Error(`${command} exited with ${code ?? signal}${stderr === '' ? '' : `: ${stderr}`}`))
    })
  })
}
