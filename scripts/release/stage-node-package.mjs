import { createHash } from 'node:crypto'
import { copyFile, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const stagingRoot = resolve(repositoryRoot, 'dist/node-release/staged')
const bindingRoot = join(repositoryRoot, 'bindings/node')
const localCandidate = process.argv.includes('--local-candidate')

function fail(message) {
  throw new Error(message)
}

function argument(name) {
  const index = process.argv.indexOf(`--${name}`)
  if (index === -1 || !process.argv[index + 1]) fail(`missing --${name}`)
  return process.argv[index + 1]
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
  if (result.status !== 0) fail(result.error?.message || result.stderr || result.stdout)
  return result.stdout.trim()
}

async function json(path) {
  return JSON.parse(await readFile(path, 'utf8'))
}

async function sha256(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex')
}

function sourceRevision() {
  const head = run('git', ['rev-parse', 'HEAD'])
  const requested = process.env.ANP_IDENTITY_SOURCE_SHA?.trim() || head
  if (!/^[a-f0-9]{40}$/iu.test(requested) || requested !== head) {
    fail('ANP_IDENTITY_SOURCE_SHA must match the checked-out commit')
  }
  return {
    commit: head,
    committedAt: run('git', ['show', '-s', '--format=%cI', head]),
    dirty: run('git', ['status', '--short']).length > 0,
  }
}

export function validateAnpResolution(metadata, anpVersion, candidate) {
  const packages = metadata.packages.filter((pkg) => pkg.name === 'anp')
  if (!anpVersion || packages.length !== 1 || packages[0].version !== anpVersion ||
      (candidate ? packages[0].source !== null :
        packages[0].source !== 'registry+https://github.com/rust-lang/crates.io-index')) {
    fail(candidate ? 'local candidate must resolve one exact local ANP source' :
      'release SBOM must resolve the exact published registry ANP')
  }
  return packages[0]
}

function sbom(manifest) {
  const registryManifest = process.env.ANP_IDENTITY_REGISTRY_MANIFEST?.trim()
  if (localCandidate && registryManifest) fail('local candidate cannot claim a registry build')
  if (!localCandidate && !registryManifest) fail('ANP_IDENTITY_REGISTRY_MANIFEST must identify the verified registry build')
  const buildManifest = localCandidate ? join(repositoryRoot, 'Cargo.toml') : resolve(registryManifest)
  const metadata = JSON.parse(run('cargo', ['metadata', '--manifest-path', buildManifest, '--format-version', '1', '--locked']))
  const sourceManifest = run('git', ['show', 'HEAD:Cargo.toml'])
  const anpVersion = sourceManifest.match(/^anp\s*=.*version\s*=\s*"=([^"]+)"/m)?.[1]
  const anp = validateAnpResolution(metadata, anpVersion, localCandidate)
  const resolution = localCandidate ? {
    mode: 'local-candidate',
    anp: {
      version: anp.version,
      commit: run('git', ['-C', dirname(anp.manifest_path), 'rev-parse', 'HEAD']),
      dirty: run('git', ['-C', dirname(anp.manifest_path), 'status', '--short']).length > 0,
    },
  } : { mode: 'registry', anp: { version: anp.version, source: anp.source } }
  const cargo = metadata.packages.map((pkg) => ({
    type: 'library',
    name: pkg.name,
    version: pkg.version,
    ...(pkg.license ? { licenses: [{ expression: pkg.license }] } : {}),
    ...(pkg.source?.startsWith('registry+')
      ? { purl: `pkg:cargo/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}` }
      : {}),
  }))
  const optional = Object.entries(manifest.optionalDependencies || {}).map(([name, version]) => ({
    type: 'library',
    name,
    version,
    purl: `pkg:npm/${encodeURIComponent(name)}@${encodeURIComponent(version)}`,
    scope: 'optional',
  }))
  return { resolution, document: {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: { component: { type: 'library', name: manifest.name, version: manifest.version } },
    components: [...cargo, ...optional].sort((left, right) =>
      `${left.name}@${left.version}`.localeCompare(`${right.name}@${right.version}`)),
  } }
}

async function writeMetadata(output, manifest, target, binary) {
  const source = sourceRevision()
  const bill = sbom(manifest)
  const provenance = {
    schemaVersion: 1,
    package: { name: manifest.name, version: manifest.version },
    target: target || 'platform-independent-wrapper',
    source: {
      repository: 'https://github.com/agent-network-protocol/anp-identity',
      ...source,
    },
    dependencyResolution: bill.resolution,
    ...(localCandidate ? { localCandidate: true, cargoLockSha256: await sha256(join(repositoryRoot, 'Cargo.lock')) } : {}),
    toolchain: { rustc: run('rustc', ['--version']), node: process.version },
    ...(binary ? { binarySha256: await sha256(binary) } : {}),
  }
  await copyFile(join(repositoryRoot, 'LICENSE'), join(output, 'LICENSE'))
  await writeFile(join(output, 'NOTICE.md'), '# Notices\n\nThird-party components are listed in sbom.cdx.json.\n')
  await writeFile(join(output, 'SOURCE.md'), `# Corresponding Source\n\nRepository: https://github.com/agent-network-protocol/anp-identity\nCommit: ${source.commit}\nTarget: ${target || 'platform-independent-wrapper'}\n`)
  await writeFile(join(output, 'provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`)
  await writeFile(join(output, 'sbom.cdx.json'), `${JSON.stringify(bill.document, null, 2)}\n`)
}

async function writeChecksums(output) {
  const files = []
  for (const entry of (await readdir(output, { withFileTypes: true }))
    .sort((left, right) => left.name.localeCompare(right.name))) {
    if (entry.isFile() && entry.name !== 'checksums.json') {
      files.push({ path: entry.name, sha256: await sha256(join(output, entry.name)) })
    }
  }
  await writeFile(join(output, 'checksums.json'), `${JSON.stringify({ schemaVersion: 1, files }, null, 2)}\n`)
}

async function stage() {
  const kind = argument('kind')
  if (!['platform', 'wrapper'].includes(kind)) fail('--kind must be platform or wrapper')
  const output = resolve(repositoryRoot, argument('output'))
  if (!isAbsolute(output) || !output.startsWith(`${stagingRoot}${sep}`)) {
    fail(`output must be a child of ${stagingRoot}`)
  }
  const packageRoot = kind === 'wrapper'
    ? bindingRoot
    : resolve(repositoryRoot, argument('package-dir'))
  const manifest = await json(join(packageRoot, 'package.json'))
  if (localCandidate) manifest.private = true
  await rm(output, { recursive: true, force: true })
  await mkdir(output, { recursive: true })
  await writeFile(join(output, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`)
  await copyFile(join(packageRoot, 'README.md'), join(output, 'README.md'))

  let target
  let binary
  if (kind === 'wrapper') {
    for (const file of ['index.js', 'index.d.ts', 'provider.js', 'provider.d.ts', 'native.cjs']) {
      await copyFile(join(bindingRoot, file), join(output, file))
    }
  } else {
    target = argument('target')
    binary = resolve(repositoryRoot, argument('binary'))
    if ((await stat(binary)).size === 0) fail('native addon is empty')
    if (basename(manifest.main) !== `anp-identity.${target}.node`) {
      fail(`platform package main does not match ${target}`)
    }
    await copyFile(binary, join(output, basename(manifest.main)))
  }
  await writeMetadata(output, manifest, target, binary)
  await writeChecksums(output)
  process.stdout.write(`${relative(repositoryRoot, output)}\n`)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await stage()
