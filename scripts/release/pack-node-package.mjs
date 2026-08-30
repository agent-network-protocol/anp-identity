import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..')

function fail(message) {
  throw new Error(message)
}

function argument(name) {
  const index = process.argv.indexOf(`--${name}`)
  if (index === -1 || !process.argv[index + 1]) fail(`missing --${name}`)
  return process.argv[index + 1]
}

async function sha256(path) {
  return createHash('sha256').update(await readFile(path)).digest('hex')
}

const packageRoot = resolve(repositoryRoot, argument('package-dir'))
const destination = resolve(repositoryRoot, argument('destination'))
await mkdir(destination, { recursive: true })
const result = spawnSync('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', destination], {
  cwd: packageRoot,
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
})
if (result.status !== 0) fail(result.error?.message || result.stderr || result.stdout)
const packed = JSON.parse(result.stdout)[0]
if (!packed?.filename || !Array.isArray(packed.files)) fail('npm pack returned no auditable file list')
const manifest = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'))
if (manifest.license !== 'Apache-2.0') fail('package must declare Apache-2.0')
if (manifest.publishConfig?.registry !== 'https://registry.npmjs.org') fail('package must publish to npmjs.org')
for (const hook of ['preinstall', 'install', 'postinstall']) {
  if (manifest.scripts?.[hook]) fail(`runtime install hook is forbidden: ${hook}`)
}
const paths = packed.files.map((file) => file.path).sort()
for (const required of [
  'LICENSE', 'NOTICE.md', 'README.md', 'SOURCE.md', 'checksums.json',
  'package.json', 'provenance.json', 'sbom.cdx.json',
]) {
  if (!paths.includes(required)) fail(`package is missing ${required}`)
}
for (const path of paths) {
  if (/(^|\/)(node_modules|scripts|src|test)(\/|$)/u.test(path)
    || path.endsWith('.rs') || (path.endsWith('.ts') && !path.endsWith('.d.ts'))) {
    fail(`source/build-only file leaked into package: ${path}`)
  }
}
const nativeFiles = paths.filter((path) => path.endsWith('.node'))
if (manifest.main?.endsWith('.node')) {
  if (nativeFiles.length !== 1 || nativeFiles[0] !== manifest.main.replace(/^\.\//u, '')) {
    fail('platform package must contain exactly its declared native addon')
  }
} else {
  if (nativeFiles.length !== 0) fail('root wrapper must not embed a native addon')
  for (const required of ['index.js', 'index.d.ts', 'provider.js', 'provider.d.ts', 'native.cjs']) {
    if (!paths.includes(required)) fail(`wrapper is missing ${required}`)
  }
  const versions = Object.values(manifest.optionalDependencies || {})
  if (versions.length !== 5 || versions.some((version) => version !== manifest.version)) {
    fail('wrapper must pin five platform packages to its exact version')
  }
}
const sbom = JSON.parse(await readFile(join(packageRoot, 'sbom.cdx.json'), 'utf8'))
if (sbom.bomFormat !== 'CycloneDX' || sbom.specVersion !== '1.6') fail('invalid SBOM')
const checksums = JSON.parse(await readFile(join(packageRoot, 'checksums.json'), 'utf8'))
for (const entry of checksums.files) {
  if (await sha256(join(packageRoot, entry.path)) !== entry.sha256) fail(`checksum mismatch: ${entry.path}`)
}
const tarball = join(destination, packed.filename)
const digest = await sha256(tarball)
await writeFile(`${tarball}.sha256`, `${digest}  ${basename(tarball)}\n`)
process.stdout.write(`${JSON.stringify({ name: manifest.name, tarball, sha256: digest })}\n`)
