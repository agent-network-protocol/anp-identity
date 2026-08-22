import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'))
const exported = Object.keys(packageJson.exports).sort()
const expected = ['.', './cordis.patch.yml', './package.json', './provider', './provider-api'].sort()
if (JSON.stringify(exported) !== JSON.stringify(expected)) {
  throw new Error(`unexpected package exports: ${exported.join(', ')}`)
}

const defaultDeclaration = await readFile(new URL('../lib/index.d.ts', import.meta.url), 'utf8')
for (const forbidden of [
  'ecdhSealed',
  'exportRootKeySealed',
  'prepareHttpSignature(',
  'headerPatch:',
  'SealedSecretEnvelope',
  'injectedRootKey',
]) {
  if (defaultDeclaration.includes(forbidden)) {
    throw new Error(`default declaration exposes Host-only material: ${forbidden}`)
  }
}
for (const required of ['acquireClient(', 'authenticatedHttp:', 'prepareDocumentChange(']) {
  const publicTypes = defaultDeclaration + await readFile(new URL('../lib/types.d.ts', import.meta.url), 'utf8')
  if (!publicTypes.includes(required)) throw new Error(`default declaration is missing ${required}`)
}

const providerDeclaration = await readFile(new URL('../lib/provider-api.d.ts', import.meta.url), 'utf8')
for (const required of ['ecdhSealed(', 'exportRootKeySealed(', 'prepareHttpSignature(']) {
  if (!providerDeclaration.includes(required)) throw new Error(`Host Provider declaration is missing ${required}`)
}

const source = await Promise.all([
  'src/index.ts',
  'src/types.ts',
  'src/http-auth.ts',
].map(path => readFile(new URL(`../${path}`, import.meta.url), 'utf8')))
for (const forbidden of ['TypertRemoteService', 'Remote(', 'registerTool', 'modelTool']) {
  if (source.some(value => value.includes(forbidden))) {
    throw new Error(`Host-only service gained a Browser, Remote, or model surface: ${forbidden}`)
  }
}
