import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const fixture = join(root, 'test', 'fixtures', 'public-api.d.ts')
const entries = ['index.d.ts', 'provider.d.ts', 'provider-api.d.ts', 'types.d.ts']
const sections = []
for (const entry of entries) {
  const value = (await readFile(join(root, 'lib', entry), 'utf8'))
    .replace(/^\/\/# sourceMappingURL=.*$/gmu, '')
    .trimEnd()
  sections.push(`// ===== ${entry} =====\n${value}`)
}
const generated = `${sections.join('\n\n')}\n`

if (process.argv.includes('--update')) {
  await mkdir(dirname(fixture), { recursive: true })
  await writeFile(fixture, generated, 'utf8')
  process.exit(0)
}

let expected
try {
  expected = await readFile(fixture, 'utf8')
} catch {
  throw new Error('public API fixture is missing; run npm run update:public')
}
if (generated !== expected) {
  throw new Error('public API changed; review the declarations and run npm run update:public')
}
