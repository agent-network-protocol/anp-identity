import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const declarations = [
  ['index.d.ts', join(root, 'scripts', 'index.d.ts.template')],
  ['native.d.ts', join(root, 'test', 'fixtures', 'native.d.ts')],
]
for (const [name, fixture] of declarations) {
  const actual = readFileSync(join(root, name), 'utf8')
  const expected = readFileSync(fixture, 'utf8')
  if (actual !== expected) {
    throw new Error(`${name} differs from the reviewed snapshot`)
  }
}
const actual = declarations
  .map(([name]) => readFileSync(join(root, name), 'utf8'))
  .join('\n')
for (const forbidden of [
  /private[_A-Z]?key/i,
  /private[_A-Z]?pem/i,
  /BEGIN PRIVATE KEY/i,
  /export.*secretbytes/i,
]) {
  if (forbidden.test(actual)) {
    throw new Error(`index.d.ts exposes forbidden private material: ${forbidden}`)
  }
}
