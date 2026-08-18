import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
const actual = readFileSync(join(root, 'index.d.ts'), 'utf8')
const expected = readFileSync(join(root, 'test', 'fixtures', 'index.d.ts'), 'utf8')
if (actual !== expected) {
  throw new Error('index.d.ts differs from the reviewed snapshot')
}
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
