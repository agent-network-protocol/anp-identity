import { copyFileSync, renameSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('..', import.meta.url))
renameSync(join(root, 'index.js'), join(root, 'native.cjs'))
renameSync(join(root, 'index.d.ts'), join(root, 'native.d.ts'))
copyFileSync(join(root, 'scripts', 'index.js.template'), join(root, 'index.js'))
copyFileSync(join(root, 'scripts', 'index.d.ts.template'), join(root, 'index.d.ts'))
