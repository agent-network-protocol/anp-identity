import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { readFile } from 'node:fs/promises';
import { Script } from 'node:vm';

const sdk = new URL('../../packages/dsh-anp-identity/', import.meta.url);
const require = createRequire(new URL('package.json', sdk));
const { build } = require('esbuild');
const local = path => fileURLToPath(new URL(path, import.meta.url));
await build({
  entryPoints: [local('plugin/src/index.ts'), local('plugin/src/remote.ts')],
  outdir: local('plugin/lib'), platform: 'node', format: 'esm', bundle: true,
  packages: 'external', target: 'node22',
  tsconfigRaw: { compilerOptions: { experimentalDecorators: false } },
});
await build({
  entryPoints: [local('plugin/src/client.tsx')], outfile: local('plugin/lib/client.js'),
  platform: 'browser', format: 'cjs', bundle: true,
  nodePaths: [fileURLToPath(new URL('node_modules', sdk))],
  external: ['react', 'react/jsx-runtime'], target: 'es2022',
  define: { 'process.env.NODE_ENV': '"production"' },
  banner: { js: 'window.__ModuleLoader__.load({ id: "anp-http-demo", factory: (require) => { var module = { exports: {} }; var exports = module.exports;' },
  footer: { js: 'return module.exports; } });' },
});
new Script(await readFile(local('plugin/lib/client.js'), 'utf8'));
console.log('Built the ordinary plugin and validated its browser wrapper');
