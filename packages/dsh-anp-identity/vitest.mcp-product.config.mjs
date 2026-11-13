/** Use one real Host implementation for the source-only MCP component lane. */
import { fileURLToPath } from 'node:url'
import base from './vitest.config.ts'
const harness = process.env.DSH_MCP_PRODUCT_HARNESS_SOURCE
if (!harness) throw new Error('DSH_MCP_PRODUCT_HARNESS_SOURCE is required')
const vendor = [['cordis','cordis'],['cordis-plugin-loader','loader'],['cordis-plugin-include','include'],['cosmokit','cosmokit'],['schemastery','schemastery']].map(([name,dir]) => ({
  find: new RegExp('^@deepseek-ai/' + name + '$'),
  replacement: harness + '/vendor/' + dir + (dir === 'schemastery' ? '/lib/index.mjs' : '/lib/index.js'),
}))
export default { ...base, root: fileURLToPath(new URL('.', import.meta.url)),
  resolve: { ...base.resolve, alias: [...vendor, ...Object.entries(base.resolve.alias).map(([find,replacement]) => ({find,replacement}))] },
  test: { ...base.test, include: ['test/mcp-product-live.spec.ts'] },
}
