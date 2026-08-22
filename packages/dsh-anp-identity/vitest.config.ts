import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      '@agent-network-protocol/anp-identity/provider': fileURLToPath(
        new URL('../../bindings/node/provider.js', import.meta.url),
      ),
      '@agent-network-protocol/anp-identity': fileURLToPath(
        new URL('../../bindings/node/index.js', import.meta.url),
      ),
    },
  },
  test: {
    include: ['test/**/*.spec.ts'],
    pool: 'forks',
  },
})
