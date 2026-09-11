import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@agent-network-protocol/anp-identity/provider": fileURLToPath(
        new URL("../../bindings/node/provider.js", import.meta.url),
      ),
      "@agent-network-protocol/anp-identity": fileURLToPath(
        new URL("../../bindings/node/index.js", import.meta.url),
      ),
    },
  },
  test: {
    server: { deps: { inline: ['@deepseek-ai/dsh-client-ui-primitives'] } },
    include: ["test/**/*.spec.ts", "test/**/*.spec.tsx"],
    pool: "forks",
  },
});
