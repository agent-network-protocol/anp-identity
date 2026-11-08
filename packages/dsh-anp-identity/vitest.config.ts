import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import ts from 'typescript';

export default defineConfig({
  plugins: [{
    name: 'identity-standard-decorators',
    enforce: 'pre',
    transform(code, id) {
      const file = id.split('?', 1)[0]!.replaceAll('\\', '/');
      if (!file.endsWith('/src/management-remote.ts')) return;
      const result = ts.transpileModule(code, { fileName: file, compilerOptions: {
        target: ts.ScriptTarget.ES2024, module: ts.ModuleKind.ESNext,
        experimentalDecorators: false, sourceMap: true, inlineSources: true,
      } });
      return { code: result.outputText, map: result.sourceMapText ?? null };
    },
  }],
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
