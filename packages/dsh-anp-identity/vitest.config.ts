import { fileURLToPath } from "node:url";
import { join, resolve } from 'node:path';
import { readFileSync } from 'node:fs';
import { defineConfig } from "vitest/config";
import ts from 'typescript';

const upstreamRoot = process.env.DSH_CIMD_UPSTREAM_SOURCE;
const harnessAliases = upstreamRoot === undefined ? [] : Object.entries(
  ts.readConfigFile(join(upstreamRoot, 'tsconfig.base.json'), ts.sys.readFile).config.compilerOptions.paths as Record<string, string[]>,
).flatMap(([specifier, [path]]) => {
  if (!path || !specifier.startsWith('@deepseek-ai/') || specifier.includes('*') || !path.includes('/src')) return [];
  const packageRoot = resolve(upstreamRoot, path.slice(0, path.indexOf('/src')));
  const manifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8')) as {
    name: string; exports?: Record<string, string | { default?: string; import?: string }>; main?: string;
  };
  const key = specifier === manifest.name ? '.' : `.${specifier.slice(manifest.name.length)}`;
  const item = manifest.exports?.[key];
  const target = typeof item === 'string' ? item : item?.default ?? item?.import ?? (key === '.' ? manifest.main : undefined);
  if (!target) return [];
  return [{ find: new RegExp(`^${specifier.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')}$`), replacement: resolve(packageRoot, target) }];
});

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
    alias: [
      { find: '@agent-network-protocol/anp-identity/provider', replacement: fileURLToPath(new URL('../../bindings/node/provider.js', import.meta.url)) },
      { find: '@agent-network-protocol/anp-identity', replacement: fileURLToPath(new URL('../../bindings/node/index.js', import.meta.url)) },
      ...harnessAliases,
      ...(upstreamRoot === undefined ? [] : [{ find: '#cimd-upstream-wire',
        replacement: join(upstreamRoot, 'packages/mcp/mcp-client/lib/types/machine-http.js') }]),
    ],
  },
  test: {
    server: { deps: { inline: ['@deepseek-ai/dsh-client-ui-primitives'] } },
    include: ["test/**/*.spec.ts", "test/**/*.spec.tsx"],
    pool: "forks",
  },
});
