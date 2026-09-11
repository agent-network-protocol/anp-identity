import { build } from "esbuild";

await build({
  entryPoints: ["src/client/index.ts"],
  outfile: "lib/client.js",
  bundle: true,
  platform: "browser",
  format: "cjs",
  target: "es2022",
  sourcemap: true,
  external: [
    "react",
    "react/jsx-runtime",
    "react-dom",
    "@deepseek-ai/cordis",
    "@deepseek-ai/dsh-client-ui-slots",
    "@deepseek-ai/dsh-client-ui-primitives",
  ],
  define: { "process.env.NODE_ENV": '"production"' },
  banner: {
    js: 'window.__ModuleLoader__.load({ id: "@agent-network-protocol/dsh-anp-identity", factory: (require) => { var module = { exports: {} }; var exports = module.exports;',
  },
  footer: { js: "return module.exports; } });" },
});
