import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { confirmedHandle } from '../plugin/src/created-identity.mjs';

const require = createRequire(new URL('../../../packages/dsh-anp-identity/package.json', import.meta.url));
const { build } = require('esbuild');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');
const output = await build({ entryPoints: [fileURLToPath(new URL('../plugin/src/identity-card.tsx', import.meta.url))], bundle: true, write: false, platform: 'node', format: 'cjs', external: ['react'] });
const module = { exports: {} };
new Function('require', 'module', 'exports', output.outputFiles[0].text)(require, module, module.exports);
const { IdentityCard } = module.exports;
const approved = { kind: 'create', status: 'approved', executionStatus: 'succeeded', parameters: { handle: 'plugin-selected.handle' }, result: { reference: { did: 'did:wba:localhost:demo:unrelated-id:e1_key' } } };

test('demo identity card displays the confirmed plugin Handle alongside the full DID and target', () => {
  const html = renderToStaticMarkup(React.createElement(IdentityCard, { handle: confirmedHandle(approved), identity: approved.result.reference.did, origin: 'https://127.0.0.1:19443' }));
  assert.match(html, /Handle/);
  assert.match(html, /plugin-selected\.handle/);
  assert.match(html, /DID/);
  assert.ok(html.includes(approved.result.reference.did));
  assert.ok(html.includes('https://127.0.0.1:19443'));
});

test('legacy missing Handle is explicit and unconfirmed creation cannot supply displayed identity metadata', () => {
  const handle = confirmedHandle({ ...approved, parameters: {} });
  assert.equal(handle, null);
  const html = renderToStaticMarkup(React.createElement(IdentityCard, { handle, identity: approved.result.reference.did, origin: 'https://127.0.0.1:19443' }));
  assert.match(html, /未提供/);
  assert.doesNotMatch(html, /demo-unrelated-id/);
  for (const status of ['pending', 'denied']) assert.throws(() => confirmedHandle({ ...approved, status }), /creation_result_unavailable/);
  assert.throws(() => confirmedHandle({ ...approved, executionStatus: 'unknown' }), /creation_result_unavailable/);
});
