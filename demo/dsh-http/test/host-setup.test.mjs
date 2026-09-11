import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, cp, readFile, writeFile, mkdir, rm, realpath } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

async function isolated(t, files) {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'anp-demo-setup-test-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const file of files) await cp(new URL(`../${file}`, import.meta.url), join(root, file));
  return root;
}

test('profile setup installs only ordinary demo bundles and preserves an existing profile', async t => {
  const root = await isolated(t, ['prepare-host.mjs']);
  const run = () => execFileSync(process.execPath, [join(root, 'prepare-host.mjs')]);
  run();
  const path = join(root, 'runtime/dsh-home/profiles/anp-demo/package.json');
  const manifest = JSON.parse(await readFile(path, 'utf8'));
  assert.deepEqual(manifest.dsh.profile.bundles, [
    '@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app',
    '@agent-network-protocol/dsh-anp-identity', 'anp-http-demo',
  ]);
  assert.equal(manifest.dependencies['anp-http-demo'], `file:${join(root, 'plugin')}`);
  assert.equal(manifest.private, true);
  const edited = JSON.stringify({ ...manifest, custom: 'retain-user-changes' });
  await writeFile(path, edited);
  run();
  assert.equal(await readFile(path, 'utf8'), edited);
});

test('host startup overrides inherited identity authority and confines CA and profile to demo', { skip: process.platform === 'win32' }, async t => {
  const root = await isolated(t, ['run-host.mjs']);
  await mkdir(join(root, 'runtime'));
  await writeFile(join(root, 'runtime/config.json'), JSON.stringify({ origin: 'https://127.0.0.1:19444' }));
  const executable = join(root, 'fake-dsh');
  await writeFile(executable, `#!/usr/bin/env node
console.log(JSON.stringify({ args: process.argv.slice(2), home: process.env.DSH_HOME,
  consumers: process.env.DSH_ANP_IDENTITY_USER_CONSUMERS,
  provider: process.env.DSH_ANP_IDENTITY_ALLOW_PROVIDER_CONSUMERS,
  origins: process.env.DSH_ANP_IDENTITY_HTTP_ALLOWED_ORIGINS,
  state: process.env.DSH_ANP_IDENTITY_STATE_ROOT, ca: process.env.NODE_EXTRA_CA_CERTS }));
`, { mode: 0o700 });
  const env = { ...process.env, ANP_DEMO_DSH_BIN: executable, DSH_HOME: '/daily-profile',
    DSH_ANP_IDENTITY_ALLOW_PROVIDER_CONSUMERS: '["unexpected-provider"]', NODE_TLS_REJECT_UNAUTHORIZED: '1' };
  const result = JSON.parse(execFileSync(process.execPath, [join(root, 'run-host.mjs')], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  assert.deepEqual(result.args, ['--profile', 'anp-demo']);
  assert.equal(result.home, join(root, 'runtime/dsh-home'));
  assert.equal(result.state, join(root, 'runtime/identity-state'));
  assert.equal(result.ca, join(root, 'runtime/tls/ca.crt'));
  assert.equal(result.provider, '[]');
  assert.equal(result.consumers, '["anp-http-demo"]');
  assert.deepEqual(JSON.parse(result.origins), { 'anp-http-demo': ['https://127.0.0.1:19444'] });
  assert.throws(() => execFileSync(process.execPath, [join(root, 'run-host.mjs')], {
    env: { ...env, NODE_TLS_REJECT_UNAUTHORIZED: '0' }, stdio: 'pipe',
  }), error => error.status === 1 && error.stderr.toString().includes('TLS certificate verification must remain enabled'));
});
