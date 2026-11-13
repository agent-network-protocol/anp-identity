import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, rm, stat, mkdir, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { withFactorLock } from './factor-lock.mjs';

async function fixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-factor-lock-test-'));
  try { await run(join(root, 'factor.lock')); } finally { await rm(root, { recursive: true }); }
}
test('factor lock excludes a concurrent runner and releases on success', () => fixture(async directory => {
  await withFactorLock(async () => {
    assert.equal((await stat(directory)).mode & 0o077, 0);
    await assert.rejects(withFactorLock(() => assert.fail('second holder entered'), { directory }),
      { code: 'acceptance_test_factor_busy' });
  }, { directory });
  await assert.rejects(stat(directory), { code: 'ENOENT' });
  await withFactorLock(async () => {}, { directory });
}));
test('factor lock releases after a failed test without hiding that failure', () => fixture(async directory => {
  const failure = new Error('owned-test-failure');
  await assert.rejects(withFactorLock(async () => { throw failure; }, { directory }), error => error === failure);
  await assert.rejects(stat(directory), { code: 'ENOENT' });
}));
test('preexisting lock state is preserved and never treated as proof of a live holder', () => fixture(async directory => {
  await mkdir(directory, { mode: 0o700 });
  const file = join(directory, 'owner.json');
  await writeFile(file, 'existing-state', { mode: 0o600 });
  await assert.rejects(withFactorLock(async () => assert.fail('entered'), { directory }), { code: 'acceptance_test_factor_busy' });
  assert.equal(await readFile(file, 'utf8'), 'existing-state');
}));
