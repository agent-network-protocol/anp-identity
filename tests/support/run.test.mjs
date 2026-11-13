import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const run = args => spawnSync(process.execPath, [fileURLToPath(new URL('./run-system.mjs', import.meta.url)), ...args],
  { encoding: 'utf8', timeout: 10000, env: { ...process.env, DSH_CLI: '/must-not-start-an-acceptance-host' } });

test('case listing is offline and names the actual requested scope', () => {
  const result = run(['--list', '--case', 'ID-S01']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /^ID-S01 /u);
  assert.equal(result.stdout.trim().split('\n').length, 1);
});
test('an unknown case fails before installing or starting a Host', () => {
  const result = run(['--case', 'UNKNOWN-S99']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /acceptance_unknown_case/u);
  assert.equal(result.stderr.includes('acceptance_dsh_cli_missing'), false);
});
test('full and focused scope cannot be silently combined', () => {
  const result = run(['--all', '--case', 'ID-S01']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /acceptance_conflicting_scope/u);
});
