import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const path = fileURLToPath(new URL('./identity-operator.py', import.meta.url));
const code = 'import runpy,json,sys\nm=runpy.run_path(sys.argv[1])\ntry: m["validate"](json.load(sys.stdin))\nexcept (ValueError,TypeError,KeyError): sys.exit(2)';
const check = request => spawnSync('python3', ['-c', code, path], {
  input: JSON.stringify(request), encoding: 'utf8', timeout: 10000,
});
const runId = 'aabbccdd-eeee-ffff-aabb-ccddeeffaabb';
const scope = { action: 'cleanup', runId, handle: 'systestdwaabbccddeeeeffff',
  did: 'did:wba:awiki.me:awiki:user:owned:e1_test' };
test('identity cleanup requires the exact run-derived handle and an awiki.me DID', () => {
  assert.equal(check(scope).status, 0);
  for (const change of [{ handle: 'existing-user' }, { runId: 'not-a-run' },
    { did: 'did:wba:awiki.info:awiki:user:foreign' }, { did: 'did:wba:awiki.me.evil.test:foreign' },
    { account_ids: ['arbitrary-account'] }, { action: 'delete-all' }]) {
    const result = check({ ...scope, ...change });
    assert.equal(result.status, 2);
    assert.equal(result.stdout, '');
  }
});
test('identity preflight accepts no account or authentication selectors', () => {
  assert.equal(check({ action: 'preflight' }).status, 0);
  for (const extra of [{ phone: '+12025550123' }, { did: scope.did }, { handle: scope.handle }]) {
    assert.equal(check({ action: 'preflight', ...extra }).status, 2);
  }
});
