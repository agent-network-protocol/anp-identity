import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, writeFile, chmod, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspect } from 'node:util';
import { loadTestFactor, IDENTITY_ORIGIN } from './config.mjs';

const phone = '+12025550123', code = '012345';
async function fixture(run) {
  const root = await mkdtemp(join(tmpdir(), 'dsh-factor-test-'));
  const path = join(root, 'factor.yaml');
  try { await run(path, root); } finally { await rm(root, { recursive: true }); }
}
const save = (path, source) => writeFile(path, source, { mode: 0o600 });
const yaml = 'service:\n  baseUrl: https://awiki.info\notp:\n  phone: "' + phone + '"\n  code: "' + code + '"\n';

test('protected factor reads only OTP and keeps awiki.me as the target', () => fixture(async path => {
  await save(path, yaml);
  const factor = await loadTestFactor({ path, environment: {} });
  assert.equal(factor.phone, phone); assert.equal(factor.code, code);
  assert.equal(IDENTITY_ORIGIN, 'https://awiki.me');
  assert.deepEqual(Object.keys(factor), []);
  assert.equal(JSON.stringify(factor), '{"configured":true}');
  assert.equal(inspect(factor), 'TestFactor(<redacted>)');
  assert.equal('service' in factor, false);
}));
test('protected factor requires a complete process override', () => fixture(async path => {
  await save(path, yaml);
  await assert.rejects(loadTestFactor({ path, environment: { AWIKI_E2E_OTP_PHONE: phone } }), { code: 'test_factor_override_incomplete' });
  const factor = await loadTestFactor({ path, environment: { AWIKI_E2E_OTP_PHONE: '+12025550124', AWIKI_E2E_OTP_CODE: '654321' } });
  assert.equal(factor.phone, '+12025550124'); assert.equal(factor.code, '654321');
}));
test('protected factor rejects public files and symlinks', () => fixture(async (path, root) => {
  await save(path, yaml); await chmod(path, 0o644);
  await assert.rejects(loadTestFactor({ path, environment: {} }), { code: 'test_factor_file_insecure' });
  await chmod(path, 0o600);
  const link = join(root, 'link.yaml'); await symlink(path, link);
  await assert.rejects(loadTestFactor({ path: link, environment: {} }), { code: 'test_factor_unavailable' });
}));
test('protected factor rejects malformed, duplicate and aliased YAML without echoing secrets', () => fixture(async path => {
  for (const source of [yaml + 'otp: {}\n', 'otp: [', 'otp: &otp\n  phone: "' + phone + '"\n  code: "' + code + '"\ncopy: *otp\n', 'otp:\n  phone: "' + phone + '"\n  code: wrong\n']) {
    await save(path, source);
    await assert.rejects(loadTestFactor({ path, environment: {} }), error => {
      assert.match(error.code, /^test_factor_/u); assert.equal(String(error).includes(phone), false); return true;
    });
  }
}));
test('protected dotenv parsing never evaluates shell code or loads service settings', () => fixture(async (_path, root) => {
  const path = join(root, 'factor.env');
  await save(path, 'DID_HOSTNAME=awiki.info\nDEV_OTP_PHONE="' + phone + '"\nDEV_OTP_CODE="' + code + '"\nUNRELATED=$(exit 99)\n');
  const factor = await loadTestFactor({ path, environment: {} });
  assert.equal(factor.phone, phone); assert.equal(factor.code, code);
  await save(path, 'DEV_OTP_PHONE="' + phone + '"\nDEV_OTP_PHONE="' + phone + '"\nDEV_OTP_CODE="' + code + '"\n');
  await assert.rejects(loadTestFactor({ path, environment: {} }), { code: 'test_factor_duplicate' });
}));
test('explicit missing factor file fails even with valid environment overrides', async () => {
  await assert.rejects(loadTestFactor({ path: '/does-not-exist/factor.yaml',
    environment: { AWIKI_E2E_OTP_PHONE: phone, AWIKI_E2E_OTP_CODE: code } }), { code: 'test_factor_unavailable' });
});
