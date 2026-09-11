import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { request as httpsRequest } from 'node:https';
import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';
import { DemoVerifier } from '../server/verifier.mjs';
const require = createRequire(import.meta.url);
const { IdentityProvider } = require('../../../bindings/node/provider.js');
const config = JSON.parse(await readFile(new URL('../runtime/config.json', import.meta.url), 'utf8'));
const ca = await readFile(new URL('../runtime/tls/ca.crt', import.meta.url));
function post(path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(`${config.origin}${path}`, { ca, method: 'POST', headers: { 'content-type': 'application/json', ...headers } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(Buffer.concat(chunks).toString()) }));
    });
    req.setTimeout(15000, () => req.destroy(new Error('Demo HTTP request timed out')));
    req.on('error', reject); req.end(body);
  });
}
test('real native E1 signatures cross verified TLS and reject tampering/replay', async t => {
  const root = await mkdtemp(join(tmpdir(), 'anp-http-demo-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const provider = await IdentityProvider.initialize({ stateRoot: root, rootKeyKind: 'injected', keyId: 'demo-regression', rootKey: Buffer.alloc(32, 37) });
  const lease = await provider.acquireLease({ consumer: 'demo-test', capabilities: ['IDENTITY_CREATE', 'IDENTITY_READ', 'IDENTITY_HTTP_SIGNATURE'], ttlSeconds: 300 });
  t.after(() => lease.dispose());
  const identity = await lease.create({ profile: 'e1', domain: 'localhost', pathSegments: ['demo', randomUUID()], managedKeys: [{ fragment: 'root', role: 'root_control' }, { fragment: 'request', role: 'request_signing' }] });
  const enrollment = await post('/enroll', JSON.stringify(identity.document), { 'x-demo-control': config.control });
  assert.equal(enrollment.status, 200); assert.equal(enrollment.json.domainOwnershipVerified, false);
  const body = Buffer.from('{"message":"native HTTPS regression"}');
  const signed = await lease.prepareHttpSignature({ identity: identity.reference, kid: `${identity.reference.did}#request`, url: `${config.origin}/hello`, method: 'POST', headers: [], body });
  const headers = Object.fromEntries(signed.headerPatch.map(item => [item.name.toLowerCase(), item.value]));
  await t.test('actual signed HTTP returns independently verified 200', async () => {
    const result = await post('/hello', body, headers);
    assert.equal(result.status, 200); assert.equal(result.json.verified, true); assert.equal(result.json.did, identity.reference.did);
    assert.equal(result.json.receivedBody, body.toString()); assert.equal(result.json.checks.length, 7);
  });
  await t.test('changed body rejected', async () => {
    const result = await post('/hello', Buffer.from('tampered'), headers);
    assert.equal(result.status, 401); assert.equal(result.json.error, 'body_digest_mismatch');
  });
  await t.test('changed signature rejected', async () => {
    const signature = headers.signature.replace(/^sig1=:(.)/, (_, c) => `sig1=:${c === 'A' ? 'B' : 'A'}`);
    const result = await post('/hello', body, { ...headers, signature });
    assert.equal(result.status, 401); assert.equal(result.json.error, 'signature_invalid');
  });
  await t.test('exact wire request replay rejected', async () => {
    const result = await post('/hello', body, headers);
    assert.equal(result.status, 401); assert.equal(result.json.error, 'replay_rejected');
  });
  await t.test('missing signature rejected', async () => {
    const result = await post('/hello', body);
    assert.equal(result.status, 401); assert.equal(result.json.error, 'missing_signature');
  });
  await t.test('expired native signature rejected', async () => {
    const now = Math.floor(Date.now() / 1000);
    const stale = await lease.prepareHttpSignature({ identity: identity.reference, kid: `${identity.reference.did}#request`, url: `${config.origin}/hello`, method: 'POST', headers: [], body, created: now - 301, expires: now - 1 });
    const result = await post('/hello', body, Object.fromEntries(stale.headerPatch.map(item => [item.name, item.value])));
    assert.equal(result.status, 401); assert.equal(result.json.error, 'signature_expired');
  });
  await t.test('enrollment requires control token and rejects browser Origin', async () => {
    assert.equal((await post('/enroll', JSON.stringify(identity.document))).status, 403);
    assert.equal((await post('/enroll', JSON.stringify(identity.document), { 'x-demo-control': config.control, origin: 'https://evil.example' })).status, 403);
  });
  await t.test('public documents are pinned, not replaceable by an HTTP caller', () => {
    const verifier = new DemoVerifier(config.origin); verifier.enroll(identity.document);
    const changed = structuredClone(identity.document); changed.verificationMethod.find(m => m.id.endsWith('#request')).publicKeyMultibase = changed.verificationMethod.find(m => m.id.endsWith('#root')).publicKeyMultibase;
    assert.throws(() => verifier.enroll(changed), { code: 'document_already_pinned' });
    const request = { method: 'POST', url: `${config.origin}/hello`, headers, body };
    assert.throws(() => new DemoVerifier(config.origin).verify(request), { code: 'unknown_identity' });
    assert.throws(() => verifier.verify({ ...request, url: `${config.origin}/different` }), { code: 'unexpected_target' });
  });
});
