import { createServer } from 'node:https';
import { readFile, writeFile } from 'node:fs/promises';
import { timingSafeEqual } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DemoVerifier } from './verifier.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const config = JSON.parse(await readFile(join(root, 'runtime/config.json'), 'utf8'));
const verifier = new DemoVerifier(config.origin);
let last;
const server = createServer({ key: await readFile(join(root, 'runtime/tls/server.key')), cert: await readFile(join(root, 'runtime/tls/server.crt')) }, async (req, res) => {
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  const send = (status, result) => { res.writeHead(status); res.end(JSON.stringify(result)); };
  try {
    if (req.headers.host !== new URL(config.origin).host || req.headers.origin !== undefined) return send(403, { error: 'local_host_required' });
    if (req.method === 'GET' && req.url === '/health') return send(200, { ok: true, origin: config.origin });
    if (req.method !== 'POST') return send(404, { error: 'not_found' });
    const chunks = []; let length = 0;
    for await (const chunk of req) { length += chunk.length; if (length > 65536) throw new Error('body_too_large'); chunks.push(chunk); }
    const body = Buffer.concat(chunks);
    if (req.url === '/enroll' || req.url === '/checks') {
      const auth = req.headers['x-demo-control'];
      if (typeof auth !== 'string' || Buffer.byteLength(auth) !== Buffer.byteLength(config.control) || !timingSafeEqual(Buffer.from(auth), Buffer.from(config.control))) return send(403, { error: 'control_forbidden' });
      if (req.url === '/enroll') return send(200, verifier.enroll(JSON.parse(body.toString())));
      if (!last) return send(409, { error: 'no_signed_request' });
      const cases = [
        ['修改请求正文', { ...last, body: Buffer.from('{"message":"tampered"}') }, 'body_digest_mismatch'],
        ['修改请求签名', { ...last, headers: { ...last.headers, signature: last.headers.signature.replace(/^sig1=:(.)/, (_, char) => `sig1=:${char === 'A' ? 'B' : 'A'}`) } }, 'signature_invalid'],
        ['重放原始请求', last, 'replay_rejected'],
      ];
      const checks = cases.map(([name, request, expected]) => {
        try { verifier.verify(request); return { name, rejected: false, code: 'unexpected_success' }; }
        catch (error) { return { name, rejected: error.code === expected, code: error.code ?? 'check_failed' }; }
      });
      return send(200, { checks, allRejected: checks.every(item => item.rejected) });
    }
    if (req.url !== '/hello') return send(404, { error: 'not_found' });
    // Never trust a proxy-supplied URL or a DID supplied in the JSON payload.
    const request = { method: req.method, url: `${config.origin}/hello`, headers: { ...req.headers }, body };
    const verified = verifier.verify(request);
    last = request;
    const result = { ...verified, message: 'Hello! Your identity signature is valid.', receivedBody: body.toString(), receivedAt: new Date().toISOString(), trust: 'Local pinned DID document; not public domain resolution.' };
    await writeFile(join(root, 'runtime/last-verification.json'), JSON.stringify(result, null, 2));
    return send(200, result);
  } catch (error) { return send(401, { verified: false, error: error.code ?? 'invalid_request' }); }
});
server.requestTimeout = 10000; server.headersTimeout = 10000;
server.listen(new URL(config.origin).port, '127.0.0.1', () => console.log(`Demo verifier listening at ${config.origin}`));
process.on('SIGTERM', () => { server.closeAllConnections(); server.close(); });
