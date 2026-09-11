import { createHash, createPublicKey, verify } from 'node:crypto';

export class VerificationError extends Error { constructor(code) { super(code); this.code = code; } }
const fail = code => { throw new VerificationError(code); };
const digest = body => `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
function publicKey(method) {
  const value = method?.publicKeyMultibase;
  if (typeof value !== 'string' || !/^z[1-9A-HJ-NP-Za-km-z]{40,60}$/.test(value)) fail('invalid_public_key');
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = 0n;
  for (const c of value.slice(1)) n = n * 58n + BigInt(alphabet.indexOf(c));
  let hex = n.toString(16); if (hex.length % 2) hex = `0${hex}`;
  const bytes = Buffer.from(hex, 'hex');
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 1) fail('invalid_public_key');
  return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), bytes.subarray(2)]), format: 'der', type: 'spki' });
}

/** A deliberately narrow verifier for the native E1 POST signature profile. */
export class DemoVerifier {
  documents = new Map();
  seen = new Map();
  constructor(origin) { this.origin = origin; }
  enroll(document) {
    if (!document || typeof document.id !== 'string' || !/^did:wba:localhost:demo:[A-Za-z0-9_-]+:e1_[A-Za-z0-9_-]+$/.test(document.id)) fail('invalid_demo_did');
    const methods = document.verificationMethod;
    if (!Array.isArray(methods) || methods.length !== 2 || !Array.isArray(document.authentication)) fail('invalid_document');
    const root = methods.find(m => m.id === `${document.id}#root`);
    const request = methods.find(m => m.id === `${document.id}#request`);
    if (root?.controller !== document.id || request?.controller !== document.id || !document.authentication.includes(request?.id)) fail('unauthorized_key');
    const jwk = publicKey(root).export({ format: 'jwk' });
    const fingerprint = createHash('sha256').update(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x })).digest('base64url');
    if (!document.id.endsWith(`:e1_${fingerprint}`)) fail('did_root_mismatch');
    const record = { document: structuredClone(document), key: publicKey(request), encoded: JSON.stringify(document) };
    const previous = this.documents.get(document.id);
    if (previous && previous.encoded !== record.encoded) fail('document_already_pinned');
    if (!previous && this.documents.size >= 100) fail('demo_registry_full');
    this.documents.set(document.id, record);
    return { did: document.id, registry: 'local-pinned-public-document', domainOwnershipVerified: false };
  }
  verify({ method, url, headers, body }, now = Math.floor(Date.now() / 1000)) {
    const input = headers['signature-input'];
    const signature = headers.signature;
    if (typeof input !== 'string' || typeof signature !== 'string') fail('missing_signature');
    // Reject unsupported components/parameters instead of attempting permissive parsing.
    const parsed = /^sig1=(\("@method" "@target-uri" "@authority" "content-digest"\);created=(\d+);expires=(\d+);nonce="([A-Za-z0-9_-]{16,128})";keyid="(did:wba:localhost:demo:[A-Za-z0-9_-]+:e1_[A-Za-z0-9_-]+#request)")$/.exec(input);
    const sig = /^sig1=:([A-Za-z0-9+/]{86}==):$/.exec(signature);
    if (!parsed || !sig) fail('invalid_signature_headers');
    const [, params, createdRaw, expiresRaw, nonce, kid] = parsed;
    const created = Number(createdRaw), expires = Number(expiresRaw);
    if (!Number.isSafeInteger(created) || !Number.isSafeInteger(expires) || created > now + 30 || created < now - 300 || expires < now || expires <= created || expires - created > 300) fail('signature_expired');
    if (method !== 'POST' || url !== `${this.origin}/hello`) fail('unexpected_target');
    const did = kid.slice(0, -'#request'.length);
    const pinned = this.documents.get(did);
    if (!pinned) fail('unknown_identity');
    if (headers['content-digest'] !== digest(body)) fail('body_digest_mismatch');
    const base = `"@method": ${method}\n"@target-uri": ${url}\n"@authority": ${new URL(url).host}\n"content-digest": ${headers['content-digest']}\n"@signature-params": ${params}`;
    if (!verify(null, Buffer.from(base), pinned.key, Buffer.from(sig[1], 'base64'))) fail('signature_invalid');
    for (const [key, expiry] of this.seen) if (expiry < now) this.seen.delete(key);
    const replay = `${kid}\n${nonce}`;
    if (this.seen.has(replay)) fail('replay_rejected');
    if (this.seen.size >= 1000) fail('demo_replay_cache_full');
    this.seen.set(replay, expires);
    return { verified: true, did, kid, algorithm: 'Ed25519', method, url, nonce, created, expires, checks: ['pinned public key', 'authorized request key', 'body SHA-256', 'method and URL', 'Ed25519 signature', 'timestamp', 'nonce replay protection'], signatureInput: input, signature, contentDigest: headers['content-digest'] };
  }
}
