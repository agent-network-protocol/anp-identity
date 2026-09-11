import { mkdir, writeFile, access } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.ANP_DEMO_PORT ?? 19443);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('ANP_DEMO_PORT must be an integer between 1024 and 65535');
const runtime = join(root, 'runtime'), tls = join(runtime, 'tls');
process.umask(0o077);
await mkdir(tls, { recursive: true, mode: 0o700 });
try { await access(join(runtime, 'config.json')); console.log('Existing isolated demo configuration retained'); }
catch (error) {
  if (error.code !== 'ENOENT') throw error;
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(tls, 'ca.key'), '-out', join(tls, 'ca.crt'), '-days', '7', '-subj', '/CN=ANP isolated demo CA', '-addext', 'basicConstraints=critical,CA:TRUE'], { stdio: 'ignore' });
  execFileSync('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(tls, 'server.key'), '-out', join(tls, 'server.csr'), '-subj', '/CN=127.0.0.1'], { stdio: 'ignore' });
  await writeFile(join(tls, 'server.ext'), 'subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
  execFileSync('openssl', ['x509', '-req', '-in', join(tls, 'server.csr'), '-CA', join(tls, 'ca.crt'), '-CAkey', join(tls, 'ca.key'), '-CAcreateserial', '-out', join(tls, 'server.crt'), '-days', '7', '-extfile', join(tls, 'server.ext')], { stdio: 'ignore' });
  await writeFile(join(runtime, 'config.json'), JSON.stringify({ origin: `https://127.0.0.1:${port}`, control: randomBytes(32).toString('hex') }), { mode: 0o600 });
  console.log('Created a 7-day task-local CA and server certificate; OS trust unchanged');
}
