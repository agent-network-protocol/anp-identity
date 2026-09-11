import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const local = path => fileURLToPath(new URL(path, import.meta.url));
const config = JSON.parse(await readFile(local('runtime/config.json'), 'utf8'));
const env = {
  ...process.env,
  DSH_HOME: local('runtime/dsh-home'),
  DSH_TELEMETRY_DISABLED: '1',
  DSH_ANP_IDENTITY_STATE_ROOT: local('runtime/identity-state'),
  DSH_ANP_IDENTITY_ROOT_KEY_PROVIDER: 'local-file',
  DSH_ANP_IDENTITY_ROOT_KEY_PROVIDER_ID: 'anp-http-demo-local',
  DSH_ANP_IDENTITY_ALLOW_CONSUMERS: '["anp-http-demo"]',
  DSH_ANP_IDENTITY_USER_CONSUMERS: '["anp-http-demo"]',
  DSH_ANP_IDENTITY_ALLOW_PROVIDER_CONSUMERS: '[]',
  DSH_ANP_IDENTITY_HTTP_ALLOWED_ORIGINS: JSON.stringify({ 'anp-http-demo': [config.origin] }),
  ANP_HTTP_DEMO_CONFIG: local('runtime/config.json'),
  NODE_EXTRA_CA_CERTS: local('runtime/tls/ca.crt'),
};
if (env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new Error('TLS certificate verification must remain enabled');
const child = spawn(process.env.ANP_DEMO_DSH_BIN ?? 'dsh', ['--profile', 'anp-demo'], { env, stdio: 'inherit' });
child.on('error', error => { console.error(`Could not start DSH: ${error.code ?? 'startup_failed'}`); process.exitCode = 1; });
child.on('exit', code => { process.exitCode = code ?? 1; });
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
