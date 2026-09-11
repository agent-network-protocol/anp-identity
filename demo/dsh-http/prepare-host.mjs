import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// Prepare an isolated profile only. Installation and startup are explicit steps.
process.umask(0o077);
const profile = new URL('runtime/dsh-home/profiles/anp-demo/', import.meta.url);
await mkdir(profile, { recursive: true, mode: 0o700 });
const local = path => `file:${fileURLToPath(new URL(path, import.meta.url))}`;
const manifest = {
  name: 'anp-http-demo-profile', private: true, type: 'module',
  dependencies: {
    '@deepseek-ai/dsh-base': '0.1.5-rc.1',
    '@deepseek-ai/dsh-web-app': '0.1.5-rc.1',
    '@deepseek-ai/cordis': '4.0.2',
    '@agent-network-protocol/anp-identity': local('../../bindings/node'),
    '@agent-network-protocol/dsh-anp-identity': local('../../packages/dsh-anp-identity'),
    'anp-http-demo': local('plugin'),
  },
  dsh: { profile: { bundles: [
    '@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app',
    '@agent-network-protocol/dsh-anp-identity', 'anp-http-demo',
  ], patchReload: 'startup' } },
};
try {
  await writeFile(new URL('package.json', profile), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log('Created the isolated anp-demo profile');
} catch (error) {
  if (error.code !== 'EEXIST') throw error;
  console.log('Existing profile retained; no user configuration overwritten');
}
