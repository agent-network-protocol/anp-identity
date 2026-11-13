import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join, isAbsolute } from 'node:path';
import { AcceptanceError } from './config.mjs';

const digest = async path => createHash('sha256').update(await readFile(path)).digest('hex');
const manifest = async path => JSON.parse(await readFile(path, 'utf8'));

/** Bind installation evidence to the normal npm candidate and actual native platform package. */
export async function captureInstallation(profile, subject, subjectTarball) {
  const require = createRequire(join(profile, 'package.json'));
  const lock = await manifest(join(profile, 'package-lock.json'));
  const describe = async name => {
    const entry = require.resolve(name);
    const metadata = await manifest(join(profile, 'node_modules', name, 'package.json'));
    return { name, version: metadata.version, entry, entrySha256: await digest(entry),
      integrity: lock.packages['node_modules/' + name]?.integrity ?? null };
  };
  const nativeEntry = require.resolve('@agent-network-protocol/anp-identity');
  const nativeManifest = await manifest(join(dirname(nativeEntry), 'package.json'));
  const nativeRequire = createRequire(nativeEntry);
  const binaries = [];
  for (const name of Object.keys(nativeManifest.optionalDependencies ?? {})) {
    if (!name.includes('-' + process.platform + '-' + process.arch)) continue;
    try { binaries.push({ name, path: nativeRequire.resolve(name) }); }
    catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }
  }
  if (binaries.length !== 1 || !binaries[0].path.endsWith('.node'))
    throw new AcceptanceError('acceptance_native_platform_artifact_missing');
  const binary = binaries[0];
  const binaryManifest = await manifest(join(dirname(binary.path), 'package.json'));
  if (binaryManifest.version !== nativeManifest.version)
    throw new AcceptanceError('acceptance_native_platform_version_mismatch');
  return { platform: process.platform, arch: process.arch,
    subject: { ...await describe(subject),
      tarballSha256: isAbsolute(subjectTarball) ? await digest(subjectTarball) : null },
    identity: await describe('@agent-network-protocol/dsh-anp-identity'),
    native: { ...binary, version: binaryManifest.version, wrapperVersion: nativeManifest.version,
      sha256: await digest(binary.path), integrity: lock.packages['node_modules/' + binary.name]?.integrity ?? null } };
}
