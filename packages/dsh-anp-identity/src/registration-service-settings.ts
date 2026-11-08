import { mkdir, lstat, readFile, open, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import lockfile from 'proper-lockfile';
import { z } from 'zod';
import { syncDirectory } from './sync-directory.js';
import { DEFAULT_REGISTRATION_ORIGIN, type RegistrationServiceSettings, type UpdateRegistrationServiceSettings } from './registration-service-types.js';

export function registrationOrigin(value: string): string {
  try {
    if (value.length > 2048) throw new Error();
    const url = new URL(value.trim());
    if (url.hostname.length > 253 || url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new Error();
    return url.origin;
  } catch { throw new Error('registration_service_invalid_origin'); }
}
const document = z.object({
  schema: z.literal(1), version: z.number().int().nonnegative(),
  origin: z.string().refine(value => { try { return registrationOrigin(value) === value; } catch { return false; } }),
  flows: z.record(z.string().regex(/^[a-f0-9]{64}$/u), z.object({
    fingerprint: z.string().regex(/^[a-f0-9]{64}$/u), origin: z.string(),
  }).strict()),
}).strict();
type Document = z.infer<typeof document>;
const initial = (): Document => ({ schema: 1, version: 0, origin: DEFAULT_REGISTRATION_ORIGIN, flows: {} });

/** Host-owned preferences and immutable per-flow origin pins, never credentials. */
export class RegistrationServiceSettingsStore {
  private readonly root: string;
  constructor(stateRoot: string) { this.root = join(stateRoot, 'manager-settings'); }
  private async transaction<T>(assertActive: () => void, operation: (state: Document) => { value: T; changed: boolean }): Promise<T> {
    assertActive();
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const info = await lstat(this.root);
    if (!info.isDirectory() || info.isSymbolicLink() || (process.platform !== 'win32' && Boolean(info.mode & 0o077)) ||
      typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('registration_service_settings_unavailable');
    const release = await lockfile.lock(this.root, { realpath: true, retries: { retries: 80, minTimeout: 10, maxTimeout: 100 } });
    try {
      assertActive();
      const path = join(this.root, 'registration.json');
      let state = initial();
      try {
        const stat = await lstat(path);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 131072 || (process.platform !== 'win32' && Boolean(stat.mode & 0o077)) ||
          typeof process.getuid === 'function' && stat.uid !== process.getuid()) throw new Error('registration_service_settings_unavailable');
        state = document.parse(JSON.parse(await readFile(path, 'utf8')));
        for (const pin of Object.values(state.flows)) if (registrationOrigin(pin.origin) !== pin.origin) throw new Error();
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('registration_service_settings_unavailable');
      }
      assertActive();
      const result = operation(state);
      if (result.changed) {
        state.version++;
        const temp = join(this.root, '.' + randomUUID() + '.tmp');
        try {
          const file = await open(temp, 'wx', 0o600);
          try { await file.writeFile(JSON.stringify(state) + '\n'); await file.sync(); } finally { await file.close(); }
          assertActive(); await rename(temp, path); await syncDirectory(this.root);
        } finally { await rm(temp, { force: true }); }
      }
      assertActive();
      return structuredClone(result.value);
    } finally { await release(); }
  }
  read(assertActive: () => void): Promise<RegistrationServiceSettings> {
    return this.transaction(assertActive, state => ({ value: { origin: state.origin, version: state.version }, changed: false }));
  }
  update(input: UpdateRegistrationServiceSettings, assertActive: () => void): Promise<RegistrationServiceSettings> {
    const origin = registrationOrigin(input.origin);
    if (!Number.isSafeInteger(input.expectedVersion) || input.expectedVersion < 0) throw new Error('registration_service_invalid_version');
    return this.transaction(assertActive, state => {
      if (state.version !== input.expectedVersion) throw new Error('registration_service_conflict');
      state.origin = origin;
      return { value: { origin, version: state.version + 1 }, changed: true };
    });
  }
  pin(key: string, fingerprint: string, assertActive: () => void): Promise<string> {
    if (![key, fingerprint].every(value => /^[a-f0-9]{64}$/u.test(value))) throw new Error('registration_service_invalid_flow');
    return this.transaction(assertActive, state => {
      const pin = state.flows[key];
      if (pin) {
        if (pin.fingerprint !== fingerprint) throw new Error('registration_service_flow_conflict');
        return { value: pin.origin, changed: false };
      }
      if (Object.keys(state.flows).length >= 256) throw new Error('registration_service_settings_unavailable');
      state.flows[key] = { origin: state.origin, fingerprint };
      return { value: state.origin, changed: true };
    });
  }
}
