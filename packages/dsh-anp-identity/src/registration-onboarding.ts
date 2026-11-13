import { z } from 'zod';
import { mkdir, lstat, readFile, open, rename, rm } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import lockfile from 'proper-lockfile';
import { RegistrationBootstrapConfigSchema } from './registration-bootstrap.js';
import { syncDirectory } from './sync-directory.js';

import { registrationInputSchema, type RegistrationOnboardingInput } from './registration-onboarding-types.js';

const saved = z.object({
  version: z.number().int().nonnegative(),
  config: RegistrationBootstrapConfigSchema,
  parameters: z.object({
    profile: z.enum(['e1','web']), usage: z.literal('protocol'), identityOnly: z.literal(true),
    label: z.string(), domain: z.string(), path: z.string(), handle: z.string(),
  }).strict(),
}).strict();
export type SavedRegistrationOnboarding = z.infer<typeof saved>;

/** Private owner input, not a model DTO. OTPs are never written here. */
export class RegistrationOnboardingStore {
  constructor(private readonly root: string) {}
  private async locked<T>(active: () => void, action: () => Promise<T>): Promise<T> {
    active(); await mkdir(this.root, { recursive: true, mode: 0o700 });
    const info = await lstat(this.root);
    if (!info.isDirectory() || info.isSymbolicLink() ||
      process.platform !== 'win32' && (info.mode & 0o077) ||
      typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('registration_onboarding_unavailable');
    const release = await lockfile.lock(this.root, { realpath: true, retries: { retries: 80, minTimeout: 10, maxTimeout: 100 } });
    try { active(); return await action(); } finally { await release(); }
  }
  private async load(): Promise<SavedRegistrationOnboarding | undefined> {
    try {
      const file = join(this.root, 'owner-registration.json'), info = await lstat(file);
      if (!info.isFile() || info.isSymbolicLink() || info.size > 16384 ||
        process.platform !== 'win32' && (info.mode & 0o077) ||
        typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error();
      return saved.parse(JSON.parse(await readFile(file, 'utf8')));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw new Error('registration_onboarding_unavailable');
    }
  }
  read(active: () => void): Promise<SavedRegistrationOnboarding | undefined> {
    return this.locked(active, async () => { const value = await this.load(); active(); return value; });
  }
  async create(input: RegistrationOnboardingInput, origin: string, active: () => void): Promise<SavedRegistrationOnboarding> {
    const value = registrationInputSchema.parse(input);
    if (value.expectedOrigin !== origin) throw new Error('registration_onboarding_origin_changed');
    const host = new URL(origin);
    if (host.protocol !== 'https:' || host.port || !/^[a-z0-9.-]+$/iu.test(host.hostname)) throw new Error('registration_onboarding_origin_unavailable');
    return this.locked(active, async () => {
      const old = await this.load();
      if ((old?.version ?? 0) !== value.expectedVersion) throw new Error('registration_onboarding_conflict');
      const id = 'ui-' + randomUUID(), requestId = 'create-' + randomUUID();
      const result = saved.parse({
        version: (old?.version ?? 0) + 1,
        config: { id, requestId, stateRoot: this.root, origin, clientName: value.label,
          ...(value.phone ? { phone: value.phone } : { email: value.email }),
          capabilities: { mcpMachine: true, papSession: true, papAccount: false }, redirectUris: [] },
        parameters: { profile: value.profile, usage: 'protocol', identityOnly: true, label: value.label,
          domain: host.hostname, path: value.profile === 'web' ? '/awiki/web/' + randomUUID().replaceAll('-', '') : '/awiki/user/' + value.handle, handle: value.handle + '.' + host.hostname },
      });
      const temp = join(this.root, '.' + randomUUID() + '.tmp');
      try {
        const file = await open(temp, 'wx', 0o600);
        try { await file.writeFile(JSON.stringify(result) + '\n'); await file.sync(); } finally { await file.close(); }
        active(); await rename(temp, join(this.root, 'owner-registration.json')); await syncDirectory(this.root); active();
      } finally { await rm(temp, { force: true }); }
      return result;
    });
  }
}
