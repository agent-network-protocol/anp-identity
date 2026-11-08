import { mkdtemp, rm, readFile, writeFile, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { afterEach, expect, it } from 'vitest';
import { RegistrationServiceSettingsStore, registrationOrigin } from '../src/registration-service-settings.js';
import { RegistrationBootstrapConfigSchema } from '../src/registration-bootstrap.js';

const roots: string[] = [];
afterEach(async () => { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });
async function fixture() { const root = await mkdtemp(join(tmpdir(), 'registration-settings-')); roots.push(root); return { root, store: new RegistrationServiceSettingsStore(root) }; }
const active = () => {};
it('defaults new registrations to awiki.me without creating an identity or network request', async () => {
  const { store } = await fixture();
  expect(await store.read(active)).toEqual({ origin: 'https://awiki.me', version: 0 });
  expect(RegistrationBootstrapConfigSchema.parse({ id: 'new', requestId: 'new', stateRoot: '/private/state',
    email: 'owner@example.com', clientName: 'Example', capabilities: { mcpMachine: true, papSession: true, papAccount: false } }).origin).toBe('https://awiki.me');
});
it('persists a canonical HTTPS preference and rejects stale writes across instances', async () => {
  const { root, store } = await fixture();
  expect(await store.update({ origin: 'https://service.example/', expectedVersion: 0 }, active)).toEqual({ origin: 'https://service.example', version: 1 });
  const next = new RegistrationServiceSettingsStore(root);
  expect(await next.read(active)).toEqual({ origin: 'https://service.example', version: 1 });
  await expect(store.update({ origin: 'https://other.example', expectedVersion: 0 }, active)).rejects.toThrow('registration_service_conflict');
  expect((await next.read(active)).origin).toBe('https://service.example');
  expect((await stat(join(root, 'manager-settings'))).mode & 0o777).toBe(0o700);
  expect((await stat(join(root, 'manager-settings/registration.json'))).mode & 0o777).toBe(0o600);
});
it.each(['http://awiki.me','https://user:pass@awiki.me','https://awiki.me/path','https://awiki.me?token=value','https://awiki.me#fragment','not-a-url'])('rejects an unsafe service origin: %s', value => {
  expect(() => registrationOrigin(value)).toThrow('registration_service_invalid_origin');
});
it('serializes concurrent CAS updates so exactly one writer succeeds', async () => {
  const { root, store } = await fixture(); await store.read(active);
  const other = new RegistrationServiceSettingsStore(root);
  const result = await Promise.allSettled([store.update({ origin: 'https://one.example', expectedVersion: 0 }, active), other.update({ origin: 'https://two.example', expectedVersion: 0 }, active)]);
  expect(result.filter(item => item.status === 'fulfilled')).toHaveLength(1);
  expect((await store.read(active)).version).toBe(1);
});
it('pins an existing registration to its original service while new flows use the saved preference', async () => {
  const { root, store } = await fixture();
  const key = 'a'.repeat(64), fingerprint = 'b'.repeat(64);
  expect(await store.pin(key, fingerprint, active)).toBe('https://awiki.me');
  const current = await store.read(active);
  await store.update({ origin: 'https://new.example', expectedVersion: current.version }, active);
  expect(await new RegistrationServiceSettingsStore(root).pin(key, fingerprint, active)).toBe('https://awiki.me');
  expect(await store.pin('c'.repeat(64), fingerprint, active)).toBe('https://new.example');
  await expect(store.pin(key, 'd'.repeat(64), active)).rejects.toThrow('registration_service_flow_conflict');
  const bytes = await readFile(join(root, 'manager-settings/registration.json'), 'utf8');
  expect(bytes).not.toContain('email'); expect(bytes).not.toContain('phone');
});
it('never resets corrupt settings or writes after the owning manager is inactive', async () => {
  const { root, store } = await fixture();
  await expect(store.update({ origin: 'https://one.example', expectedVersion: 0 }, () => { throw new Error('inactive'); })).rejects.toThrow('inactive');
  await store.read(active);
  const path = join(root, 'manager-settings/registration.json'); await writeFile(path, 'corrupt', { mode: 0o600 });
  await expect(store.read(active)).rejects.toThrow('registration_service_settings_unavailable');
  expect(await readFile(path, 'utf8')).toBe('corrupt');
});
