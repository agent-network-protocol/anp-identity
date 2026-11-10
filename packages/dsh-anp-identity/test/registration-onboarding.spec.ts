import { mkdtemp, mkdir, readdir, readFile, rm, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { RegistrationOnboardingStore } from '../src/registration-onboarding.js';
import { registrationInputSchema, normalizeRegistrationPhone, composeRegistrationPhone } from '../src/registration-onboarding-types.js';
const roots: string[] = [];
afterEach(async () => { for (const root of roots.splice(0)) await rm(root,{recursive:true,force:true}); });
const active = () => {};
const input = { expectedOrigin:'https://awiki.me',expectedVersion:0,label:'Public identity',handle:'test-user',profile:'e1' as const,phone:'+15551234567' };
it('saves an owner-only stable registration intent for safe restart, without OTPs or network requests', async () => {
  const root = await mkdtemp(join(tmpdir(),'onboarding-'));roots.push(root);
  const store = new RegistrationOnboardingStore(root);
  expect(await store.read(active)).toBeUndefined();
  const result = await store.create(input,'https://awiki.me',active);
  expect(result.parameters).toMatchObject({usage:'protocol',identityOnly:true,domain:'awiki.me',handle:'test-user.awiki.me',path:'/user/test-user'});
  expect(result.config.capabilities).toEqual({mcpMachine:true,papSession:true,papAccount:false});
  expect(result.config.redirectUris).toEqual([]);
  expect(await new RegistrationOnboardingStore(root).read(active)).toEqual(result);
  await expect(store.create(input,'https://awiki.me',active)).rejects.toThrow('registration_onboarding_conflict');
  const bytes = await readFile(join(root,'owner-registration.json'),'utf8');
  expect(bytes).not.toContain('otp');expect(bytes).not.toContain('verificationCode');
  if(process.platform!=='win32')expect((await stat(join(root,'owner-registration.json'))).mode&0o777).toBe(0o600);
});
it('rejects changed origins, unexpected capabilities and contact ambiguity before any saved intent', async () => {
  const root = await mkdtemp(join(tmpdir(),'onboarding-'));roots.push(root);
  const store = new RegistrationOnboardingStore(root);
  await expect(store.create(input,'https://other.example',active)).rejects.toThrow('registration_onboarding_origin_changed');
  expect(registrationInputSchema.safeParse({...input,capabilities:{papAccount:true}}).success).toBe(false);
  expect(registrationInputSchema.safeParse({...input,email:'test@example.com'}).success).toBe(false);
  expect(registrationInputSchema.safeParse({...input,phone:undefined}).success).toBe(false);
  expect(registrationInputSchema.safeParse({...input,handle:'../unsafe'}).success).toBe(false);
  expect(await store.read(active)).toBeUndefined();
});

it('normalizes mainland mobile input but never guesses the country for other local numbers', () => {
  expect(normalizeRegistrationPhone('13800138000')).toBe('+8613800138000');
  expect(normalizeRegistrationPhone('+86 138-0013-8000')).toBe('+8613800138000');
  expect(normalizeRegistrationPhone('0086 13800138000')).toBe('+8613800138000');
  expect(normalizeRegistrationPhone('+1 (555) 123-4567')).toBe('+15551234567');
  for (const value of ['5551234567','abc13800138000','+86invalid','13800138000 ext 1','']) expect(normalizeRegistrationPhone(value)).toBeUndefined();
  expect(registrationInputSchema.parse({...input,phone:'13800138000'}).phone).toBe('+8613800138000');
});

it('combines the selected dialing code without assuming China for other countries', () => {
  expect(composeRegistrationPhone('+86','13800138000')).toBe('+8613800138000');
  expect(composeRegistrationPhone('+86','10000000001')).toBe('+8610000000001');
  expect(composeRegistrationPhone('+1','5551234567')).toBe('+15551234567');
  expect(composeRegistrationPhone('+86','+8613800138000')).toBeUndefined();
  expect(composeRegistrationPhone('86','13800138000')).toBeUndefined();
  expect(composeRegistrationPhone('+86','1234')).toBeUndefined();
});

it('keeps an existing saved E1 namespace and leaves the Web branch unchanged', async () => {
  const root = await mkdtemp(join(tmpdir(),'onboarding-')); roots.push(root);
  const store = new RegistrationOnboardingStore(root);
  const created = await store.create(input,'https://awiki.me',active);
  const file = join(root,'owner-registration.json');
  const old = JSON.parse(await readFile(file,'utf8')); old.parameters.path='/awiki/user/test-user';
  await import('node:fs/promises').then(fs=>fs.writeFile(file,JSON.stringify(old)));
  expect((await new RegistrationOnboardingStore(root).read(active))?.parameters.path).toBe('/awiki/user/test-user');
  const webRoot = await mkdtemp(join(tmpdir(),'onboarding-web-')); roots.push(webRoot);
  const web = await new RegistrationOnboardingStore(webRoot).create({...input,profile:'web'},'https://awiki.me',active);
  expect(web.parameters.path).toBe('/awiki/user/test-user');
  expect(created.parameters.handle).toBe(web.parameters.handle);
});

it('archives an unstarted deleted identity flow with CAS and retains its owner record', async () => {
  const root = await mkdtemp(join(tmpdir(), 'onboarding-archive-')); roots.push(root);
  const store = new RegistrationOnboardingStore(root);
  const first = await store.create(input, 'https://awiki.me', active);
  const archiveInput = { requestId: first.config.requestId, expectedVersion: first.version };
  const archived = await store.archiveUnstarted(archiveInput, async current => { expect(current).toEqual(first); }, active);
  expect(archived).toMatchObject({ version: 2, archived: true, config: first.config });
  expect(await new RegistrationOnboardingStore(root).read(active)).toEqual(archived);
  const backup = (await readdir(root)).find(name => name.startsWith('archived-registration-'))!;
  expect(JSON.parse(await readFile(join(root, backup), 'utf8'))).toEqual(first);
  await expect(store.archiveUnstarted(archiveInput, async () => {}, active)).rejects.toThrow('registration_onboarding_conflict');
  await expect(store.create(input, 'https://awiki.me', active)).rejects.toThrow('registration_onboarding_conflict');
  const next = await store.create({ ...input, expectedVersion: archived.version }, 'https://awiki.me', active);
  expect(next.version).toBe(3); expect(next.archived).toBeUndefined();
  expect(next.config.requestId).not.toBe(first.config.requestId);
});

it('refuses to archive any initialized flow, even if its journal is missing', async () => {
  const root = await mkdtemp(join(tmpdir(), 'onboarding-execution-')); roots.push(root);
  const store = new RegistrationOnboardingStore(root);
  const first = await store.create(input, 'https://awiki.me', active);
  const flow = join(root, 'registration-bootstrap', createHash('sha256').update(first.config.id).digest('hex'));
  await mkdir(flow, { recursive: true, mode: 0o700 });
  await expect(store.archiveUnstarted({ requestId: first.config.requestId, expectedVersion: first.version }, async () => {}, active))
    .rejects.toThrow('registration_onboarding_recovery_required');
  expect(await store.read(active)).toEqual(first);
  expect((await readdir(root)).some(name => name.startsWith('archived-registration-'))).toBe(false);
});

it('requires deletion evidence and serializes competing archive writers', async () => {
  const root = await mkdtemp(join(tmpdir(), 'onboarding-archive-cas-')); roots.push(root);
  const store = new RegistrationOnboardingStore(root);
  const first = await store.create(input, 'https://awiki.me', active);
  const key = { requestId: first.config.requestId, expectedVersion: first.version };
  await expect(store.archiveUnstarted(key, async () => { throw new Error('not_deleted'); }, active)).rejects.toThrow('not_deleted');
  expect(await store.read(active)).toEqual(first);
  const results = await Promise.allSettled([store.archiveUnstarted(key, async () => {}, active),
    new RegistrationOnboardingStore(root).archiveUnstarted(key, async () => {}, active)]);
  expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
  expect((await store.read(active))?.version).toBe(2);
});
