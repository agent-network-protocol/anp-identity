import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
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
  expect(result.parameters).toMatchObject({usage:'protocol',identityOnly:true,domain:'awiki.me',handle:'test-user.awiki.me',path:'/awiki/user/test-user'});
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
  expect(composeRegistrationPhone('+1','5551234567')).toBe('+15551234567');
  expect(composeRegistrationPhone('+86','+8613800138000')).toBeUndefined();
  expect(composeRegistrationPhone('86','13800138000')).toBeUndefined();
  expect(composeRegistrationPhone('+86','1234')).toBeUndefined();
});
