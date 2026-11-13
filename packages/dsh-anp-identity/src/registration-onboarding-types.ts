import { z } from 'zod';
/** Normalize explicit international numbers and unambiguous mainland-China mobile numbers only. */
export function normalizeRegistrationPhone(value: string): string | undefined {
  let phone = value.trim().replace(/[\s()-]/gu, '');
  if (/^1[3-9][0-9]{9}$/u.test(phone)) phone = '+86' + phone;
  if (/^00[1-9][0-9]{6,14}$/u.test(phone)) phone = '+' + phone.slice(2);
  return /^\+[1-9][0-9]{6,14}$/u.test(phone) ? phone : undefined;
}
/** The UI keeps the selected dialing code separate; never infer another country. */
export function composeRegistrationPhone(code: string, number: string): string | undefined {
  if (code === 'international') {
    if (!/^(?:\+|00)/u.test(number.trim())) return undefined;
    return normalizeRegistrationPhone(number);
  }
  const dialing = code.trim();
  const national = number.trim().replace(/[\s()-]/gu, '');
  if (!/^\+[1-9][0-9]{0,3}$/u.test(dialing) || !/^[0-9]+$/u.test(national)) return undefined;
  if (dialing === '+86' && !/^1[0-9]{10}$/u.test(national)) return undefined;
  return normalizeRegistrationPhone(dialing + national);
}
export const registrationInputSchema = z.object({
  expectedOrigin: z.string().min(1).max(2048),
  label: z.string().trim().min(1).max(128),
  handle: z.string().trim().regex(/^[a-z][a-z0-9-]{2,39}$/u),
  profile: z.enum(['e1', 'web']).default('e1'),
  phone: z.string().max(64).transform(value => normalizeRegistrationPhone(value) ?? '').refine(value => /^\+[1-9][0-9]{6,14}$/u.test(value), 'Use an international E.164 phone number').optional(),
  email: z.string().trim().email().max(254).optional(),
  expectedVersion: z.number().int().nonnegative(),
}).strict().superRefine((value, ctx) => {
  if (Boolean(value.phone) === Boolean(value.email)) ctx.addIssue({ code: 'custom', message: 'Select one verification method' });
});
export type RegistrationOnboardingInput = z.input<typeof registrationInputSchema>;
export interface RegistrationOnboardingStatus {
  readonly intentId?: string;
  readonly available: boolean;
  readonly version: number;
  readonly inProgress: boolean;
}
