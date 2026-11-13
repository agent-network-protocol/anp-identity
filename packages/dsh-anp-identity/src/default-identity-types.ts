/** Browser-safe preferences; selecting a row in the manager is not a default change. */
import { z } from 'zod'

export const identityReferenceSchema = z.object({
  storeId: z.string().min(1).max(256), identityId: z.string().min(1).max(256), did: z.string().min(1).max(2048),
}).strict()
export const defaultIdentitySettingsSchema = z.object({
  schema: z.literal(1), version: z.number().int().nonnegative(), identity: identityReferenceSchema.nullable(),
}).strict()
export const updateDefaultIdentitySchema = z.object({
  expectedVersion: z.number().int().nonnegative(), identity: identityReferenceSchema.nullable(),
}).strict()
export type DefaultIdentitySettings = z.infer<typeof defaultIdentitySettingsSchema>
export type UpdateDefaultIdentity = z.infer<typeof updateDefaultIdentitySchema>
