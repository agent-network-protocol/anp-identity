/** Explicit browser-safe Typert method contract for the optional manager. */
import { z } from "zod";
import type { TypertRemoteContribution } from "@deepseek-ai/dsh-typert-protocol";

const reference = z
  .object({
    storeId: z.string().min(1),
    identityId: z.string().min(1),
    did: z.string().min(1),
  })
  .strict();
const version = z
  .object({
    requestId: z.string().min(1),
    expectedVersion: z.number().int().positive(),
  })
  .strict();
const decision = version
  .extend({
    decision: z.enum(["approve", "deny"]),
    identity: reference.optional(),
    mode: z.enum(["once", "permanent"]).optional(),
    reviewedSnapshot: z
      .object({
        version: z.string().min(1),
        capabilities: z.array(
          z.enum(["identity:read", "identity:sign", "identity:http-auth"]),
        ),
        signingPurposes: z.array(z.string()),
        httpOrigins: z.array(z.string()),
      })
      .strict()
      .optional(),
  })
  .strict();
const methods = [
  ["listIdentities", undefined],
  ["listRequests", z.boolean().optional()],
  ["getRequest", z.string().min(1)],
  ["decide", decision],
  ["grants", reference],
  [
    "revoke",
    z
      .object({
        grantId: z.string().min(1),
        expectedVersion: z.number().int().positive(),
      })
      .strict(),
  ],
  ["publicDocument", reference],
  [
    "deleteIdentity",
    z.object({ reference, confirmationName: z.string().min(1) }).strict(),
  ],
  ["markPrompted", version],
  ["reauthorize", version],
] as const;

const contribution: TypertRemoteContribution = {
  package: "@agent-network-protocol/dsh-anp-identity",
  descriptors: methods.map(([method, schema]) => ({
    id: `@agent-network-protocol/dsh-anp-identity#anpIdentityManager/${method}`,
    service: "anpIdentityManager",
    namespace: "anpIdentityManager",
    method,
    invocation: { kind: "direct" },
    parameters:
      schema === undefined
        ? []
        : [
            {
              name: "input",
              wire: "input",
              source: "json",
              ...(method === "listRequests" ? { acceptsUndefined: true } : {}),
              codec: {
                mode: "strict",
                typeSymbol: `anp-identity/manager#${method}Input`,
                schema,
              },
            },
          ],
    result: {
      mode: "strict",
      typeSymbol: `anp-identity/manager#${method}Result`,
      schema: z.json().nullable(),
    },
  })),
};
export default contribution;
