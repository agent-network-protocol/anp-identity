import { Context } from "@deepseek-ai/cordis";
import TypertRegistry from "@deepseek-ai/dsh-typert-registry";
import TypertGateway from "@deepseek-ai/dsh-api-gateway";
import RemoteAccessService from "@deepseek-ai/dsh-api-remote-access";
import { Peer } from "@deepseek-ai/dsh-client-connection";
import { describe, expect, it, vi } from "vitest";
import ManagerRemote from "../lib/management-remote.js";
import contribution from "../src/remote.js";
import { initialProtocolPolicy, type UpdateProtocolPolicy } from '../src/protocol-policy-types.js';

describe("manager Host Remote with the real DSH registry and gateway", () => {
  it("registers strict query and command endpoints without a consumer signing or private-key surface", async () => {
    const ctx = new Context();
    const reference = {
      storeId: "store",
      identityId: "identity",
      did: "did:wba:example.com:identity",
    };
    const manager = {
      listIdentities: vi.fn(async () => [
        {
          reference,
          state: "active",
          catalogState: "active",
          label: "Example",
          integrations: [],
        },
      ]),
      decide: vi.fn(async (input) => ({
        requestId: input.requestId,
        status: "approved",
      })),
      revoke: vi.fn(async () => undefined),
    };
    const acquireManagement = vi.fn((_context: Context) => manager);
    const registrationServiceSettings = vi.fn(async (_context: Context) => ({ origin: 'https://awiki.me', version: 0 }));
    const configureRegistrationService = vi.fn(async (_context: Context, input: { origin: string; expectedVersion: number }) => ({ origin: input.origin, version: input.expectedVersion + 1 }));
    const protocolManagement = vi.fn(async (_context: Context) => ({ policy: initialProtocolPolicy(), domainAccessEnabled: true, protocols: [] }));
    const configureProtocolPolicy = vi.fn(async (_context: Context, input: UpdateProtocolPolicy) => ({ ...input.policy, schema: 1, version: input.expectedVersion + 1 }));
    const defaultIdentity = vi.fn(async (_context: Context) => ({ schema: 1, version: 0, identity: null }));
    const configureDefaultIdentity = vi.fn(async (_context: Context, input: { expectedVersion: number; identity: typeof reference | null }) => ({ schema: 1, version: input.expectedVersion + 1, identity: input.identity }));
    ctx.provide("anpIdentity", { acquireManagement, registrationServiceSettings, configureRegistrationService, protocolManagement, configureProtocolPolicy, defaultIdentity, configureDefaultIdentity });
    await ctx.plugin(TypertRegistry);
    await ctx.plugin(RemoteAccessService);
    await ctx.plugin(TypertGateway);
    const plugin = ctx.plugin(ManagerRemote);
    await plugin;
    try {
      expect(acquireManagement).toHaveBeenCalledTimes(2);
      expect(ctx.typert.local.list()).toHaveLength(
        contribution.descriptors.length,
      );
      const invoke = (method: string, args: Record<string, unknown> = {}) =>
        ctx.typertGateway.invoke({
          peer: new Peer(ctx, { principal: { kind: 'owner' } }),
          namespace: "anpIdentityManager",
          method,
          args,
        });
      await expect(invoke("listIdentities")).resolves.toEqual([
        {
          reference,
          state: "active",
          catalogState: "active",
          label: "Example",
          integrations: [],
        },
      ]);
      await expect(invoke('registrationBootstrapStatus')).resolves.toEqual([]);
      await expect(invoke('registrationServiceSettings')).resolves.toEqual({ origin: 'https://awiki.me', version: 0 });
      await expect(invoke('configureRegistrationService', { input: { origin: 'https://service.example', expectedVersion: 0, credentials: 'not-accepted' } })).rejects.toMatchObject({ code: 'gateway/input-invalid' });
      expect(configureRegistrationService).not.toHaveBeenCalled();
      await expect(invoke('configureRegistrationService', { input: { origin: 'https://service.example', expectedVersion: 0 } })).resolves.toEqual({ origin: 'https://service.example', version: 1 });
      expect(registrationServiceSettings.mock.calls[0]![0]).toBe(acquireManagement.mock.calls[0]![0]);
      expect(configureRegistrationService.mock.calls[0]![0]).toBe(acquireManagement.mock.calls[0]![0]);
      await expect(invoke('protocolManagement')).resolves.toMatchObject({ policy: initialProtocolPolicy() });
      await expect(invoke('defaultIdentity')).resolves.toEqual({ schema: 1, version: 0, identity: null });
      await expect(invoke('configureDefaultIdentity', { input: { expectedVersion: 0, identity: reference, consumer: 'owner' } })).rejects.toMatchObject({ code: 'gateway/input-invalid' });
      expect(configureDefaultIdentity).not.toHaveBeenCalled();
      await expect(invoke('configureDefaultIdentity', { input: { expectedVersion: 0, identity: reference } })).resolves.toMatchObject({ version: 1, identity: reference });
      expect(configureDefaultIdentity.mock.calls[0]![0]).toBe(acquireManagement.mock.calls[0]![0]);
      const { schema: _schema, version: _version, ...policy } = initialProtocolPolicy();
      await expect(invoke('configureProtocolPolicy', { input: { expectedVersion: 0, policy, consumer: 'pretend-owner' } })).rejects.toMatchObject({ code: 'gateway/input-invalid' });
      expect(configureProtocolPolicy).not.toHaveBeenCalled();
      await expect(invoke('configureProtocolPolicy', { input: { expectedVersion: 0, policy } })).resolves.toMatchObject({ version: 1 });
      expect(configureProtocolPolicy.mock.calls[0]![0]).toBe(acquireManagement.mock.calls[0]![0]);
      await expect(
        invoke("decide", {
          input: {
            requestId: "request",
            expectedVersion: 1,
            decision: "approve",
            identity: reference,
            mode: "once",
            capabilities: ["private-key:export"],
          },
        }),
      ).rejects.toMatchObject({ code: "gateway/input-invalid" });
      expect(manager.decide).not.toHaveBeenCalled();
      await expect(
        invoke("decide", {
          input: {
            requestId: "request",
            expectedVersion: 1,
            decision: "approve",
            identity: reference,
            mode: "once",
          },
        }),
      ).resolves.toEqual({ requestId: "request", status: "approved" });
      expect(manager.decide).toHaveBeenCalledOnce();
      await expect(
        invoke("revoke", { input: { grantId: "grant", expectedVersion: 1 } }),
      ).resolves.toBeNull();
      for (const method of [
        "sign",
        "dispatch",
        "acquireProvider",
        "exportPrivateKey",
        "requestCreateIdentity",
        'registerLocalIdentity',
        'configureManagedPublicationBackend',
        'pinManagementContext',
        'bindPapHostConsumer',
      ])
        await expect(invoke(method)).rejects.toMatchObject({
          code: "gateway/invocation-unavailable",
        });
      await plugin.dispose();
      await expect(invoke("listIdentities")).rejects.toMatchObject({
        code: "gateway/definition-unavailable",
      });
    } finally {
      await ctx.fiber.dispose();
    }
  });
});
