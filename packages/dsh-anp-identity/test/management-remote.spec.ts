import { Context } from "@deepseek-ai/cordis";
import TypertRegistry from "@deepseek-ai/dsh-typert-registry";
import TypertGateway from "@deepseek-ai/dsh-api-gateway";
import { describe, expect, it, vi } from "vitest";
import ManagerRemote from "../lib/management-remote.js";
import contribution from "../src/remote.js";

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
    const acquireManagement = vi.fn(() => manager);
    ctx.provide("anpIdentity", { acquireManagement });
    await ctx.plugin(TypertRegistry);
    await ctx.plugin(TypertGateway);
    const plugin = ctx.plugin(ManagerRemote);
    await plugin;
    try {
      expect(acquireManagement).toHaveBeenCalledOnce();
      expect(ctx.typert.local.list()).toHaveLength(
        contribution.descriptors.length,
      );
      const invoke = (method: string, args: Record<string, unknown> = {}) =>
        ctx.typertGateway.invoke({
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
