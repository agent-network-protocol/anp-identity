// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import {
  IdentityController,
  identityKey,
  type ManagementRemote,
} from "../src/client/controller.js";
import {
  IdentitySettings,
  IdentityOverlay,
  FULL_PERMISSION_NOTICE,
} from "../src/client/views.js";
import type {
  ManagedIdentitySummary,
  RequestReview,
} from "../src/management-types.js";
import type {
  AuthorizationGrant,
  AuthorizationRequest,
  CapabilitySnapshot,
} from "../src/authorization-types.js";

const identity: ManagedIdentitySummary = {
  reference: {
    storeId: "store",
    identityId: "one",
    did: "did:wba:example.com:one",
  },
  state: "active",
  catalogState: "active",
  label: "工作身份",
  handle: "work.example.com",
  integrations: [],
};
const { handle: _handle, ...withoutHandle } = identity;
const second: ManagedIdentitySummary = {
  ...withoutHandle,
  label: "个人身份",
  reference: {
    ...identity.reference,
    identityId: "two",
    did: "did:wba:example.com:two",
  },
};
const snapshot: CapabilitySnapshot = {
  version: "ordinary/1",
  capabilities: ["identity:read", "identity:sign", "identity:http-auth"],
  signingPurposes: ["request_signing"],
  httpOrigins: ["https://api.example.com"],
};
const caller = { consumer: "@example/research", displayName: "资料助手" };
function request(
  kind: "create" | "access",
  id: string = kind,
): AuthorizationRequest {
  const base = {
    id,
    caller,
    purpose: "连接资料服务",
    version: 1,
    status: "pending" as const,
    createdAt: 1000,
    expiresAt: Date.now() + 60000,
    fingerprint: "fixed",
    prompted: false,
  };
  return kind === "create"
    ? {
        ...base,
        kind,
        parameters: {
          label: "笔记身份",
          domain: "example.com",
          path: "/agents/notes",
        },
      }
    : {
        ...base,
        kind,
        identity: identity.reference,
        operation: {
          capability: "identity:http-auth",
          fingerprint: "fixed-operation",
          summary: "GET https://api.example.com/profile",
          httpOrigin: "https://api.example.com",
        },
      };
}
function fixture(
  requests: AuthorizationRequest[] = [],
  initialGrants: AuthorizationGrant[] = [],
) {
  let identities = [identity, second];
  let grants = initialGrants;
  const ok = <T,>(value: T) => ({ ok: true as const, value });
  const remote = {
    listIdentities: vi.fn(async () => ok(identities)),
    listRequests: vi.fn(async (history?: boolean) =>
      ok(
        requests.filter((r) =>
          history ? r.status !== "pending" : r.status === "pending",
        ),
      ),
    ),
    getRequest: vi.fn(
      async (id: string): Promise<{ ok: true; value: RequestReview }> =>
        ok({
          request: requests.find((r) => r.id === id)!,
          identities,
          snapshot,
          snapshots: identities.map((i) => ({
            identity: i.reference,
            snapshot,
          })),
        } satisfies RequestReview),
    ),
    markPrompted: vi.fn(async ({ requestId }: { requestId: string }) => {
      requests = requests.map((r) =>
        r.id === requestId ? { ...r, prompted: true } : r,
      );
      return ok(null);
    }),
    decide: vi.fn(async (input) => {
      const current = requests.find((r) => r.id === input.requestId)!;
      const result = {
        ...current,
        status:
          input.decision === "approve"
            ? ("approved" as const)
            : ("denied" as const),
        version: 2,
        ...(current.kind === "access" ? { mode: input.mode } : {}),
      };
      requests = requests.map((r) => (r.id === current.id ? result : r));
      return ok(result);
    }),
    grants: vi.fn(async (reference) =>
      ok(
        grants.filter(
          (g) => identityKey(g.identity) === identityKey(reference),
        ),
      ),
    ),
    revoke: vi.fn(async ({ grantId }) => {
      grants = grants.filter((g) => g.id !== grantId);
      return ok(null);
    }),
    publicDocument: vi.fn(async (ref) =>
      ok({ id: ref.did, verificationMethod: [] }),
    ),
    deleteIdentity: vi.fn(async ({ reference }) => {
      identities = identities.filter(
        (i) => identityKey(i.reference) !== identityKey(reference),
      );
      return ok(null);
    }),
    reauthorize: vi.fn(async () => ok(request("access", "new-request"))),
  } satisfies ManagementRemote;
  const controller = new IdentityController(remote);
  return {
    controller,
    remote,
    render: () =>
      render(
        <>
          <IdentitySettings controller={controller} />
          <IdentityOverlay controller={controller} />
        </>,
      ),
  };
}
afterEach(cleanup);

describe("Identity management UI against Host-shaped Remote", () => {
  it("keeps complete identity values copyable while switching compact identity cards", async () => {
    const f = fixture();
    const copy = vi.spyOn(f.controller, "copy").mockResolvedValue(undefined);
    f.render();
    await act(() => f.controller.refresh());
    const nav = screen.getByRole("navigation", { name: "我的身份" });
    expect(nav.querySelector("svg")).toBeNull();
    expect(within(nav).getByTitle(identity.reference.did).textContent).toBe(identity.reference.did);
    fireEvent.click(screen.getByRole("button", { name: "复制 DID" }));
    expect(copy).toHaveBeenLastCalledWith(identity.reference.did);
    fireEvent.click(screen.getByRole("button", { name: "复制 Handle" }));
    expect(copy).toHaveBeenLastCalledWith(identity.handle);
    fireEvent.click(within(nav).getByRole("button", { name: /个人身份/ }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "复制 Handle" })).toBeNull());
    fireEvent.click(screen.getByRole("button", { name: "复制 DID" }));
    expect(copy).toHaveBeenLastCalledWith(second.reference.did);
    expect(screen.getByText("未设置")).toBeTruthy();
    expect(within(nav).getByRole("button", { name: /个人身份/ }).getAttribute("aria-current")).toBe("true");
  });
  it("shows saved Handle, no creation shortcuts, and current read-only permission details", async () => {
    const grant: AuthorizationGrant = {
      id: "grant",
      requestId: "r",
      caller,
      identity: identity.reference,
      snapshot,
      mode: "permanent",
      version: 1,
      approvedAt: 1,
      status: "active",
    };
    const f = fixture([], [grant]);
    f.render();
    await act(() => f.controller.refresh());
    expect(screen.getByText("work.example.com")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /创建身份/ })).toBeNull();
    expect(
      screen.getByRole("button", { name: "删除身份" }).hasAttribute("disabled"),
    ).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "权限详情" }));
    const dialog = await screen.findByRole("dialog", { name: "权限详情" });
    expect(within(dialog).getByText(FULL_PERMISSION_NOTICE)).toBeTruthy();
    expect(within(dialog).getByText(/request_signing/)).toBeTruthy();
    expect(within(dialog).queryAllByRole("checkbox")).toHaveLength(0);
    expect(within(dialog).queryAllByRole("radio")).toHaveLength(0);
    expect(
      within(dialog).queryByRole("button", { name: "允许授权" }),
    ).toBeNull();
    fireEvent.click(within(dialog).getByRole("button", { name: "关闭" }));
    fireEvent.click(screen.getByRole("button", { name: /个人身份/ }));
    await waitFor(() => {
      expect(screen.getByText("未设置")).toBeTruthy();
    });
  });
  it("keeps creation immutable, queues one modal, and later retains both pending requests across refresh", async () => {
    const f = fixture([request("create"), request("access")]);
    f.render();
    await act(() => f.controller.refresh());
    const dialog = screen.getByRole("dialog", { name: /创建身份/ });
    expect(screen.getAllByRole("dialog")).toHaveLength(1);
    expect(document.activeElement).toBe(
      within(dialog).getByRole("button", { name: "稍后关闭" }),
    );
    const approve = within(dialog).getByRole("button", { name: "允许创建" });
    approve.focus();
    fireEvent.keyDown(document, { key: "Tab" });
    expect(document.activeElement).toBe(
      within(dialog).getByRole("button", { name: "稍后关闭" }),
    );
    expect(within(dialog).queryAllByRole("textbox")).toHaveLength(0);
    expect(
      within(dialog).getByText("仅创建身份，不会同时授予使用权限。"),
    ).toBeTruthy();
    expect(f.remote.decide).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "稍后" }));
    await act(() => f.controller.refresh());
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("tab", { name: /授权请求\s*2/ })).toBeTruthy();
    fireEvent.click(screen.getByRole("tab", { name: /授权请求\s*2/ }));
    expect(screen.getAllByRole("button", { name: "查看请求" })).toHaveLength(2);
    const trigger = screen.getAllByRole("button", { name: "查看请求" })[0]!;
    trigger.focus();
    fireEvent.click(trigger);
    await screen.findByRole("dialog");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(trigger));
    expect(f.remote.decide).not.toHaveBeenCalled();
  });
  it("defaults each use confirmation to once and sends the immutable version plus selected mode only on approval", async () => {
    const f = fixture([request("access")]);
    f.render();
    await act(() => f.controller.refresh());
    expect(
      (screen.getByRole("radio", { name: /单次授权/ }) as HTMLInputElement)
        .checked,
    ).toBe(true);
    const mode = screen.getByRole("group", { name: "授权方式" });
    const scope = screen.getByText("全部使用权限 · 查看范围");
    const operation = screen.getByText(
      "本次操作：GET https://api.example.com/profile",
    );
    expect(
      mode.compareDocumentPosition(scope) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      operation.compareDocumentPosition(scope) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(FULL_PERMISSION_NOTICE)).toBeTruthy();
    expect(
      within(dialog).getByText("签名可在外部使用，不受网站列表限制。"),
    ).toBeTruthy();
    fireEvent.click(screen.getByRole("radio", { name: /永久授权/ }));
    fireEvent.click(screen.getByRole("button", { name: "允许授权" }));
    await waitFor(() =>
      expect(f.remote.decide).toHaveBeenCalledWith({
        requestId: "access",
        expectedVersion: 1,
        decision: "approve",
        identity: identity.reference,
        mode: "permanent",
        reviewedSnapshot: snapshot,
      }),
    );
    expect(f.remote.publicDocument).not.toHaveBeenCalled();
  });
  it("blocks once without a concrete operation without silently switching to permanent", async () => {
    const access = request("access");
    if (access.kind !== "access") throw new Error("fixture");
    const { operation: _operation, ...withoutOperation } = access;
    const f = fixture([withoutOperation]);
    f.render();
    await act(() => f.controller.refresh());
    expect(
      (screen.getByRole("radio", { name: /单次授权/ }) as HTMLInputElement)
        .checked,
    ).toBe(true);
    expect(
      screen.getByRole("button", { name: "允许授权" }).hasAttribute("disabled"),
    ).toBe(true);
    expect(screen.getByText(/原插件未提供明确操作/)).toBeTruthy();
    expect(f.remote.decide).not.toHaveBeenCalled();
  });
  it("closes a stale permission modal when the authoritative grant was revoked elsewhere", async () => {
    const grant: AuthorizationGrant = {
      id: "grant",
      requestId: "r",
      caller,
      identity: identity.reference,
      snapshot,
      mode: "permanent",
      version: 1,
      approvedAt: 1,
      status: "active",
    };
    const f = fixture([], [grant]);
    f.render();
    await act(() => f.controller.refresh());
    fireEvent.click(screen.getByRole("button", { name: "权限详情" }));
    await screen.findByRole("dialog");
    await f.remote.revoke({
      grantId: grant.id,
      expectedVersion: grant.version,
    });
    await act(() => f.controller.refresh());
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText("该授权已失效。")).toBeTruthy();
  });
  it("clears stale DID JSON when switching identities and reports failures instead of empty success", async () => {
    const f = fixture();
    f.render();
    await act(() => f.controller.refresh());
    fireEvent.click(screen.getByRole("button", { name: /查看 DID 文档/ }));
    await screen.findByRole("button", { name: "复制 JSON" });
    fireEvent.click(screen.getByRole("button", { name: /个人身份/ }));
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "复制 JSON" })).toBeNull(),
    );
    f.remote.listIdentities.mockRejectedValueOnce(
      new Error("Catalog unavailable"),
    );
    await act(() => f.controller.refresh());
    expect(screen.getByRole("alert").textContent).toContain(
      "Catalog unavailable",
    );
    expect(screen.queryByText("身份由插件申请创建")).toBeNull();
  });
  it("reconciles an uncertain approved creation through result lookup without requesting or approving another creation", async () => {
    const initial = request("create");
    if (initial.kind !== "create") throw new Error("fixture");
    const uncertain = {
      ...initial,
      prompted: true,
      status: "approved" as const,
      executionStatus: "unknown" as const,
      operationId: "existing-operation",
    };
    const succeeded = {
      ...uncertain,
      executionStatus: "succeeded" as const,
      result: { reference: identity.reference, label: "笔记身份" },
    };
    const f = fixture([uncertain]);
    f.render();
    await act(() => f.controller.refresh());
    fireEvent.click(screen.getByRole("tab", { name: "授权请求" }));
    fireEvent.click(screen.getByRole("button", { name: "已处理" }));
    await screen.findByRole("button", { name: "核对结果" });
    expect(screen.queryByRole("button", { name: "重新申请" })).toBeNull();
    f.remote.getRequest.mockResolvedValueOnce({
      ok: true,
      value: {
        request: succeeded,
        identities: [identity, second],
        snapshot,
        snapshots: [],
      },
    });
    fireEvent.click(screen.getByRole("button", { name: "核对结果" }));
    const dialog = await screen.findByRole("dialog", { name: "请求结果" });
    expect(within(dialog).getByText("创建结果：身份已创建")).toBeTruthy();
    expect(within(dialog).getByText(identity.reference.did)).toBeTruthy();
    expect(
      within(dialog).queryByRole("button", { name: "允许创建" }),
    ).toBeNull();
    expect(f.remote.getRequest).toHaveBeenCalledExactlyOnceWith(initial.id);
    expect(f.remote.reauthorize).not.toHaveBeenCalled();
    expect(f.remote.decide).not.toHaveBeenCalled();
    expect(f.remote.markPrompted).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "关闭" }));
    expect(screen.getByText("已允许 · 身份已创建")).toBeTruthy();
    expect(screen.getByRole("button", { name: "查看结果" })).toBeTruthy();
  });
  it.each([
    ["consumed", "已使用"],
    ["expired", "已过期"],
    ["revoked", "已撤销"],
  ] as const)(
    "shows the current %s grant outcome without implying a historic approval still works",
    async (status, label) => {
      const initial = request("access");
      if (initial.kind !== "access") throw new Error("fixture");
      const approved = {
        ...initial,
        prompted: true,
        status: "approved" as const,
        mode: "once" as const,
        grantId: "old-grant",
      };
      const grant: AuthorizationGrant = {
        id: "old-grant",
        requestId: initial.id,
        caller,
        identity: identity.reference,
        snapshot,
        mode: "once",
        version: 2,
        approvedAt: 1,
        status,
      };
      const f = fixture([approved]);
      f.render();
      await act(() => f.controller.refresh());
      fireEvent.click(screen.getByRole("tab", { name: "授权请求" }));
      fireEvent.click(screen.getByRole("button", { name: "已处理" }));
      await screen.findByRole("button", { name: "查看结果" });
      f.remote.getRequest.mockResolvedValueOnce({
        ok: true,
        value: { request: approved, grant, identities: [identity] },
      });
      fireEvent.click(screen.getByRole("button", { name: "查看结果" }));
      const dialog = await screen.findByRole("dialog", { name: "请求结果" });
      expect(within(dialog).getByText(`当前授权：${label}`)).toBeTruthy();
      expect(
        within(dialog).queryByRole("button", { name: "允许授权" }),
      ).toBeNull();
      expect(f.remote.reauthorize).not.toHaveBeenCalled();
      expect(f.remote.decide).not.toHaveBeenCalled();
    },
  );
});
