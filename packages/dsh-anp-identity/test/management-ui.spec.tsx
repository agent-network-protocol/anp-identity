// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
import type { RegistrationBootstrapStatus } from '../src/registration-bootstrap.js';
import { mountStyles } from '../src/client/styles.js';

beforeEach(() => { vi.spyOn(document, 'hasFocus').mockReturnValue(true); });

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
          handle: "notes.example",
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
  let serviceSettings = { origin: "https://awiki.me", version: 0 };
  let identities = [identity, second];
  let grants = initialGrants;
  const ok = <T,>(value: T) => ({ ok: true as const, value });
  const remote = {
    registrationOnboardingStatus: vi.fn(async () => ok<{available:boolean;version:number;inProgress:boolean;intentId?:string}>({available:true,version:0,inProgress:false})),
    startIdentityRegistration: vi.fn(async (_input: unknown) => {
      requests.push(request("create","test-request"));
      return ok<{status?:string;code?:string;phase?:string;requestId?:string}>({phase:'awaiting_approval',requestId:'test-request'});
    }),
    dismissRegistrationRequest: vi.fn(async () => ok(null)),
    registrationServiceSettings: vi.fn(async () => ok(serviceSettings)),
    configureRegistrationService: vi.fn(async input => {
      serviceSettings = { origin: input.origin, version: input.expectedVersion + 1 };
      return ok(serviceSettings);
    }),
    registrationBootstrapStatus: vi.fn(async () => ok<RegistrationBootstrapStatus[]>([])),
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
    retryPublication: vi.fn(async (ref) => ok({ state: "awaiting_configuration" as const, did: ref.did })),
    publicationStatus: vi.fn(async (ref) => ok({ state: "local" as const, did: ref.did })),
    publishIdentity: vi.fn(async (input) => ok({ state: "awaiting_configuration" as const, did: input.reference.did })),
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
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("Identity management UI against Host-shaped Remote", () => {
  it('shows safe registration phases and references without claiming an automatic protocol permission grant', async () => {
    const f = fixture();
    f.remote.registrationBootstrapStatus.mockResolvedValue({ ok: true, value: [{
      id: 'work', requestId: 'create-work', phase: 'published', reference: identity.reference,
      clientId: 'https://identity.example/user-service/v1/agent-clients/work/client.json',
    }] });
    f.render();
    await act(() => f.controller.refresh());
    expect(screen.getByText('协议身份注册')).toBeTruthy();
    expect(screen.getByText('注册与发布已完成；还需由 Host 配置协议用途许可和消费者连接。')).toBeTruthy();
    expect(screen.getByText('本地身份引用')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/access_token|accessToken|ciphertext|claim_secret/u);
    f.controller.dispose();
  });
  it("keeps complete identity values copyable while switching compact identity cards", async () => {
    const f = fixture();
    const copy = vi.spyOn(f.controller, "copy").mockResolvedValue(undefined);
    f.render();
    await act(() => f.controller.refresh());
    const nav = screen.getByRole("navigation", { name: "我的身份" });
    expect(nav.querySelector("svg")).toBeNull();
    expect(within(nav).getByTitle(identity.handle!).textContent).toBe(identity.handle);
    expect(screen.getByRole("heading", { name: identity.handle! })).toBeTruthy();
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
    expect(screen.getByRole("heading", { name: second.label! })).toBeTruthy();
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
    expect(screen.getByRole("heading", { name: "work.example.com" })).toBeTruthy();
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
    expect(within(dialog).getByText("notes.example")).toBeTruthy();
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
    expect(within(dialog).queryByText(/本次操作：/)).toBeNull();
    expect(within(dialog).getByText(/持续授权：可读取公开身份、签名，并请求下列全部网站，直到你撤销/)).toBeTruthy();
    expect(within(dialog).getByText(/网站：https:\/\/api.example.com/)).toBeTruthy();
    fireEvent.click(screen.getByRole("radio", { name: /单次授权/ }));
    expect(within(dialog).getByText("本次操作：GET https://api.example.com/profile")).toBeTruthy();
    expect(within(dialog).queryByText(/持续授权：/)).toBeNull();
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
  it("confirms permanent revocation with plugin and identity and does nothing on cancellation", async () => {
    const grant: AuthorizationGrant = { id: "grant", requestId: "r", caller, identity: identity.reference, snapshot, mode: "permanent", version: 1, approvedAt: 1, status: "active" };
    const f = fixture([], [grant]);
    f.render();
    await act(() => f.controller.refresh());
    fireEvent.click(screen.getByRole("button", { name: "撤销" }));
    const dialog = await screen.findByRole("dialog", { name: "撤销授权" });
    expect(within(dialog).getByText(caller.displayName)).toBeTruthy();
    expect(within(dialog).getByText(identity.reference.did)).toBeTruthy();
    expect(f.remote.revoke).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "取消" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(f.remote.revoke).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "撤销" }));
    const confirmation = await screen.findByRole("dialog", { name: "撤销授权" });
    fireEvent.click(within(confirmation).getByRole("button", { name: "确认撤销" }));
    await waitFor(() => expect(f.remote.revoke).toHaveBeenCalledExactlyOnceWith({ grantId: grant.id, expectedVersion: grant.version }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it.each(["权限详情", "撤销"])("closes a stale %s modal when the authoritative grant was revoked elsewhere", async trigger => {
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
    fireEvent.click(screen.getByRole("button", { name: trigger }));
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

it('submits an explicit SMS code only to the manager and clears the password input', async () => {
  const f = fixture();
  const submit = vi.fn(async () => ({ ok: true as const, value: null }));
  Object.assign(f.remote, { submitRegistrationOtp: submit });
  f.remote.registrationBootstrapStatus.mockResolvedValue({ ok: true, value: [{
    id: 'phone', requestId: 'create-phone', phase: 'awaiting_phone_verification',
  }] });
  f.render(); await act(() => f.controller.refresh());
  const input = screen.getByLabelText('短信验证码') as HTMLInputElement;
  expect(input.type).toBe('password');
  expect((screen.getByRole('button', { name: '验证并注册' }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(input, { target: { value: '314159' } });
  fireEvent.click(screen.getByRole('button', { name: '验证并注册' }));
  await waitFor(() => expect(submit).toHaveBeenCalledWith({ code: '314159' }));
  expect(input.value).toBe('');
  expect(JSON.stringify(f.controller.getSnapshot())).not.toContain('314159');
  f.controller.dispose();
});

it('labels a wildcard HTTP approval as all HTTPS domains rather than a literal star', async () => {
  const pending = request('access', 'wildcard-review');
  const f = fixture([pending]);
  const wildcard = { ...snapshot, httpOrigins: ['*'] };
  f.remote.getRequest.mockResolvedValue({ ok: true, value: { request: pending, identities: [identity], snapshot: wildcard,
    snapshots: [{ identity: identity.reference, snapshot: wildcard }] } });
  f.render(); await act(() => f.controller.refresh());
  expect(await screen.findByText(/全部 HTTPS 域名（通配权限）/)).toBeTruthy();
  expect(f.remote.decide).not.toHaveBeenCalled();
  f.controller.dispose();
});

it('shows protocol HTTP-only approval without raw signing warnings or capability', async () => {
  const pending = request('access', 'device-http-review');
  const f = fixture([pending]);
  const httpOnly: CapabilitySnapshot = { version: 'ordinary-http/1', capabilities: ['identity:read', 'identity:http-auth'], signingPurposes: [], httpOrigins: ['https://anp-demo.awiki.info'] };
  f.remote.getRequest.mockResolvedValue({ ok: true, value: { request: pending, identities: [identity], snapshot: httpOnly,
    snapshots: [{ identity: identity.reference, snapshot: httpOnly }] } });
  f.render(); await act(() => f.controller.refresh());
  expect(await screen.findByText('仅允许公开身份读取与精确 HTTP 请求认证，不提供设备断言或通用签名权限。')).toBeTruthy();
  expect(screen.queryByText('签名可在外部使用，不受网站列表限制。')).toBeNull();
  expect(f.remote.decide).not.toHaveBeenCalled();
  f.controller.dispose();
});

it.each(["approved", "expired", "cancelled"] as const)("closes a stale request review after another tab changes it to %s", async status => {
  const pending = request("access", "cross-tab");
  const f = fixture([pending]);
  f.render();
  await act(() => f.controller.refresh());
  expect(f.controller.getSnapshot().modal?.kind).toBe("request");
  f.remote.listRequests.mockResolvedValue({ ok: true, value: [{ ...pending, status, version: 2 }] });
  await act(() => f.controller.refresh());
  expect(f.controller.getSnapshot().modal).toBeNull();
  expect(f.controller.getSnapshot().notice).toContain("不会自动重复授权");
  expect(f.remote.decide).not.toHaveBeenCalled();
  f.controller.dispose();
});

it("closes a pending review with a changed version without silently approving the new version", async () => {
  const pending = request("access", "changed-version");
  const f = fixture([pending]);
  await act(() => f.controller.refresh());
  f.remote.listRequests.mockResolvedValue({ ok: true, value: [{ ...pending, version: 2 }] });
  await act(() => f.controller.refresh());
  expect(f.controller.getSnapshot().modal).toBeNull();
  expect(f.remote.decide).not.toHaveBeenCalled();
  expect(f.remote.getRequest).toHaveBeenCalledTimes(1);
  f.controller.dispose();
});

it.each(["request_conflict", "request_not_pending", "request_not_found"])("refreshes a rejected stale decision (%s) without retrying approval", async code => {
  const pending = request("access", "decision-race");
  const f = fixture([pending]);
  await act(() => f.controller.refresh());
  f.remote.decide.mockRejectedValueOnce(new Error(code));
  f.remote.listRequests.mockResolvedValue({ ok: true, value: [] });
  await act(() => f.controller.decide({ decision: "approve", mode: "once", identity: identity.reference }));
  expect(f.remote.decide).toHaveBeenCalledTimes(1);
  expect(f.remote.decide.mock.calls[0]?.[0]).toMatchObject({ requestId: pending.id, expectedVersion: 1, mode: "once" });
  expect(f.controller.getSnapshot().modal).toBeNull();
  expect(f.controller.getSnapshot().error).toBeNull();
  expect(f.controller.getSnapshot().notice).toContain("不会自动重复授权");
  expect(f.remote.listRequests).toHaveBeenCalledTimes(2);
  f.controller.dispose();
});

it("closes a review removed from the pending-only list but retains an unchanged pending review", async () => {
  const pending = request("access", "pending-only");
  const f = fixture([pending]);
  await act(() => f.controller.refresh());
  await act(() => f.controller.refresh());
  expect(f.controller.getSnapshot().modal?.kind).toBe("request");
  f.remote.listRequests.mockResolvedValue({ ok: true, value: [] });
  await act(() => f.controller.refresh());
  expect(f.controller.getSnapshot().modal).toBeNull();
  expect(f.remote.decide).not.toHaveBeenCalled();
  f.controller.dispose();
});

it("keeps an unrelated decision error visible without retrying or dismissing the review", async () => {
  const pending = request("access", "unrelated-error");
  const f = fixture([pending]);
  await act(() => f.controller.refresh());
  f.remote.decide.mockRejectedValueOnce(new Error("provider_unavailable"));
  await act(() => f.controller.decide({ decision: "approve", mode: "once", identity: identity.reference }));
  expect(f.remote.decide).toHaveBeenCalledTimes(1);
  expect(f.controller.getSnapshot().modal?.kind).toBe("request");
  expect(f.controller.getSnapshot().error).toBe("provider_unavailable");
  f.controller.dispose();
});

it('edits and saves the registration origin without creating an identity, sending an OTP or migrating an existing flow', async () => {
  const f = fixture();
  f.remote.registrationBootstrapStatus.mockResolvedValue({ ok: true, value: [{
    id: 'existing', requestId: 'existing', phase: 'published', origin: 'https://id.awiki.info',
    reference: identity.reference,
  }] });
  f.render(); await act(() => f.controller.refresh());
  expect((screen.getByLabelText('身份服务地址') as HTMLInputElement).value).toBe('https://awiki.me');
  fireEvent.change(screen.getByLabelText('身份服务地址'), { target: { value: 'https://service.example' } });
  fireEvent.click(screen.getByRole('button', { name: '保存服务地址' }));
  await waitFor(() => expect(f.remote.configureRegistrationService).toHaveBeenCalledWith({ origin: 'https://service.example', expectedVersion: 0 }));
  expect(screen.getByText('注册服务：https://id.awiki.info')).toBeTruthy();
  expect(f.remote.decide).not.toHaveBeenCalled();
  f.controller.dispose();
});
it('retains the reviewed version of an unsaved origin when another page updates the preference', async () => {
  const f = fixture(); f.render(); await act(() => f.controller.refresh());
  fireEvent.change(screen.getByLabelText('身份服务地址'), { target: { value: 'https://draft.example' } });
  f.remote.registrationServiceSettings.mockResolvedValue({ ok: true, value: { origin: 'https://new.example', version: 4 } });
  await act(() => f.controller.refresh());
  fireEvent.click(screen.getByRole('button', { name: '保存服务地址' }));
  await waitFor(() => expect(f.remote.configureRegistrationService).toHaveBeenCalledWith({ origin: 'https://draft.example', expectedVersion: 0 }));
  f.controller.dispose();
});

it('refreshes a conflicting preference and requires an explicit reload before replacing the unsaved draft', async () => {
  const f = fixture(); f.render(); await act(() => f.controller.refresh());
  fireEvent.change(screen.getByLabelText('身份服务地址'), { target: { value: 'https://draft.example' } });
  f.remote.registrationServiceSettings.mockResolvedValue({ ok: true, value: { origin: 'https://other.example', version: 2 } });
  f.remote.configureRegistrationService.mockRejectedValueOnce(new Error('registration_service_conflict'));
  fireEvent.click(screen.getByRole('button', { name: '保存服务地址' }));
  await screen.findByText('配置已在其他页面更新，请刷新后重新确认。');
  expect((screen.getByLabelText('身份服务地址') as HTMLInputElement).value).toBe('https://draft.example');
  fireEvent.click(screen.getByRole('button', { name: '重新载入已保存地址' }));
  await waitFor(() => expect((screen.getByLabelText('身份服务地址') as HTMLInputElement).value).toBe('https://other.example'));
  expect(f.remote.configureRegistrationService).toHaveBeenCalledTimes(1);
  f.controller.dispose();
});

it('labels identity management and shows a safe creation example without making a request', async () => {
  const f=fixture();f.render();await act(()=>f.controller.refresh());
  expect(screen.getByRole('heading',{name:'身份管理'})).toBeTruthy();
  expect(screen.getByRole('button',{name:'复制示例提示词'})).toBeTruthy();
  expect(screen.getByText(/帮我创建一个公共身份，用于登录三方服务/)).toBeTruthy();
  expect(f.remote.startIdentityRegistration).not.toHaveBeenCalled();f.controller.dispose();
});
it('opens an owner form for an Agent intent without creating, sending contact data or approving', async () => {
  const f=fixture();
  f.remote.registrationOnboardingStatus.mockResolvedValue({ok:true,value:{available:true,version:0,inProgress:false,intentId:'agent-intent'}});
  f.render();await act(()=>f.controller.refresh());
  expect(screen.getByRole('dialog',{name:'创建公共身份'})).toBeTruthy();
  expect((screen.getByLabelText('注册手机号') as HTMLInputElement).value).toBe('');
  expect(f.remote.startIdentityRegistration).not.toHaveBeenCalled();expect(f.remote.decide).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button',{name:'稍后'}));await waitFor(()=>expect(f.remote.dismissRegistrationRequest).toHaveBeenCalledOnce());
  f.controller.dispose();
});
it('submits private contact only through the owner Remote and still requires separate creation approval', async () => {
  const f=fixture();f.render();await act(()=>f.controller.refresh());
  fireEvent.click(screen.getByRole('button',{name:'创建公共身份'}));
  fireEvent.change(screen.getByLabelText('Handle'),{target:{value:'test-user'}});
  fireEvent.change(screen.getByLabelText('国家/地区码'),{target:{value:'+1'}});
  fireEvent.change(screen.getByLabelText('注册手机号'),{target:{value:'5551234567'}});
  fireEvent.click(screen.getByRole('button',{name:'申请创建并注册'}));
  await waitFor(()=>expect(f.remote.startIdentityRegistration).toHaveBeenCalledWith({
    label:'三方服务公共身份',handle:'test-user',profile:'e1',expectedOrigin:'https://awiki.me',expectedVersion:0,phone:'+15551234567'
  }));
  expect(f.remote.decide).not.toHaveBeenCalled();
  expect(JSON.stringify(f.controller.getSnapshot())).not.toContain('+15551234567');f.controller.dispose();
});

it('normalizes a local Chinese phone before the owner Remote and explains invalid contacts without submitting', async () => {
  const f=fixture();f.render();await act(()=>f.controller.refresh());
  fireEvent.click(screen.getByRole('button',{name:'创建公共身份'}));
  fireEvent.change(screen.getByLabelText('Handle'),{target:{value:'test-user'}});
  fireEvent.change(screen.getByLabelText('注册手机号'),{target:{value:'not-a-phone'}});
  fireEvent.click(screen.getByRole('button',{name:'申请创建并注册'}));
  expect(screen.getByText(/中国大陆手机号应为/)).toBeTruthy();
  expect(f.remote.startIdentityRegistration).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('注册手机号'),{target:{value:'13800138000'}});
  fireEvent.click(screen.getByRole('button',{name:'申请创建并注册'}));
  await waitFor(()=>expect(f.remote.startIdentityRegistration).toHaveBeenCalledWith(expect.objectContaining({phone:'+8613800138000'})));
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});

it('defaults to China and distinguishes a known refusal from a genuinely unconfirmed delivery', async () => {
  const f=fixture();f.render();await act(()=>f.controller.refresh());
  fireEvent.click(screen.getByRole('button',{name:'创建公共身份'}));
  expect((screen.getByLabelText('国家/地区码') as HTMLSelectElement).value).toBe('+86');
  fireEvent.change(screen.getByLabelText('Handle'),{target:{value:'test-user'}});
  fireEvent.change(screen.getByLabelText('注册手机号'),{target:{value:'13800138000'}});
  f.remote.startIdentityRegistration.mockResolvedValueOnce({ok:true,value:{status:'rejected',code:'requester_unavailable'}});
  fireEvent.click(screen.getByRole('button',{name:'申请创建并注册'}));
  await screen.findByText('身份创建入口尚未就绪，本次未提交。请刷新或检查插件是否启用。');
  expect(f.controller.getSnapshot().error).not.toContain('无法确认');
  f.remote.startIdentityRegistration.mockRejectedValueOnce(new Error('connection_lost'));
  fireEvent.click(screen.getByRole('button',{name:'申请创建并注册'}));
  await screen.findByText('无法确认创建请求是否送达。请刷新身份管理查看当前状态，不要重复提交。');
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});

it('opens the exact creation approval immediately after submitting a form previously closed with Later', async () => {
  const f=fixture();f.render();await act(()=>f.controller.refresh());
  act(()=>f.controller.openRegistration());act(()=>f.controller.closeModal());
  act(()=>f.controller.openRegistration());
  await act(()=>f.controller.startIdentityRegistration({label:'Example',handle:'test-user',phone:'+15551234567',profile:'e1',expectedOrigin:'https://awiki.me',expectedVersion:0}));
  const modal=f.controller.getSnapshot().modal;
  expect(modal?.kind).toBe('request');
  if(modal?.kind!=='request')throw new Error('Expected approval');
  expect(modal.review.request.id).toBe('test-request');
  expect(f.remote.getRequest).toHaveBeenCalledWith('test-request');
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});
it('keeps the submitted approval open when an older polling result arrives late', async () => {
  const f=fixture();await act(()=>f.controller.refresh());
  let resolve: (value: {ok:true;value:AuthorizationRequest[]})=>void=()=>{};
  f.remote.listRequests.mockImplementationOnce(()=>new Promise(r=>{resolve=r;}));
  const polling=f.controller.refresh();
  act(()=>f.controller.openRegistration());
  await act(()=>f.controller.startIdentityRegistration({label:'Example',handle:'test-user',phone:'+15551234567',profile:'e1',expectedOrigin:'https://awiki.me',expectedVersion:0}));
  expect(f.controller.getSnapshot().modal?.kind).toBe('request');
  await act(async()=>{resolve({ok:true,value:[]});await polling;});
  expect(f.controller.getSnapshot().modal?.kind).toBe('request');
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});
it('shows a persistent Continue approval action before SMS verification is available', async () => {
  const pending=request('create','continue-create');
  const f=fixture([pending]);
  f.remote.registrationBootstrapStatus.mockResolvedValue({ok:true,value:[{id:'flow',requestId:pending.id,phase:'awaiting_approval',origin:'https://awiki.me'}]});
  f.render();await act(()=>f.controller.refresh());act(()=>f.controller.closeModal());
  expect(screen.queryByLabelText('短信验证码')).toBeNull();
  fireEvent.click(screen.getByRole('button',{name:'继续创建审批'}));
  await waitFor(()=>expect(f.controller.getSnapshot().modal?.kind).toBe('request'));
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});

for (const phase of ['awaiting_phone_verification', 'blocked'] as const) {
  it(`keeps registration visible after approval and shows ${phase} without another create request`, async () => {
    const pending = request('create', 'approved-registration');
    const f = fixture([pending]);
    let decided = false;
    f.remote.registrationBootstrapStatus.mockImplementation(async () => ({ok:true,value:[{
      id:'flow', requestId:pending.id, phase:decided ? phase : 'awaiting_approval', origin:'https://identity.example',
      ...(decided && phase === 'blocked' ? {reason:'client_upgrade_required' as const} : {}),
    }]}));
    const decide = f.remote.decide.getMockImplementation()!;
    f.remote.decide.mockImplementation(async input => { const result = await decide(input); decided = true; return result; });
    f.render(); await act(() => f.controller.refresh());
    await screen.findByRole('button', {name:'允许创建'});
    fireEvent.click(screen.getByRole('button', {name:'允许创建'}));
    const dialog = await screen.findByRole('dialog', {name:'完成身份注册'});
    if (phase === 'awaiting_phone_verification') expect(await within(dialog).findByLabelText('短信验证码')).toBeTruthy();
    else {
      expect(await within(dialog).findByText(/短信未发送：注册服务拒绝了当前客户端版本/)).toBeTruthy();
      expect(within(dialog).queryByLabelText('短信验证码')).toBeNull();
    }
    expect(f.remote.decide).toHaveBeenCalledTimes(1);
    fireEvent.click(within(dialog).getByRole('button', {name:'稍后继续'}));
    fireEvent.click(screen.getByRole('button', {name:'继续注册'}));
    expect(await screen.findByRole('dialog', {name:'完成身份注册'})).toBeTruthy();
    expect(f.remote.decide).toHaveBeenCalledTimes(1);
    f.controller.dispose();
  });
}

it('offers an explicit SMS retry for a blocked challenge, never for an uncertain registration', async () => {
  const f=fixture(); const retry=vi.fn(async()=>({ok:true as const,value:null}));
  Object.assign(f.remote,{retryRegistrationSms:retry});
  f.remote.registrationBootstrapStatus.mockResolvedValue({ok:true,value:[{id:'flow',requestId:'request',phase:'blocked',reason:'phone_unavailable'}]});
  f.render(); await act(()=>f.controller.refresh());
  expect(retry).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button',{name:'重试发送验证码'}));
  await waitFor(()=>expect(retry).toHaveBeenCalledOnce());
  f.remote.registrationBootstrapStatus.mockResolvedValue({ok:true,value:[{id:'flow',requestId:'request',phase:'registration_uncertain'}]});
  await act(()=>f.controller.refresh());
  expect(screen.queryByRole('button',{name:'重试发送验证码'})).toBeNull();
  f.controller.dispose();
});

it('shows published registration fields in Handle, DID, CIMD, local reference order without deriving a new handle', async () => {
  const f=fixture();
  f.remote.registrationBootstrapStatus.mockResolvedValue({ok:true,value:[{
    id:'published',requestId:'created',phase:'published',reference:identity.reference,
    clientId:'https://example.com/work/client.json',
  }]});
  f.render();await act(()=>f.controller.refresh());
  const section=screen.getByRole('heading',{name:'协议身份注册'}).closest('[role="status"]')!;
  const fields=[...section.querySelectorAll('.anpi-copy')].map(row=>row.textContent);
  expect(fields).toHaveLength(4);
  expect(fields[0]).toContain('Handle'); expect(fields[0]).toContain(identity.handle);
  expect(fields[1]).toContain('DID');expect(fields[2]).toContain('CIMD');expect(fields[3]).toContain('本地身份引用');
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});

it('keeps the DID copy button in the same trailing column as other published fields', async () => {
  const f=fixture(); const unmountStyles=mountStyles();
  const copy=vi.spyOn(f.controller,'copy').mockResolvedValue(undefined);
  try {
    f.remote.registrationBootstrapStatus.mockResolvedValue({ok:true,value:[{
      id:'published',requestId:'created',phase:'published',reference:identity.reference,
      clientId:'https://example.com/work/client.json',
    }]});
    f.render(); await act(()=>f.controller.refresh());
    const section=screen.getByRole('heading',{name:'协议身份注册'}).closest('[role="status"]')!;
    const did=within(section as HTMLElement).getByRole('button',{name:'复制 DID'});
    const cimd=within(section as HTMLElement).getByRole('button',{name:'复制 CIMD'});
    expect(did.parentElement!.lastElementChild).toBe(did);
    expect(getComputedStyle(did.parentElement!).gridTemplateColumns).toBe(getComputedStyle(cimd.parentElement!).gridTemplateColumns);
    expect(getComputedStyle(did).gridColumn).toBe(getComputedStyle(cimd).gridColumn);
    expect(getComputedStyle(did).gridRow).toBe(getComputedStyle(cimd).gridRow);
    fireEvent.click(did); expect(copy).toHaveBeenLastCalledWith(identity.reference.did);
  } finally { unmountStyles(); f.controller.dispose(); }
});

it.each([
  ['awaiting_approval',false], ['awaiting_email_verification',true],
  ['awaiting_phone_verification',true], ['registering',true], ['publishing',true],
  ['registration_uncertain',true], ['blocked',true], ['published',false], ['disposed',false],
] as const)('shows registration continuation only for unfinished state %s', async (phase, visible) => {
  const f=fixture();
  f.remote.registrationBootstrapStatus.mockResolvedValue({ok:true,value:[{
    id:'flow',requestId:'created',phase,reference:identity.reference,
  }]});
  f.render();await act(()=>f.controller.refresh());
  expect(Boolean(screen.queryByRole('button',{name:'继续注册'}))).toBe(visible);
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});
it('removes registration continuation as soon as verification transitions to published', async () => {
  const f=fixture();
  f.remote.registrationBootstrapStatus.mockResolvedValue({ok:true,value:[{id:'flow',requestId:'created',phase:'awaiting_phone_verification'}]});
  f.render();await act(()=>f.controller.refresh());
  expect(screen.getByRole('button',{name:'继续注册'})).toBeTruthy();
  f.remote.registrationBootstrapStatus.mockResolvedValue({ok:true,value:[{id:'flow',requestId:'created',phase:'published',reference:identity.reference,clientId:'https://example.com/work/client.json'}]});
  await act(()=>f.controller.refresh());
  expect(screen.queryByRole('button',{name:'继续注册'})).toBeNull();
  expect(screen.queryByLabelText('短信验证码')).toBeNull();
  expect(screen.getByText(/注册与发布已完成/)).toBeTruthy();
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});

it('turns an open registration dialog into completion, not another continuation, after publication', async () => {
  const f=fixture();
  f.remote.registrationBootstrapStatus.mockResolvedValue({ok:true,value:[{id:'flow',requestId:'created',phase:'awaiting_phone_verification'}]});
  f.render();await act(()=>f.controller.refresh());act(()=>f.controller.openRegistrationProgress('created'));
  expect(await screen.findByRole('dialog',{name:'完成身份注册'})).toBeTruthy();
  f.remote.registrationBootstrapStatus.mockResolvedValue({ok:true,value:[{id:'flow',requestId:'created',phase:'published',reference:identity.reference,clientId:'https://example.com/work/client.json'}]});
  await act(()=>f.controller.refresh());
  const dialog=await screen.findByRole('dialog',{name:'注册完成'});
  expect(within(dialog).queryByRole('button',{name:'稍后继续'})).toBeNull();
  expect(within(dialog).getByText(/身份注册与发布已完成，无需再次注册/)).toBeTruthy();
  fireEvent.click(within(dialog).getByRole('button',{name:'完成'}));
  expect(screen.queryByRole('dialog')).toBeNull();expect(screen.queryByRole('button',{name:'继续注册'})).toBeNull();
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});

it.each(['anp-domain/1','domain-operation/1'])('opens an exact %s approval dialog without settings and never offers permanent access', async version => {
  const f=fixture([request('access','exact-anp')]);
  const exact:CapabilitySnapshot={version,capabilities:['identity:read','identity:http-auth'],signingPurposes:[],httpOrigins:['*']};
  const original=f.remote.getRequest.getMockImplementation()!;
  f.remote.getRequest.mockImplementation(async id=>{const result=await original(id);return {ok:true,value:{...result.value,snapshot:exact,snapshots:[{identity:identity.reference,snapshot:exact}],operationPreview:{method:'GET',target:'https://api.example.com/profile',parameters:{query:'<script>not executable</script>',amount:12,currency:'USD'},bodyDigest:'a'.repeat(64)}}};});
  render(<IdentityOverlay controller={f.controller}/>);
  await act(()=>f.controller.refresh());
  const dialog=screen.getByRole('dialog');
  expect(screen.queryByRole('tablist',{name:'身份管理'})).toBeNull();
  expect(within(dialog).getByText(/GET https:\/\/api.example.com\/profile/)).toBeTruthy();
  expect(within(dialog).getByText('目标网站：https://api.example.com')).toBeTruthy();
  expect(within(dialog).getByLabelText('参数摘要').textContent).toContain('<script>not executable</script>');
  expect(dialog.querySelector('script')).toBeNull();
  expect(within(dialog).getByText('a'.repeat(64))).toBeTruthy();
  expect(f.remote.decide).not.toHaveBeenCalled();
  expect(within(dialog).queryByRole('radio',{name:/永久授权/})).toBeNull();
  expect(within(dialog).queryByText(FULL_PERMISSION_NOTICE)).toBeNull();
  expect(within(dialog).getByText(/请求内容均已绑定/)).toBeTruthy();
  fireEvent.click(within(dialog).getByRole('button',{name:'允许本次操作'}));
  await waitFor(()=>expect(f.remote.decide).toHaveBeenCalledWith(expect.objectContaining({mode:'once',requestId:'exact-anp',reviewedSnapshot:exact})));
  f.controller.dispose();
});
it('does not let a background tab consume an approval prompt before the foreground page', async () => {
  vi.mocked(document.hasFocus).mockReturnValue(false);
  const f=fixture([request('access','foreground')]);f.render();
  await act(()=>f.controller.refresh());expect(screen.queryByRole('dialog')).toBeNull();expect(f.remote.markPrompted).not.toHaveBeenCalled();
  vi.mocked(document.hasFocus).mockReturnValue(true);
  await act(()=>f.controller.refresh());expect(screen.getByRole('dialog')).toBeTruthy();expect(f.remote.markPrompted).toHaveBeenCalledOnce();
  f.controller.dispose();
});
it('deferring one batch does not disable automatic dialogs for later authorization requests', async () => {
  const f=fixture([request('access','first-batch')]);f.render();
  await act(()=>f.controller.refresh());fireEvent.click(screen.getByRole('button',{name:'稍后'}));
  await act(()=>f.controller.refresh());expect(screen.queryByRole('dialog')).toBeNull();
  const next=request('access','new-operation');
  f.remote.listRequests.mockResolvedValue({ok:true,value:[next]});
  f.remote.getRequest.mockResolvedValue({ok:true,value:{request:next,identities:[identity],snapshot}});
  await act(()=>f.controller.refresh());expect(screen.getByRole('dialog')).toBeTruthy();
  expect(f.remote.markPrompted).toHaveBeenLastCalledWith({requestId:'new-operation',expectedVersion:1});f.controller.dispose();
});

it('does not consume an automatic prompt when focus is lost during the review fetch', async () => {
  const f=fixture([request('access','focus-during-fetch')]);f.render();
  const original=f.remote.getRequest.getMockImplementation()!;
  let entered!:()=>void, release!:()=>void;
  const started=new Promise<void>(resolve=>entered=resolve), gate=new Promise<void>(resolve=>release=resolve);
  f.remote.getRequest.mockImplementationOnce(async id=>{entered();await gate;return original(id);});
  let refreshing!:Promise<void>;act(()=>{refreshing=f.controller.refresh();});await started;
  vi.mocked(document.hasFocus).mockReturnValue(false);
  await act(async()=>{release();await refreshing;});
  expect(screen.queryByRole('dialog')).toBeNull();expect(f.remote.markPrompted).not.toHaveBeenCalled();
  vi.mocked(document.hasFocus).mockReturnValue(true);await act(()=>f.controller.refresh());
  expect(screen.getByRole('dialog')).toBeTruthy();expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});
it('recovers an unseen automatic dialog after focus changes during markPrompted', async () => {
  const f=fixture([request('access','focus-during-mark')]);f.render();
  const original=f.remote.markPrompted.getMockImplementation()!;
  let entered!:()=>void, release!:()=>void;
  const started=new Promise<void>(resolve=>entered=resolve),gate=new Promise<void>(resolve=>release=resolve);
  f.remote.markPrompted.mockImplementationOnce(async input=>{entered();await gate;return original(input);});
  let refreshing!:Promise<void>;act(()=>{refreshing=f.controller.refresh();});await started;
  vi.mocked(document.hasFocus).mockReturnValue(false);await act(async()=>{release();await refreshing;});
  expect(screen.queryByRole('dialog')).toBeNull();
  vi.mocked(document.hasFocus).mockReturnValue(true);await act(()=>f.controller.refresh());
  expect(screen.getByRole('dialog')).toBeTruthy();expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});
it('allows a foreground page to present a new pending request already marked by another tab', async () => {
  const f=fixture();f.render();await act(()=>f.controller.refresh());
  const next={...request('access','new-other-tab'),prompted:true};
  f.remote.listRequests.mockResolvedValue({ok:true,value:[next]});
  f.remote.getRequest.mockResolvedValue({ok:true,value:{request:next,identities:[identity],snapshot}});
  await act(()=>f.controller.refresh());expect(screen.getByRole('dialog')).toBeTruthy();
  act(()=>f.controller.closeModal(false));await act(()=>f.controller.refresh());
  expect(screen.queryByRole('dialog')).toBeNull();expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});
it('does not automatically reopen inherited already-prompted requests or consume a prompt after disposal', async () => {
  const inherited={...request('access','inherited'),prompted:true};
  const f=fixture([inherited]);f.render();await act(()=>f.controller.refresh());
  expect(screen.queryByRole('dialog')).toBeNull();expect(f.remote.getRequest).not.toHaveBeenCalled();f.controller.dispose();
  cleanup();
  const g=fixture([request('access','disposed-fetch')]);g.render();
  const original=g.remote.getRequest.getMockImplementation()!;
  let entered!:()=>void,release!:()=>void;
  const started=new Promise<void>(resolve=>entered=resolve),gate=new Promise<void>(resolve=>release=resolve);
  g.remote.getRequest.mockImplementationOnce(async id=>{entered();await gate;return original(id);});
  let refreshing!:Promise<void>;act(()=>{refreshing=g.controller.refresh();});await started;
  g.controller.dispose();await act(async()=>{release();await refreshing;});
  expect(g.remote.markPrompted).not.toHaveBeenCalled();expect(g.remote.decide).not.toHaveBeenCalled();
});
it('keeps exact approval disabled when the immutable operation preview is unavailable', async () => {
  const f=fixture([request('access','missing-preview')]);
  const exact:CapabilitySnapshot={version:'domain-operation/1',capabilities:['identity:read','identity:http-auth'],signingPurposes:[],httpOrigins:['*']};
  const original=f.remote.getRequest.getMockImplementation()!;
  f.remote.getRequest.mockImplementation(async id=>{const result=await original(id);return {ok:true,value:{...result.value,snapshot:exact,snapshots:[{identity:identity.reference,snapshot:exact}]}};});
  render(<IdentityOverlay controller={f.controller}/>);await act(()=>f.controller.refresh());
  const dialog=screen.getByRole('dialog');
  expect(within(dialog).getByRole('button',{name:'允许本次操作'}).hasAttribute('disabled')).toBe(true);
  expect(within(dialog).getByRole('alert').textContent).toContain('操作摘要不可用');
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});
it('starts a foreground-triggered prompt queue once and removes its event handlers on disposal', async () => {
  vi.mocked(document.hasFocus).mockReturnValue(false);
  const f=fixture([request('access','focus-event')]);render(<IdentityOverlay controller={f.controller}/>);
  try {
    act(()=>{f.controller.start();f.controller.start();});
    await waitFor(()=>expect(f.remote.listRequests).toHaveBeenCalledOnce());
    expect(screen.queryByRole('dialog')).toBeNull();
    vi.mocked(document.hasFocus).mockReturnValue(true);fireEvent(window,new Event('focus'));
    await screen.findByRole('dialog');const calls=f.remote.listRequests.mock.calls.length;
    f.controller.dispose();fireEvent(window,new Event('focus'));
    await new Promise(resolve=>setTimeout(resolve,0));expect(f.remote.listRequests).toHaveBeenCalledTimes(calls);
  } finally { f.controller.dispose(); }
});

it('keeps Web disabled and submits an international phone only as E1', async () => {
  const f=fixture();f.render();await act(()=>f.controller.refresh());
  fireEvent.click(screen.getByRole('button',{name:'创建公共身份'}));
  expect((screen.getByLabelText('身份类型') as HTMLSelectElement).disabled).toBe(true);
  expect((screen.getByRole('option',{name:'Web（暂未开放）',hidden:true}) as HTMLOptionElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText('Handle'),{target:{value:'overseas-user'}});
  fireEvent.change(screen.getByLabelText('国家/地区码'),{target:{value:'international'}});
  fireEvent.change(screen.getByLabelText('注册手机号'),{target:{value:'+44 7700 900123'}});
  fireEvent.click(screen.getByRole('button',{name:'申请创建并注册'}));
  await waitFor(()=>expect(f.remote.startIdentityRegistration).toHaveBeenCalledWith(expect.objectContaining({phone:'+447700900123',profile:'e1'})));
  expect(f.remote.decide).not.toHaveBeenCalled();f.controller.dispose();
});
