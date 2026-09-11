import type { RemoteResult } from "@deepseek-ai/dsh-typert-protocol";
import type { IdentityReference } from "@agent-network-protocol/anp-identity";
import type {
  AuthorizationDecision,
  AuthorizationGrant,
  AuthorizationRequest,
} from "../authorization-types.js";
import type {
  IdentityManagement,
  ManagedIdentitySummary,
  RequestReview,
} from "../management-types.js";

export type ManagementRemote = {
  [K in keyof IdentityManagement]: (
    ...args: Parameters<IdentityManagement[K]>
  ) => Promise<RemoteResult<Awaited<ReturnType<IdentityManagement[K]>> | null>>;
};
export type ManagerModal =
  | { readonly kind: "request"; readonly review: RequestReview }
  | { readonly kind: "result"; readonly review: RequestReview }
  | {
      readonly kind: "permissions" | "revoke";
      readonly grant: AuthorizationGrant;
      readonly identity: ManagedIdentitySummary;
    }
  | { readonly kind: "delete"; readonly identity: ManagedIdentitySummary };
export interface ManagerView {
  readonly loading: boolean;
  readonly identities: readonly ManagedIdentitySummary[];
  readonly requests: readonly AuthorizationRequest[];
  readonly history: readonly AuthorizationRequest[];
  readonly selectedKey: string | null;
  readonly grants: readonly AuthorizationGrant[];
  readonly document: string | null;
  readonly documentOpen: boolean;
  readonly modal: ManagerModal | null;
  readonly pending: boolean;
  readonly error: string | null;
  readonly notice: string | null;
}
export const identityKey = (ref: IdentityReference): string =>
  JSON.stringify([ref.storeId, ref.identityId, ref.did]);
export const identityReference = (
  identity: ManagedIdentitySummary,
): IdentityReference => identity.reference;

/** One shared controller owns both settings and overlay; remounts cannot duplicate prompts. */
export class IdentityController {
  private view: ManagerView = {
    loading: true,
    identities: [],
    requests: [],
    history: [],
    selectedKey: null,
    grants: [],
    document: null,
    documentOpen: false,
    modal: null,
    pending: false,
    error: null,
    notice: null,
  };
  private listeners = new Set<() => void>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private refreshing = false;
  private disposed = false;
  private pauseQueue = false;
  private selectionVersion = 0;
  private returnFocus: HTMLElement | null = null;
  getSnapshot = (): ManagerView => this.view;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  constructor(private readonly remote: ManagementRemote) {}
  private patch(value: Partial<ManagerView>): void {
    if (this.disposed) return;
    this.view = { ...this.view, ...value };
    for (const listener of this.listeners) listener();
  }
  private async call<K extends keyof IdentityManagement>(
    method: K,
    ...args: Parameters<IdentityManagement[K]>
  ): Promise<Awaited<ReturnType<IdentityManagement[K]>>> {
    const result = await (
      this.remote[method] as (
        ...values: Parameters<IdentityManagement[K]>
      ) => Promise<RemoteResult<unknown>>
    )(...args);
    if (!result.ok) throw new Error(result.error.message);
    return result.value as Awaited<ReturnType<IdentityManagement[K]>>;
  }
  start(): void {
    void this.refresh();
    this.timer = setInterval(() => {
      void this.refresh();
    }, 3000);
  }
  dispose(): void {
    this.disposed = true;
    clearInterval(this.timer);
    this.listeners.clear();
  }
  async refresh(): Promise<void> {
    if (this.refreshing || this.disposed) return;
    this.refreshing = true;
    try {
      const [identities, requests] = await Promise.all([
        this.call("listIdentities"),
        this.call("listRequests", false),
      ]);
      const selectedKey = identities.some(
        (i) => identityKey(identityReference(i)) === this.view.selectedKey,
      )
        ? this.view.selectedKey
        : identities[0]
          ? identityKey(identityReference(identities[0]))
          : null;
      const changed = selectedKey !== this.view.selectedKey;
      this.patch({
        loading: false,
        identities,
        requests: requests
          .filter((r) => r.status === "pending")
          .sort((a, b) => b.createdAt - a.createdAt),
        selectedKey,
        ...(changed ? { grants: [], document: null, documentOpen: false } : {}),
      });
      await this.loadGrants();
      if (!this.pauseQueue && this.view.modal === null) {
        const next = this.view.requests.find((r) => !r.prompted);
        if (next) await this.openRequest(next.id, true);
      }
    } catch (error) {
      this.patch({
        loading: false,
        error:
          error instanceof Error
            ? error.message
            : "Unable to load identity management",
      });
    } finally {
      this.refreshing = false;
    }
  }
  async selectIdentity(key: string): Promise<void> {
    this.selectionVersion++;
    this.patch({
      selectedKey: key,
      grants: [],
      document: null,
      documentOpen: false,
      error: null,
    });
    try {
      await this.loadGrants();
    } catch (error) {
      this.fail(error);
    }
  }
  selected(): ManagedIdentitySummary | undefined {
    return this.view.identities.find(
      (i) => identityKey(identityReference(i)) === this.view.selectedKey,
    );
  }
  private async loadGrants(): Promise<void> {
    const selected = this.selected();
    if (!selected) return;
    const key = this.view.selectedKey;
    const grants = await this.call("grants", identityReference(selected));
    if (this.view.selectedKey === key) {
      this.patch({ grants: grants.filter((g) => g.status === "active") });
      const modal = this.view.modal;
      if (
        (modal?.kind === "permissions" || modal?.kind === "revoke") &&
        !grants.some(
          (g) =>
            g.id === modal.grant.id &&
            g.status === "active" &&
            g.version === modal.grant.version,
        )
      ) {
        this.closeModal();
        this.patch({ notice: "该授权已失效。" });
      }
    }
  }
  private captureFocus(): void {
    if (typeof document !== "undefined")
      this.returnFocus =
        document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null;
  }
  async openRequest(id: string, automatic = false): Promise<void> {
    if (this.view.modal !== null || this.view.pending) return;
    this.captureFocus();
    this.patch({ pending: true, error: null });
    try {
      const review = await this.call("getRequest", id);
      if (review.request.status !== "pending") {
        await this.refresh();
        return;
      }
      await this.call("markPrompted", {
        requestId: id,
        expectedVersion: review.request.version,
      });
      this.patch({
        modal: { kind: "request", review },
        requests: this.view.requests.map((r) =>
          r.id === id ? { ...r, prompted: true } : r,
        ),
      });
      if (!automatic) this.pauseQueue = false;
    } catch (error) {
      this.fail(error);
    } finally {
      this.patch({ pending: false });
    }
  }
  closeModal(later = true): void {
    if (this.view.pending) return;
    if (later) this.pauseQueue = true;
    this.patch({ modal: null, error: null });
    const focus = this.returnFocus;
    queueMicrotask(() => {
      if (focus?.isConnected) focus.focus();
    });
  }
  async decide(
    decision: Omit<AuthorizationDecision, "requestId" | "expectedVersion">,
  ): Promise<void> {
    const modal = this.view.modal;
    if (modal?.kind !== "request" || this.view.pending) return;
    this.patch({ pending: true, error: null });
    try {
      const result = await this.call("decide", {
        ...decision,
        requestId: modal.review.request.id,
        expectedVersion: modal.review.request.version,
      });
      this.patch({
        pending: false,
        notice:
          result.kind === "create" && result.executionStatus === "succeeded"
            ? "身份已创建，尚未发布身份文档。"
            : result.kind === "create" && result.status === "approved"
              ? "创建结果待核对，请查看已处理请求；不要重复创建。"
              : null,
      });
      this.closeModal(false);
      await this.refresh();
    } catch (error) {
      this.fail(error);
    } finally {
      this.patch({ pending: false });
    }
  }
  async openPermissions(grantId: string): Promise<void> {
    await this.openGrantModal(grantId, "permissions");
  }
  async openRevoke(grantId: string): Promise<void> {
    await this.openGrantModal(grantId, "revoke");
  }
  private async openGrantModal(grantId: string, kind: "permissions" | "revoke"): Promise<void> {
    if (this.view.modal || this.view.pending) return;
    this.captureFocus();
    try {
      await this.loadGrants();
      const grant = this.view.grants.find((g) => g.id === grantId);
      const identity = this.selected();
      if (!grant || !identity)
        throw new Error("The authorization is no longer active");
      this.patch({
        modal: { kind, grant, identity },
        error: null,
      });
    } catch (error) {
      this.fail(error);
    }
  }
  async revoke(): Promise<void> {
    const modal = this.view.modal;
    if (modal?.kind !== "revoke") return;
    const grant = modal.grant;
    await this.action(async () => {
      await this.call("revoke", {
        grantId: grant.id,
        expectedVersion: grant.version,
      });
      this.patch({ pending: false });
      this.closeModal();
      await this.refresh();
    });
  }
  openDelete(): void {
    const identity = this.selected();
    if (
      !identity ||
      this.view.modal ||
      identity.deleteBlockedReason ||
      this.view.grants.length ||
      identity.integrations.length
    )
      return;
    this.captureFocus();
    this.patch({ modal: { kind: "delete", identity }, error: null });
  }
  async deleteIdentity(confirmationName: string): Promise<void> {
    const modal = this.view.modal;
    if (modal?.kind !== "delete") return;
    await this.action(async () => {
      await this.call("deleteIdentity", {
        reference: identityReference(modal.identity),
        confirmationName,
      });
      this.patch({ pending: false });
      this.closeModal();
      await this.refresh();
    });
  }
  async toggleDocument(): Promise<void> {
    if (this.view.documentOpen) {
      this.patch({ documentOpen: false, document: null });
      return;
    }
    const identity = this.selected();
    if (!identity) return;
    const version = this.selectionVersion;
    const key = this.view.selectedKey;
    try {
      const value = await this.call(
        "publicDocument",
        identityReference(identity),
      );
      if (this.selectionVersion === version && this.view.selectedKey === key)
        this.patch({
          document: JSON.stringify(value, null, 2),
          documentOpen: true,
        });
    } catch (error) {
      this.fail(error);
    }
  }
  async loadHistory(): Promise<void> {
    try {
      this.patch({ history: await this.call("listRequests", true) });
    } catch (error) {
      this.fail(error);
    }
  }
  async openResult(requestId: string): Promise<void> {
    if (this.view.modal || this.view.pending) return;
    this.captureFocus();
    await this.action(async () => {
      const review = await this.call("getRequest", requestId);
      this.patch({
        modal: { kind: "result", review },
        history: this.view.history.map((request) =>
          request.id === requestId ? review.request : request,
        ),
      });
    });
  }
  async reauthorize(request: AuthorizationRequest): Promise<void> {
    await this.action(async () => {
      const next = await this.call("reauthorize", {
        requestId: request.id,
        expectedVersion: request.version,
      });
      this.patch({ pending: false });
      await this.openRequest(next.id);
      await this.refresh();
    });
  }
  async copy(value: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      this.patch({ notice: "已复制" });
    } catch {
      this.patch({ error: "无法复制，请检查剪贴板权限。" });
    }
  }
  private fail(error: unknown): void {
    this.patch({
      error:
        error instanceof Error ? error.message : "Identity management failed",
    });
  }
  private async action(operation: () => Promise<void>): Promise<void> {
    if (this.view.pending) return;
    this.patch({ pending: true, error: null });
    try {
      await operation();
    } catch (error) {
      this.fail(error);
    } finally {
      this.patch({ pending: false });
    }
  }
}
