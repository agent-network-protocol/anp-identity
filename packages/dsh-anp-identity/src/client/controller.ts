import type { RegistrationOnboardingInput, RegistrationOnboardingStatus } from '../registration-onboarding-types.js';
import type { RegistrationServiceSettings, UpdateRegistrationServiceSettings } from '../registration-service-types.js';
import type { OAuthClientIdentity } from "../publication-types.js";
import type { RegistrationBootstrapStatus } from '../registration-bootstrap.js';
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
} & {
  registrationOnboardingStatus?: () => Promise<RemoteResult<RegistrationOnboardingStatus>>;
  startIdentityRegistration?: (input: RegistrationOnboardingInput) => Promise<RemoteResult<unknown>>;
  dismissRegistrationRequest?: () => Promise<RemoteResult<null>>;
  registrationServiceSettings?: () => Promise<RemoteResult<RegistrationServiceSettings>>;
  configureRegistrationService?: (input: UpdateRegistrationServiceSettings) => Promise<RemoteResult<RegistrationServiceSettings>>;
  registrationBootstrapStatus?: () => Promise<RemoteResult<RegistrationBootstrapStatus[] | null>>;
  retryRegistrationSms?: () => Promise<RemoteResult<null>>;
  submitRegistrationOtp?: (input: { code: string }) => Promise<RemoteResult<null>>;
};
export type ManagerModal =
  | { readonly kind: "registration" }
  | { readonly kind: "registration-progress"; readonly requestId: string }
  | { readonly kind: "request"; readonly review: RequestReview }
  | { readonly kind: "result"; readonly review: RequestReview }
  | {
      readonly kind: "permissions" | "revoke";
      readonly grant: AuthorizationGrant;
      readonly identity: ManagedIdentitySummary;
    }
  | { readonly kind: "delete"; readonly identity: ManagedIdentitySummary };
export interface ManagerView {
  readonly onboarding: RegistrationOnboardingStatus | null;
  readonly registrationService: RegistrationServiceSettings | null;
  readonly loading: boolean;
  readonly bootstraps: readonly RegistrationBootstrapStatus[];
  readonly identities: readonly ManagedIdentitySummary[];
  readonly requests: readonly AuthorizationRequest[];
  readonly history: readonly AuthorizationRequest[];
  readonly selectedKey: string | null;
  readonly grants: readonly AuthorizationGrant[];
  readonly publication: OAuthClientIdentity | null;
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
  /** Submit the code only to the authenticated manager; never retain it in view state. */
  async submitRegistrationOtp(code: string): Promise<void> {
    await this.action(async () => {
      if (!this.remote.submitRegistrationOtp) throw new Error('SMS registration is unavailable');
      const result = await this.remote.submitRegistrationOtp({ code });
      if (!result.ok) throw new Error('SMS verification could not be submitted');
      await this.refresh();
    });
  }
  async retryRegistrationSms(): Promise<void> {
    await this.action(async () => {
      if (!this.remote.retryRegistrationSms) throw new Error('SMS retry is unavailable');
      const result = await this.remote.retryRegistrationSms();
      if (!result.ok) throw new Error('SMS retry could not be started');
      await this.refresh();
    });
  }
  private view: ManagerView = {
    onboarding: null,
    registrationService: null,
    loading: true,
    bootstraps: [],
    identities: [],
    requests: [],
    history: [],
    selectedKey: null,
    publication: null,
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
  private requestReviewEpoch = 0;
  private disposed = false;
  private readonly deferredRequests = new Set<string>();
  private readonly staleRequestIds = new Set<string>();
  private readonly presentedRequests = new Set<string>();
  private readonly inheritedPromptedRequests = new Set<string>();
  private requestsInitialized = false;
  private readonly onForeground = () => { void this.refresh(); };
  private selectionVersion = 0;
  private openedOnboardingIntent: string | undefined;
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
    if (this.timer || this.disposed) return;
    if (typeof window !== 'undefined') window.addEventListener('focus', this.onForeground);
    if (typeof document !== 'undefined') document.addEventListener('visibilitychange', this.onForeground);
    void this.refresh();
    this.timer = setInterval(() => {
      void this.refresh();
    }, 3000);
  }
  dispose(): void {
    this.disposed = true;
    clearInterval(this.timer);
    if (typeof window !== 'undefined') window.removeEventListener('focus', this.onForeground);
    if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', this.onForeground);
    this.listeners.clear();
  }
  async refresh(): Promise<void> {
    if (this.refreshing || this.disposed) return;
    this.refreshing = true;
    const reviewEpoch = this.requestReviewEpoch;
    try {
      const [identities, requests, bootstrapResult, settingsResult, onboardingResult] = await Promise.all([
        this.call("listIdentities"),
        this.call("listRequests", false),
        this.remote.registrationBootstrapStatus?.(),
        this.remote.registrationServiceSettings?.(),
        this.remote.registrationOnboardingStatus?.(),
      ]);
      if (reviewEpoch !== this.requestReviewEpoch) return;
      if (onboardingResult && !onboardingResult.ok) throw new Error('Unable to read identity onboarding status');
      if (settingsResult && !settingsResult.ok) throw new Error('Unable to read registration service settings');
      if (bootstrapResult && !bootstrapResult.ok) throw new Error('Unable to read protocol registration status');
      const pendingRequests = requests.filter(request => request.status === 'pending');
      const pendingKeys = new Set(pendingRequests.map(request => `${request.id}:${request.version}`));
      const pendingIds = new Set(pendingRequests.map(request => request.id));
      for (const entries of [this.deferredRequests, this.presentedRequests, this.inheritedPromptedRequests]) {
        for (const key of entries) if (!pendingKeys.has(key)) entries.delete(key);
      }
      for (const id of this.staleRequestIds) if (!pendingIds.has(id)) this.staleRequestIds.delete(id);
      if (!this.requestsInitialized) {
        for (const request of pendingRequests) if (request.prompted) this.inheritedPromptedRequests.add(`${request.id}:${request.version}`);
        this.requestsInitialized = true;
      }
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
        registrationService: settingsResult?.ok ? settingsResult.value : null,
        onboarding: onboardingResult?.ok ? onboardingResult.value : null,
        bootstraps: bootstrapResult?.ok ? bootstrapResult.value ?? [] : [],
        identities,
        requests: pendingRequests.sort((a, b) => b.createdAt - a.createdAt),
        selectedKey,
        ...(changed ? { publication: null, grants: [], document: null, documentOpen: false } : {}),
      });
      // Another tab may have decided the request while this review stayed open.
      // Never update its version silently or replay the user's approval.
      const modal = this.view.modal;
      if (modal?.kind === "request" && !this.view.pending &&
        !requests.some(r => r.id === modal.review.request.id &&
          r.status === "pending" && r.version === modal.review.request.version)) {
        this.closeStaleRequest();
      }
      await this.loadGrants();
      if (reviewEpoch !== this.requestReviewEpoch) return;
      const intent = this.view.onboarding?.intentId;
      if (intent && this.openedOnboardingIntent !== intent && !this.view.modal && !this.view.pending) {
        this.openedOnboardingIntent = intent;
        this.openRegistration();
      }
      if (this.view.modal === null && this.isForeground()) {
        const next = this.view.requests.find((r) => {
          const key = `${r.id}:${r.version}`;
          return (!r.prompted || !this.inheritedPromptedRequests.has(key)) && !this.presentedRequests.has(key)
            && !this.staleRequestIds.has(r.id) && !this.deferredRequests.has(key);
        });
        if (next) await this.openRequest(next.id, true);
      }
    } catch (error) {
      if (reviewEpoch !== this.requestReviewEpoch) return;
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
  openRegistration(): void {
    if (this.view.pending || this.view.modal || !this.view.onboarding?.available || this.view.onboarding.inProgress) return;
    this.captureFocus();
    this.patch({ modal: { kind: "registration" }, error: null });
  }
  async startIdentityRegistration(input: RegistrationOnboardingInput): Promise<void> {
    if (this.view.pending || !this.remote.startIdentityRegistration) return;
    this.patch({ pending: true, error: null });
    try {
      const result = await this.remote.startIdentityRegistration(input);
      if (!result.ok) {
        const error = result.error as {code?:string;message?:string};
        if (error.code === 'gateway/input-invalid' || error.message?.includes('input-invalid')) {
          this.patch({error:"表单格式校验未通过，本次未提交。请检查 Handle、国家码、手机号或邮箱。"}); return;
        }
        throw new Error("transport_unconfirmed");
      }
      const value = result.value as {status?:string;code?:string;phase?:string;requestId?:string};
      if (value?.status === "rejected") {
        const messages: Record<string,string> = {
          invalid_parameters:"表单格式校验未通过，本次未提交。请检查 Handle 和验证资料。",
          origin_changed:"注册服务地址已改变，本次未提交。请关闭表单、重新确认服务地址。",
          configuration_changed:"注册状态已在其他页面更新，请刷新后继续现有流程，不要另建。",
          registration_in_progress:"已有注册正在进行，请在身份管理中继续当前流程。",
          requester_unavailable:"身份创建入口尚未就绪，本次未提交。请刷新或检查插件是否启用。",
          save_unavailable:"无法保存注册资料，本次尚未申请创建。请检查服务状态后重试。",
        };
        this.patch({error:value.code && Object.hasOwn(messages,value.code) ? messages[value.code]! : "请求被拒绝，本次未提交。请刷新状态后检查表单。"}); return;
      }
      if (value?.status === "uncertain" || value?.phase !== "awaiting_approval" || typeof value.requestId !== "string") throw new Error("creation_unconfirmed");
      this.patch({ pending: false });
      this.deferredRequests.clear();
      this.closeModal(false);
      // Resume this exact owner-submitted flow; a background refresh may be busy.
      await this.openRequest(value.requestId);
      await this.refresh();
    } catch {
      this.patch({ error: "无法确认创建请求是否送达。请刷新身份管理查看当前状态，不要重复提交。" });
    } finally { this.patch({ pending: false }); }
  }
  async configureRegistrationService(origin: string, expectedVersion: number): Promise<boolean> {
    if (this.view.pending || !this.remote.configureRegistrationService) return false;
    this.patch({ pending: true, error: null });
    try {
      const result = await this.remote.configureRegistrationService({ origin, expectedVersion });
      if (!result.ok) throw new Error(result.error.message);
      this.patch({ registrationService: result.value, notice: "身份服务地址已保存，仅用于后续新注册；已有身份和正在进行的流程不会迁移。" });
      return true;
    } catch (error) {
      const conflict = error instanceof Error && error.message === 'registration_service_conflict';
      if (conflict) await this.refresh();
      this.patch({ error: conflict ? "配置已在其他页面更新，请刷新后重新确认。" : "保存失败，请填写不含路径、参数或账户信息的 HTTPS 服务根地址。" });
      return false;
    } finally { this.patch({ pending: false }); }
  }
  async selectIdentity(key: string): Promise<void> {
    this.selectionVersion++;
    this.patch({
      selectedKey: key,
      publication: null,
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
    const [grants, publication] = await Promise.all([
      this.call("grants", identityReference(selected)),
      selected.catalogState === "active" ? this.call("publicationStatus", identityReference(selected))
        .catch(() => ({state: "failed" as const, did: selected.reference.did})) : Promise.resolve(null),
    ]);
    if (this.view.selectedKey === key) {
      this.patch({ publication, grants: grants.filter((g) => g.status === "active") });
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
  private isForeground(): boolean {
    return typeof document === 'undefined' || document.visibilityState !== 'hidden' && document.hasFocus();
  }
  private captureFocus(): void {
    if (typeof document !== "undefined")
      this.returnFocus =
        document.activeElement instanceof HTMLElement
          ? document.activeElement
          : null;
  }
  async openRequest(id: string, automatic = false): Promise<void> {
    if (this.disposed || this.view.modal !== null || this.view.pending || automatic && !this.isForeground()) return;
    this.requestReviewEpoch++;
    this.captureFocus();
    this.patch({ pending: true, error: null });
    try {
      const review = await this.call("getRequest", id);
      if (review.request.status !== "pending") {
        await this.refresh();
        return;
      }
      if (this.disposed || automatic && !this.isForeground()) return;
      await this.call("markPrompted", {
        requestId: id,
        expectedVersion: review.request.version,
      });
      if (this.disposed || automatic && !this.isForeground()) return;
      this.presentedRequests.add(`${id}:${review.request.version}`);
      this.patch({
        modal: { kind: "request", review },
        requests: this.view.requests.map((r) =>
          r.id === id ? { ...r, prompted: true } : r,
        ),
      });
      if (!automatic) { this.deferredRequests.clear(); this.staleRequestIds.delete(id); }
    } catch (error) {
      this.fail(error);
    } finally {
      this.patch({ pending: false });
    }
  }
  openRegistrationProgress(requestId: string): void {
    if (this.view.pending || !this.view.bootstraps.some(flow => flow.requestId === requestId)) return;
    this.captureFocus();
    this.requestReviewEpoch++;
    this.patch({ modal: { kind: "registration-progress", requestId }, error: null });
  }
  closeModal(later = true): void {
    if (this.view.pending) return;
    if (later && this.view.modal?.kind === "registration") {
      void this.remote.dismissRegistrationRequest?.().catch(() => {});
    }
    if (later) for (const request of this.view.requests) this.deferredRequests.add(`${request.id}:${request.version}`);
    this.patch({ modal: null, error: null });
    const focus = this.returnFocus;
    queueMicrotask(() => {
      if (focus?.isConnected) focus.focus();
    });
  }
  private closeStaleRequest(): void {
    if (this.view.modal?.kind === "request") this.staleRequestIds.add(this.view.modal.review.request.id);
    this.patch({ pending: false });
    this.closeModal(false);
    this.patch({ notice: "此授权请求已处理、已过期或已变更，旧弹窗已关闭。请查看授权请求的最新状态；不会自动重复授权。" });
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
      if (result.kind === "create" && result.status === "approved" &&
        this.view.bootstraps.some(flow => flow.requestId === result.id)) {
        // Keep the owner in the registration flow while the private bootstrap advances.
        this.requestReviewEpoch++;
        this.patch({ modal: { kind: "registration-progress", requestId: result.id } });
      } else {
        this.closeModal(false);
      }
      await this.refresh();
    } catch (error) {
      if (error instanceof Error && ["request_conflict", "request_not_pending", "request_not_found"].includes(error.message)) {
        this.closeStaleRequest();
        await this.refresh();
      } else {
        this.fail(error);
      }
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
  async retryPublication(): Promise<void> {
    const selected = this.selected();
    if (!selected || this.view.pending) return;
    this.patch({pending: true, error: null});
    try {
      await this.call("retryPublication", identityReference(selected));
      await this.refresh();
    } catch {
      this.patch({error: "身份发布尚未完成，请检查身份托管配置后重试。"});
    } finally { this.patch({pending: false}); }
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
