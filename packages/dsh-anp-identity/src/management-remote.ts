import { randomUUID } from 'node:crypto';
import { registerIdentityGuidance } from './agent-guidance.js';
import { registerConfigurationTools } from './configuration-tools.js';
import { RegistrationOnboardingStore, type SavedRegistrationOnboarding } from './registration-onboarding.js';
import { registrationInputSchema, type RegistrationOnboardingInput } from './registration-onboarding-types.js';
import { createHash } from 'node:crypto';
import type { UpdateRegistrationServiceSettings } from './registration-service-types.js';
import type { UpdateProtocolPolicy } from './protocol-policy-types.js';
import type { UpdateDefaultIdentity } from './default-identity-types.js';
import type { PublicationConfig } from './publication-types.js';
/** Optional Host manager boundary. Never expose this service to consumer leases. */
import type { Context } from "@deepseek-ai/cordis";
import { Remote, TypertRemoteService } from "@deepseek-ai/dsh-typert-protocol";
import type { IdentityReference } from "@agent-network-protocol/anp-identity";
import type { AuthorizationDecision } from "./authorization-types.js";
import type {
  IdentityManagement,
  RequestVersion,
  RevokeGrantInput,
  DeleteManagedIdentityInput,
} from "./management-types.js";
import contribution from "./remote.js";
import z from '@deepseek-ai/schemastery';
import type AnpIdentityService from './index.js';
import { RegistrationBootstrapConfigSchema, startRegistrationBootstrap } from './registration-bootstrap.js';
import type { RegistrationBootstrapInput, RegistrationBootstrapController } from './registration-bootstrap.js';
import type {} from "@deepseek-ai/dsh-typert-registry";

export interface Config { registrationBootstrap?: RegistrationBootstrapInput }
export const Config: z<Config> = z.object({ registrationBootstrap: z.any() });

export class IdentityManagerRemote extends TypertRemoteService {
  static inject = ["anpIdentity", "typert"];
  static Config = Config;
  private readonly manager: IdentityManagement;
  private readonly managerContext: Context;
  private bootstrap: RegistrationBootstrapController | undefined;
  private readonly bootstrapReady: Promise<void>;
  private bootstrapError: Error | undefined;
  private readonly onboardingStore: RegistrationOnboardingStore | undefined;
  private readonly configuredBootstrap: boolean;
  private onboardingVersion = 0;
  private onboardingIntent: string | undefined;
  private startingRegistration = false;
  constructor(ctx: Context, config: Config = {}) {
    super(ctx, "anpIdentityManager");
    const service = ctx.anpIdentity as unknown as {
      acquireManagement(context: Context): IdentityManagement;
    };
    this.managerContext = ctx;
    const manager = service.acquireManagement(ctx);
    this.manager = manager;
    this.configuredBootstrap = config.registrationBootstrap !== undefined;
    const identityService = ctx.anpIdentity as AnpIdentityService;
    registerConfigurationTools(ctx, {
      assertOwner: () => { (ctx.anpIdentity as AnpIdentityService).acquireManagement(ctx); },
      protocols: () => (ctx.anpIdentity as AnpIdentityService).protocolManagement(ctx),
      setProtocols: (input, check) => (ctx.anpIdentity as AnpIdentityService).configureProtocolPolicy(ctx, input, check),
      identity: async () => {
        const [defaultIdentity, registrationService, status] = await Promise.all([
          (ctx.anpIdentity as AnpIdentityService).defaultIdentity(ctx),
          (ctx.anpIdentity as AnpIdentityService).registrationServiceSettings(ctx), this.publicIdentityStatus(),
        ]);
        return { defaultIdentity, registrationService, identities: status.identities };
      },
      setDefault: (input, check) => (ctx.anpIdentity as AnpIdentityService).configureDefaultIdentity(ctx, input, check),
      setRegistration: (input, check) => (ctx.anpIdentity as AnpIdentityService).configureRegistrationService(ctx, input, check),
    });
    this.onboardingStore = typeof identityService.registrationBootstrapRoot === 'function'
      ? new RegistrationOnboardingStore(identityService.registrationBootstrapRoot(ctx)) : undefined;
    registerIdentityGuidance(ctx, { status: () => this.publicIdentityStatus(), request: async () => {
      await this.bootstrapReady;
      if (this.onboardingVersion > 0 && !this.bootstrap) return { status: 'recovery_required', action: '打开身份管理完成或恢复当前注册；不要重复创建。' };
      const phase = this.bootstrap?.status().phase;
      if (phase && !['published','disposed'].includes(phase)) {
        const requestId = this.bootstrap!.status().requestId;
        const pending = phase === 'awaiting_approval' && (await this.manager.getRequest(requestId)).request.status === 'pending';
        return { status: phase, requestId, action: pending ? '打开 设置 → 身份管理 → 继续创建审批。审批前不会发送验证码，不要重复创建。'
          : phase === 'awaiting_approval' ? '创建正在处理或结果待核对，请在身份管理刷新状态，不要重复创建。'
          : '打开 设置 → 身份管理 完成当前流程，不要重复创建。' };
      }
      if (!this.onboardingStore || this.configuredBootstrap || !ctx.get('anpIdentityRequester')?.available(ctx))
        return { status: 'not_configured', action: '身份创建请求器未就绪，请用户启用身份插件的内置创建入口。不要查源码、密钥目录或其他 CLI。' };
      this.onboardingIntent ??= randomUUID();
      return { status: 'awaiting_user_input', intentId: this.onboardingIntent,
        action: '已请求打开 设置 → 身份管理 → 创建公共身份。请用户在页面填写 Handle 和手机号/邮箱，并确认审批。不要在聊天收集验证码，不要运行 CLI 或搜索文件。' };
    } });
    let disposed = false;
    this.bootstrapReady = (async () => {
      if (config.registrationBootstrap === undefined) {
        const saved = await this.onboardingStore?.read(() => { (this.managerContext.anpIdentity as AnpIdentityService).acquireManagement(this.managerContext); });
        if (saved) {
          this.onboardingVersion = saved.version;
          await this.ensureCreationRequest(saved);
          if (!disposed) this.bootstrap = startRegistrationBootstrap({ context: ctx, service: identityService, manager, config: saved.config });
        }
        return;
      }
      const input = RegistrationBootstrapConfigSchema.parse(config.registrationBootstrap);
      if (config.registrationBootstrap.origin === undefined) {
        const { origin: _origin, ...rest } = input;
        const digest = (value: string) => createHash('sha256').update(value).digest('hex');
        input.origin = await (ctx.anpIdentity as AnpIdentityService).resolveRegistrationServiceOrigin(
          ctx, digest(input.id + '\0' + input.requestId), digest(JSON.stringify(rest)));
      }
      if (!disposed) this.bootstrap = startRegistrationBootstrap({
        context: ctx, service: ctx.anpIdentity as AnpIdentityService, manager, config: input,
      });
    })();
    void this.bootstrapReady.catch(() => { this.bootstrapError = new Error('registration_service_settings_unavailable'); });
    ctx.effect(() => () => { disposed = true; return this.bootstrap?.dispose(); }, 'anp-identity: registration bootstrap');
    ctx.effect(() =>
      ctx.typert.register({
        package: contribution.package,
        face: "host",
        schemas: [],
        model: { services: [], events: [], objects: [] },
        invocations: contribution.descriptors,
      }),
    );
  }
  private async ensureCreationRequest(saved: SavedRegistrationOnboarding): Promise<void> {
    const deadline = Date.now() + 10000;
    for (;;) {
      (this.managerContext.anpIdentity as AnpIdentityService).acquireManagement(this.managerContext);
      const requester = this.managerContext.get('anpIdentityRequester');
      if (requester) {
        await requester.request(this.managerContext, { requestId: saved.config.requestId,
          purpose: 'Create public identity ' + saved.parameters.handle + ' for third-party MCP/ANP/PAP access; registration and publication require user verification.',
          parameters: saved.parameters });
        return;
      }
      if (Date.now() > deadline) throw new Error('registration_requester_unavailable');
      await new Promise(resolve => setTimeout(resolve, 100));
    }
  }
  private async publicIdentityStatus() {
    await this.bootstrapReady;
    const settings = await (this.managerContext.anpIdentity as AnpIdentityService).registrationServiceSettings(this.managerContext);
    const identities = await this.manager.listIdentities();
    const publicIdentities = await Promise.all(identities.map(async identity => {
      const publication = await this.manager.publicationStatus(identity.reference);
      return { label: identity.label ?? identity.handle ?? identity.reference.did, reference: identity.reference,
        state: publication.state, mcpMachine: publication.state === 'published' && Boolean(publication.capabilities?.mcpMachine),
        papSession: publication.state === 'published' && Boolean(publication.capabilities?.papSession) };
    }));
    return { registrationService: settings.origin, identities: publicIdentities,
      registrationPhase: this.bootstrap?.status().phase ?? 'not_started',
      ...(this.bootstrap ? { registrationRequestId: this.bootstrap.status().requestId } : {}),
      action: '创建公共身份请用 identity_request_creation；协议访问请用 identity_connection_guide。不要搜索源码、凭据或其他 CLI。' };
  }
  @Remote async registrationOnboardingStatus() {
    await this.bootstrapReady;
    return { ...(this.onboardingIntent ? { intentId: this.onboardingIntent } : {}),
      available: Boolean(this.onboardingStore) && !this.configuredBootstrap && Boolean(this.managerContext.get('anpIdentityRequester')?.available(this.managerContext)),
      version: this.onboardingVersion, inProgress: Boolean(this.onboardingVersion > 0 && !this.bootstrap || this.bootstrap && !['published','disposed'].includes(this.bootstrap.status().phase)) };
  }
  @Remote dismissRegistrationRequest() { this.onboardingIntent = undefined; return null; }
  @Remote protocolManagement() {
    return (this.managerContext.anpIdentity as AnpIdentityService).protocolManagement(this.managerContext);
  }
  @Remote configureProtocolPolicy(input: UpdateProtocolPolicy) {
    return (this.managerContext.anpIdentity as AnpIdentityService).configureProtocolPolicy(this.managerContext, input);
  }
  @Remote defaultIdentity() {
    return (this.managerContext.anpIdentity as AnpIdentityService).defaultIdentity(this.managerContext);
  }
  @Remote configureDefaultIdentity(input: UpdateDefaultIdentity) {
    return (this.managerContext.anpIdentity as AnpIdentityService).configureDefaultIdentity(this.managerContext, input);
  }
  @Remote async startIdentityRegistration(raw: RegistrationOnboardingInput) {
    if (!this.onboardingStore || this.configuredBootstrap) return { status:'rejected', code:'requester_unavailable' };
    if (this.startingRegistration) return { status:'rejected', code:'registration_in_progress' };
    this.startingRegistration = true;
    let savedForThisRequest = false;
    try {
      await this.bootstrapReady;
      if (this.onboardingVersion > 0 && !this.bootstrap || this.bootstrap && !['published','disposed'].includes(this.bootstrap.status().phase)) return { status:'rejected', code:'registration_in_progress' };
      const parsed = registrationInputSchema.safeParse(raw);
      if (!parsed.success) return { status:'rejected', code:'invalid_parameters' };
      const input = parsed.data;
      if (!this.managerContext.get('anpIdentityRequester')?.available(this.managerContext)) return { status:'rejected', code:'requester_unavailable' };
      const service = this.managerContext.anpIdentity as AnpIdentityService;
      const settings = await service.registrationServiceSettings(this.managerContext);
      const saved = await this.onboardingStore.create(input, settings.origin, () => { service.acquireManagement(this.managerContext); });
      this.onboardingVersion = saved.version;
      savedForThisRequest = true;
      await this.ensureCreationRequest(saved);
      await this.bootstrap?.dispose();
      this.bootstrap = startRegistrationBootstrap({ context: this.managerContext, service, manager: this.manager, config: saved.config });
      this.onboardingIntent = undefined;
      return { status:'awaiting_approval', requestId: saved.config.requestId, phase: 'awaiting_approval', origin: saved.config.origin };
    } catch (error) {
      const message = error instanceof Error ? error.message : '';
      if (!savedForThisRequest) return { status:'rejected', code: message === 'registration_onboarding_origin_changed' ? 'origin_changed'
        : message === 'registration_onboarding_conflict' ? 'configuration_changed' : 'save_unavailable' };
      return { status:'uncertain', code:'creation_request_unconfirmed' };
    } finally { this.startingRegistration = false; }
  }
  @Remote registrationBootstrapStatus() { if (this.bootstrapError) throw this.bootstrapError; return this.bootstrap ? [this.bootstrap.status()] : []; }
  @Remote registrationServiceSettings() { return (this.managerContext.anpIdentity as AnpIdentityService).registrationServiceSettings(this.managerContext); }
  @Remote configureRegistrationService(input: UpdateRegistrationServiceSettings) { return (this.managerContext.anpIdentity as AnpIdentityService).configureRegistrationService(this.managerContext, input); }
  /** Accept a user-entered SMS code without persisting or returning it. */
  @Remote async submitRegistrationOtp(input: { code: string }) {
    await this.bootstrapReady;
    if (!this.bootstrap) throw new Error('bootstrap_otp_unavailable');
    this.bootstrap.submitOtp(input.code);
    return null;
  }
  /** Owner-only retry; an uncertain registration must never be replayed. */
  @Remote async retryRegistrationSms() {
    await this.bootstrapReady;
    const status = this.bootstrap?.status();
    if (this.startingRegistration || this.configuredBootstrap || !this.onboardingStore || !status
      || status.phase !== 'blocked' || !['phone_unavailable','client_upgrade_required'].includes(status.reason ?? '')) {
      throw new Error('bootstrap_phone_retry_unavailable');
    }
    this.startingRegistration = true;
    try {
      const service = this.managerContext.anpIdentity as AnpIdentityService;
      const saved = await this.onboardingStore.read(() => { service.acquireManagement(this.managerContext); });
      if (!saved?.config.phone || saved.config.requestId !== status.requestId) throw new Error('bootstrap_phone_retry_unavailable');
      await this.bootstrap!.dispose();
      this.bootstrap = startRegistrationBootstrap({context:this.managerContext, service, manager:this.manager,
        config:saved.config, retryPhoneChallenge:true});
      return null;
    } finally { this.startingRegistration = false; }
  }
  @Remote listIdentities() {
    return this.manager.listIdentities();
  }
  @Remote listRequests(input?: boolean) {
    return this.manager.listRequests(input);
  }
  @Remote getRequest(input: string) {
    return this.manager.getRequest(input);
  }
  @Remote decide(input: AuthorizationDecision) {
    return this.manager.decide(input);
  }
  @Remote grants(input: IdentityReference) {
    return this.manager.grants(input);
  }
  @Remote async revoke(input: RevokeGrantInput) {
    await this.manager.revoke(input);
    return null;
  }
  @Remote retryPublication(input: IdentityReference) { return this.manager.retryPublication(input); }
  @Remote publicationStatus(input: IdentityReference) { return this.manager.publicationStatus(input); }
  @Remote publishIdentity(input: { reference: IdentityReference; config: PublicationConfig }) {
    return this.manager.publishIdentity(input);
  }
  @Remote publicDocument(input: IdentityReference) {
    return this.manager.publicDocument(input);
  }
  @Remote async deleteIdentity(input: DeleteManagedIdentityInput) {
    await this.manager.deleteIdentity(input);
    return null;
  }
  @Remote async markPrompted(input: RequestVersion) {
    await this.manager.markPrompted(input);
    return null;
  }
  @Remote reauthorize(input: RequestVersion) {
    return this.manager.reauthorize(input);
  }
}
export default IdentityManagerRemote;
