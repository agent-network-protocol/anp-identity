import { createHash } from 'node:crypto';
import type { UpdateRegistrationServiceSettings } from './registration-service-types.js';
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
  constructor(ctx: Context, config: Config = {}) {
    super(ctx, "anpIdentityManager");
    const service = ctx.anpIdentity as unknown as {
      acquireManagement(context: Context): IdentityManagement;
    };
    this.managerContext = ctx;
    const manager = service.acquireManagement(ctx);
    this.manager = manager;
    let disposed = false;
    this.bootstrapReady = (async () => {
      if (config.registrationBootstrap === undefined) return;
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
