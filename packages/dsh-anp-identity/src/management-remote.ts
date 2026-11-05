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
  private readonly bootstrap: RegistrationBootstrapController | undefined;
  constructor(ctx: Context, config: Config = {}) {
    super(ctx, "anpIdentityManager");
    const service = ctx.anpIdentity as unknown as {
      acquireManagement(context: Context): IdentityManagement;
    };
    this.manager = service.acquireManagement(ctx);
    this.bootstrap = config.registrationBootstrap === undefined ? undefined : startRegistrationBootstrap({
      context: ctx, service: ctx.anpIdentity as AnpIdentityService, manager: this.manager,
      config: RegistrationBootstrapConfigSchema.parse(config.registrationBootstrap),
    });
    ctx.effect(() => () => this.bootstrap?.dispose(), 'anp-identity: registration bootstrap');
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
  @Remote registrationBootstrapStatus() { return this.bootstrap ? [this.bootstrap.status()] : []; }
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
