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
import type {} from "@deepseek-ai/dsh-typert-registry";

export class IdentityManagerRemote extends TypertRemoteService {
  static inject = ["anpIdentity", "typert"];
  private readonly manager: IdentityManagement;
  constructor(ctx: Context) {
    super(ctx, "anpIdentityManager");
    const service = ctx.root.get("anpIdentity") as unknown as {
      acquireManagement(): IdentityManagement;
    };
    this.manager = service.acquireManagement();
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
