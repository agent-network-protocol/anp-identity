import type { IdentityReference } from "@agent-network-protocol/anp-identity";
import type {
  AuthorizationDecision,
  AuthorizationGrant,
  AuthorizationRequest,
  CapabilitySnapshot,
} from "./authorization-types.js";
import type { IdentityDescriptor } from "./types.js";

/** Public manager presentation. This never carries a native lease or credentials. */
export interface ManagedIdentitySummary extends IdentityDescriptor {
  readonly integrations: readonly {
    readonly consumer: string;
    readonly displayName: string;
    readonly kind: "legacy" | "provider";
  }[];
  readonly deleteBlockedReason?: string;
}
export interface RequestReview {
  readonly request: AuthorizationRequest;
  readonly grant?: AuthorizationGrant;
  readonly identities: readonly ManagedIdentitySummary[];
  readonly snapshot?: CapabilitySnapshot;
  readonly permanentIdentities?: readonly IdentityReference[];
  readonly snapshots?: readonly {
    readonly identity: IdentityReference;
    readonly snapshot: CapabilitySnapshot;
  }[];
  readonly unavailableReason?: string;
}
export interface RequestVersion {
  readonly requestId: string;
  readonly expectedVersion: number;
}
export interface RevokeGrantInput {
  readonly grantId: string;
  readonly expectedVersion: number;
}
export interface DeleteManagedIdentityInput {
  readonly reference: IdentityReference;
  readonly confirmationName: string;
}
/** Host-only manager capability. Ordinary consumer facades must not return this object. */
export interface IdentityManagement {
  listIdentities(): Promise<ManagedIdentitySummary[]>;
  listRequests(history?: boolean): Promise<AuthorizationRequest[]>;
  getRequest(requestId: string): Promise<RequestReview>;
  decide(input: AuthorizationDecision): Promise<AuthorizationRequest>;
  grants(reference: IdentityReference): Promise<AuthorizationGrant[]>;
  revoke(input: RevokeGrantInput): Promise<void>;
  publicDocument(reference: IdentityReference): Promise<unknown>;
  deleteIdentity(input: DeleteManagedIdentityInput): Promise<void>;
  markPrompted(input: RequestVersion): Promise<void>;
  reauthorize(input: RequestVersion): Promise<AuthorizationRequest>;
}
