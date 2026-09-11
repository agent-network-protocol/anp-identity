import type { Context } from '@deepseek-ai/cordis'
import type { PublicIdentity, SignRequest, Signature, IdentityReference } from './types.js'
import type { AuthorizationRequest, AuthorizationExecution, RequestCreateInput } from './authorization-types.js'

/** Raw operation input. The Host computes the fingerprint; consumers cannot supply one. */
export type UserOperation =
  | { readonly action: 'read' }
  | { readonly action: 'sign'; readonly request: SignRequest }
  | { readonly action: 'http'; readonly request: Request }

export interface UserAccessRequest {
  readonly requestId: string
  readonly purpose: string
  readonly identity?: IdentityReference
  readonly operation?: UserOperation
}

/** A caller- and identity-bound object with no management or Provider methods. */
export interface AuthorizedIdentity {
  publicIdentity(executionId?: string): Promise<PublicIdentity>
  sign(request: SignRequest, executionId?: string): Promise<Signature>
  readonly authenticatedHttp: {
    dispatch(request: Request, executionId?: string): Promise<Response>
  }
}

export interface UserIdentityClient {
  requestCreateIdentity(input: RequestCreateInput): Promise<AuthorizationRequest>
  getCreateRequest(requestId: string): Promise<AuthorizationRequest>
  cancelCreateRequest(requestId: string, expectedVersion: number): Promise<AuthorizationRequest>
  requestAccess(input: UserAccessRequest): Promise<AuthorizationRequest>
  getAccessRequest(requestId: string): Promise<AuthorizationRequest>
  cancelAccessRequest(requestId: string, expectedVersion: number): Promise<AuthorizationRequest>
  openAuthorizedIdentity(grantId: string): Promise<AuthorizedIdentity>
  getExecution(executionId: string): Promise<AuthorizationExecution>
  subscribeRequestChanges(listener: () => void): () => void
}

/** Bind using the installed Cordis context, never a consumer string from a request. */
export function bindIdentityClient(ctx: Context): UserIdentityClient {
  const service = ctx.anpIdentity as unknown as { bindUserConsumer(context: Context): UserIdentityClient }
  return service.bindUserConsumer(ctx)
}
