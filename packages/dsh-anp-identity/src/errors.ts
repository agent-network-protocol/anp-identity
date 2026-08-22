/** Stable DSH plugin error without identity, path, payload, or provider detail. */
export class AnpIdentityPluginError extends Error {
  public readonly name = 'AnpIdentityPluginError'

  public constructor(
    public readonly code: AnpIdentityPluginErrorCode,
    message = ERROR_MESSAGES[code],
  ) {
    super(message)
  }
}

export type AnpIdentityPluginErrorCode =
  | 'invalid_request'
  | 'provider_unavailable'
  | 'provider_incompatible'
  | 'provider_disposed'
  | 'consumer_forbidden'
  | 'capability_forbidden'
  | 'identity_not_found'
  | 'identity_unclaimed'
  | 'identity_deleting'
  | 'identity_in_use'
  | 'handle_conflict'
  | 'catalog_conflict'
  | 'catalog_corrupt'
  | 'http_origin_forbidden'
  | 'http_body_too_large'
  | 'http_body_unsupported'

const ERROR_MESSAGES: Readonly<Record<AnpIdentityPluginErrorCode, string>> = {
  invalid_request: 'The ANP Identity request is invalid.',
  provider_unavailable: 'The ANP Identity provider is unavailable.',
  provider_incompatible: 'The ANP Identity provider is incompatible.',
  provider_disposed: 'The ANP Identity lease has been disposed.',
  consumer_forbidden: 'The DSH consumer is not allowed to use ANP Identity.',
  capability_forbidden: 'The ANP Identity capability is not authorized.',
  identity_not_found: 'The requested ANP identity was not found.',
  identity_unclaimed: 'The requested ANP identity has no consumer grant.',
  identity_deleting: 'The requested ANP identity is being deleted.',
  identity_in_use: 'The requested ANP identity is still granted to another consumer.',
  handle_conflict: 'The requested ANP identity handle is already in use.',
  catalog_conflict: 'The ANP Identity catalog changed concurrently.',
  catalog_corrupt: 'The ANP Identity catalog is corrupt.',
  http_origin_forbidden: 'The HTTP request origin is not authorized.',
  http_body_too_large: 'The HTTP request body exceeds 4 MiB.',
  http_body_unsupported: 'The HTTP request body cannot be replayed safely.',
}

export function pluginError(code: AnpIdentityPluginErrorCode): AnpIdentityPluginError {
  return new AnpIdentityPluginError(code)
}
