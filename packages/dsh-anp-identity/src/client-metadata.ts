/** Build admission metadata only from the actual installed identity package. */
export function identityClientVersionHeader(manifest: unknown): string {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)
    || !('name' in manifest) || manifest.name !== '@agent-network-protocol/dsh-anp-identity'
    || !('version' in manifest) || typeof manifest.version !== 'string'
    || !/^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3}(?:\+(?:0|[1-9][0-9]*))?$/u.test(manifest.version)) {
    throw new Error('bootstrap_invalid_package_version')
  }
  return 'dsh-identity/1106/' + manifest.version
}
