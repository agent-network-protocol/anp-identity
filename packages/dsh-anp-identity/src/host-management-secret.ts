/** Host-only management-broker encryption keys backed by the credential record seam. */
import { createHash, randomBytes } from 'node:crypto'
import { isAbsolute, resolve } from 'node:path'
import { credentialKey } from '@deepseek-ai/dsh-credentials'
import type { CredentialProvider, CredentialRecord } from '@deepseek-ai/dsh-credentials'

/** The actual Host credential service; reference and environment resolution are deliberately absent. */
export interface HostManagementSecretContext {
  readonly credentials?: Pick<CredentialProvider, 'readRecord' | 'modifyRecord'> | undefined
}

/** Stable Host partition and a current observation of protected broker state. */
export interface HostManagementSecretOptions {
  context: HostManagementSecretContext
  /** Absolute, stable broker ciphertext directory, also checked by hasExistingCiphertext; normalize aliases in the installer. */
  stateRoot: string
  /** Stable Host bootstrap identifier, never a request id; changing it requires an independent broker directory. */
  bootstrapId: string
  /** Recheck actual encrypted broker state while the credential record is exclusively locked. */
  hasExistingCiphertext(): Promise<boolean>
  /** The installer may reject a revoked Host context; service proxies are not generation identifiers. */
  assertActive?(): void | Promise<void>
}

/** Host-only key access; callers must clear each returned buffer after their cryptographic operation. */
export interface HostManagementSecret {
  /** Return a new 32-byte buffer after an exclusive current-record check. */
  getKey(): Promise<Buffer>
  /** Revoke future access and reject an in-flight result before it reaches the broker. */
  dispose(): void
}

/** Stable failure without provider errors, paths, records or secret material. */
export class HostManagementSecretError extends Error {
  readonly name = 'HostManagementSecretError'
  readonly code = 'credential_unavailable'

  constructor() {
    super('The management credential encryption key is unavailable.')
  }
}

function decodeKey(record: CredentialRecord | undefined): Buffer {
  if (!record || record.kind !== 'api-key'
    || Object.keys(record).some(key => key !== 'kind' && key !== 'key')
    || typeof record.key !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(record.key)) {
    throw new HostManagementSecretError()
  }
  const bytes = Buffer.from(record.key, 'base64url')
  if (bytes.length !== 32 || bytes.toString('base64url') !== record.key) {
    bytes.fill(0)
    throw new HostManagementSecretError()
  }
  return bytes
}

/**
 * Resolve one management-broker key through atomic credential-record operations.
 * The provider must implement exclusive read/decide/write; credentials-local supplies a cross-process lock.
 * Existing records are never rewritten. Missing keys cannot be recreated over encrypted broker data.
 * This uses the configured Host provider's protection, not an OS Secret Service guarantee.
 * The installer must dispose the accessor with its Host context and use assertActive for additional revocation.
 * @param options - Host service, stable partition and live encrypted-state observation.
 * @returns A disposable Host-only accessor; each successful request owns a separate key buffer.
 */
export function createHostManagementSecret(options: HostManagementSecretOptions): HostManagementSecret {
  if (!isAbsolute(options.stateRoot) || options.bootstrapId.length === 0 || options.bootstrapId.length > 256) {
    throw new HostManagementSecretError()
  }
  const partition = createHash('sha256').update(JSON.stringify([resolve(options.stateRoot), options.bootstrapId])).digest('hex')
  const key = credentialKey('anp-identity-manager', `management-broker-${partition}`)
  let disposed = false
  let observedKey = false
  const assertActive = async () => {
    if (disposed || !options.context.credentials) throw new HostManagementSecretError()
    await options.assertActive?.()
    if (disposed || !options.context.credentials) throw new HostManagementSecretError()
  }
  return {
    async getKey(): Promise<Buffer> {
      let bytes: Buffer | undefined
      try {
        await assertActive()
        const provider = options.context.credentials
        if (!provider) throw new HostManagementSecretError()
        // modifyRecord re-reads under the provider's writer lock; readRecord may be a process-local cache.
        const record = await provider.modifyRecord(key, async current => {
          await assertActive()
          if (current !== undefined) {
            const currentBytes = decodeKey(current)
            currentBytes.fill(0)
            return undefined
          }
          if (observedKey || await options.hasExistingCiphertext()) throw new HostManagementSecretError()
          await assertActive()
          const generated = randomBytes(32)
          try { return { kind: 'api-key', key: generated.toString('base64url') } }
          finally { generated.fill(0) }
        })
        bytes = decodeKey(record)
        observedKey = true
        await assertActive()
        return Buffer.from(bytes)
      } catch {
        throw new HostManagementSecretError()
      } finally {
        bytes?.fill(0)
      }
    },
    dispose(): void { disposed = true },
  }
}
