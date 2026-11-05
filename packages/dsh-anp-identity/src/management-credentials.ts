/** Encrypted Host-only management credentials, partitioned by service origin and identity. */
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto'
import { mkdir, open, readFile, rename, stat, unlink } from 'node:fs/promises'
import { join } from 'node:path'
import lockfile from 'proper-lockfile'
import type { IdentityReference } from '@agent-network-protocol/anp-identity'
import type { ManagementCredentialBroker, DeviceManagementCredential } from './management-driver.js'
import { exactHttps } from './publication-http.js'
import { pluginError } from './errors.js'
import { syncDirectory } from './sync-directory.js'

/** Each key resolver invocation must return a fresh, owner-controlled 32-byte encryption key. */
export class EncryptedManagementCredentialBroker implements ManagementCredentialBroker {
  constructor(private readonly root: string, private readonly encryptionKey: () => Promise<Buffer>) {}
  private partition(reference: IdentityReference, origin: string): string {
    exactHttps(origin)
    if (new URL(origin).origin !== origin) throw pluginError('invalid_request')
    return createHash('sha256').update(JSON.stringify([origin, reference.storeId, reference.identityId, reference.did])).digest('hex')
  }
  async get(reference: IdentityReference, origin: string): Promise<DeviceManagementCredential | undefined> {
    const partition = this.partition(reference, origin)
    let bytes: string
    try {
      const path = join(this.root, partition + '.json'); const info = await stat(path)
      if ((info.mode & 0o077) !== 0 || info.size > 4 * 1024 * 1024) throw pluginError('provider_unavailable')
      bytes = await readFile(path, 'utf8')
    } catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined; throw pluginError('provider_unavailable') }
    const key = await this.encryptionKey()
    try {
      const row = JSON.parse(bytes)
      if (row.schema !== 1 || row.partition !== partition) throw pluginError('provider_unavailable')
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(row.iv, 'base64url'))
      decipher.setAAD(Buffer.from(partition)); decipher.setAuthTag(Buffer.from(row.tag, 'base64url'))
      const credential = JSON.parse(Buffer.concat([decipher.update(Buffer.from(row.ciphertext, 'base64url')), decipher.final()]).toString('utf8')) as DeviceManagementCredential
      if (!credential.accessToken || !credential.deviceId || !credential.signingKeyId) throw pluginError('provider_unavailable')
      return credential
    } catch { throw pluginError('provider_unavailable') } finally { key.fill(0) }
  }
  private async writeUnlocked(reference: IdentityReference, origin: string, credential: DeviceManagementCredential): Promise<void> {
    const partition = this.partition(reference, origin)
    await mkdir(this.root, { recursive: true, mode: 0o700 })
    const path = join(this.root, partition + '.json')
    const key = await this.encryptionKey()
    try {
      const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, iv)
      cipher.setAAD(Buffer.from(partition))
      const ciphertext = Buffer.concat([cipher.update(JSON.stringify(credential)), cipher.final()])
      const row = { schema: 1, partition, iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), ciphertext: ciphertext.toString('base64url') }
      const temporary = path + '.' + randomUUID()
      const file = await open(temporary, 'wx', 0o600)
      try { await file.writeFile(JSON.stringify(row)); await file.sync() } finally { await file.close() }
      try { await rename(temporary, path); await syncDirectory(this.root) } finally { await unlink(temporary).catch(() => {}) }
    } finally { key.fill(0) }
  }
  async set(reference: IdentityReference, origin: string, credential: DeviceManagementCredential): Promise<void> {
    await this.transaction(reference, origin, async () => {
      const previous = await this.get(reference, origin)
      await this.writeUnlocked(reference, origin, { ...credential, operationBindings: previous?.operationBindings ?? {} })
    })
  }
  async reserveOperation(reference: IdentityReference, origin: string, operationId: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.transaction(reference, origin, async () => {
      const credential = await this.get(reference, origin)
      if (!credential) throw pluginError('provider_unavailable')
      const operations = credential.operationBindings ?? {}
      const previous = operations[operationId]
      if (previous) return structuredClone(previous)
      if (Object.keys(operations).length >= 1024) throw pluginError('provider_unavailable')
      operations[operationId] = structuredClone(body)
      if (Buffer.byteLength(JSON.stringify(operations)) > 2 * 1024 * 1024) throw pluginError('provider_unavailable')
      await this.writeUnlocked(reference, origin, { ...credential, operationBindings: operations })
      return structuredClone(body)
    })
  }
  private async transaction<T>(reference: IdentityReference, origin: string, run: () => Promise<T>): Promise<T> {
    await mkdir(this.root, { recursive: true, mode: 0o700 })
    const path = join(this.root, this.partition(reference, origin) + '.json')
    const release = await lockfile.lock(this.root, { lockfilePath: path + '.lock', realpath: false, retries: { retries: 100, minTimeout: 20, maxTimeout: 100 } })
    try { return await run() } finally { await release() }
  }

}
