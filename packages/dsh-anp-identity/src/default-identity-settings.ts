/** A saved null means automatic selection, not fallback to a profile-pinned identity. */
import { mkdir, lstat, readFile, open, rename, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import lockfile from 'proper-lockfile'
import { syncDirectory } from './sync-directory.js'
import { defaultIdentitySettingsSchema, identityReferenceSchema, updateDefaultIdentitySchema, type DefaultIdentitySettings, type UpdateDefaultIdentity } from './default-identity-types.js'

export class DefaultIdentitySettingsStore {
  private readonly root: string
  constructor(stateRoot: string, private readonly initialIdentity: DefaultIdentitySettings['identity'] = null) {
    this.root = join(stateRoot, 'manager-settings')
    this.initialIdentity = initialIdentity === null ? null : identityReferenceSchema.parse(initialIdentity)
  }
  private async transaction<T>(assertActive: () => void, operation: (state: DefaultIdentitySettings) => { value: T; changed: boolean }): Promise<T> {
    assertActive()
    await mkdir(this.root, { recursive: true, mode: 0o700 })
    const safe = async (path: string, directory: boolean) => {
      const info = await lstat(path)
      if (!(directory ? info.isDirectory() : info.isFile()) || info.isSymbolicLink()
        || !directory && info.size > 16384 || process.platform !== 'win32' && Boolean(info.mode & 0o077)
        || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw new Error('default_identity_settings_unavailable')
    }
    await safe(this.root, true)
    const release = await lockfile.lock(this.root, { realpath: true, retries: { retries: 80, minTimeout: 10, maxTimeout: 100 } })
    try {
      assertActive()
      const path = join(this.root, 'default-identity.json')
      let state: DefaultIdentitySettings = { schema: 1, version: 0, identity: this.initialIdentity }
      try {
        await safe(path, false)
        state = defaultIdentitySettingsSchema.parse(JSON.parse(await readFile(path, 'utf8')))
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('default_identity_settings_unavailable')
      }
      assertActive()
      const result = operation(state)
      if (result.changed) {
        const temp = join(this.root, '.' + randomUUID() + '.tmp')
        try {
          const file = await open(temp, 'wx', 0o600)
          try { await file.writeFile(JSON.stringify(state) + '\n'); await file.sync() } finally { await file.close() }
          assertActive(); await rename(temp, path); await syncDirectory(this.root)
        } finally { await rm(temp, { force: true }) }
      }
      assertActive()
      return structuredClone(result.value)
    } finally { await release() }
  }
  read(assertActive: () => void): Promise<DefaultIdentitySettings> {
    return this.transaction(assertActive, state => ({ value: state, changed: false }))
  }
  update(raw: UpdateDefaultIdentity, assertActive: () => void): Promise<DefaultIdentitySettings> {
    const input = updateDefaultIdentitySchema.parse(raw)
    return this.transaction(assertActive, state => {
      if (state.version !== input.expectedVersion) throw new Error('default_identity_conflict')
      if (!Number.isSafeInteger(state.version + 1)) throw new Error('default_identity_settings_unavailable')
      Object.assign(state, { identity: input.identity, version: state.version + 1 })
      return { value: state, changed: true }
    })
  }
}
