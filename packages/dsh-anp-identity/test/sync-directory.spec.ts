import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { syncDirectory } from '../src/sync-directory.js'
it('does not use unsupported directory handles on Windows', async () => {
  await expect(syncDirectory('/does-not-exist/singapore-test', 'win32')).resolves.toBeUndefined()
})
it.skipIf(process.platform === 'win32')('flushes existing directories and propagates POSIX errors', async () => {
  const root = await mkdtemp(join(tmpdir(), 'identity-sync-'))
  try {
    await expect(syncDirectory(root)).resolves.toBeUndefined()
    await expect(syncDirectory(join(root, 'absent'))).rejects.toMatchObject({ code: 'ENOENT' })
  } finally { await rm(root, {recursive:true, force:true}) }
})
