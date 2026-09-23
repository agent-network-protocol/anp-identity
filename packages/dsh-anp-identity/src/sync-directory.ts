import { open } from 'node:fs/promises'

/** Flush POSIX directory metadata after an already-fsynced atomic file replacement.
 * Node cannot open or fsync a directory on Windows. File fsync and atomic rename
 * remain mandatory there; do not swallow file-write or rename failures.
 */
export async function syncDirectory(path: string, platform: NodeJS.Platform = process.platform): Promise<void> {
  if (platform === 'win32') return
  const directory = await open(path, 'r')
  try { await directory.sync() } finally { await directory.close() }
}
