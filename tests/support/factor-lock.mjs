import { mkdir, open, lstat, readFile, unlink, rmdir } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AcceptanceError } from './config.mjs';

/** Serialize the existing shared test factor across all three repository runners. */
export async function withFactorLock(run, { directory = join(tmpdir(), 'dsh-acceptance-factor-' + process.getuid() + '.lock') } = {}) {
  try { await mkdir(directory, { mode: 0o700 }); }
  catch (error) {
    throw new AcceptanceError(error.code === 'EEXIST' ? 'acceptance_test_factor_busy' : 'acceptance_factor_lock_unavailable');
  }
  const info = await lstat(directory);
  const owner = { pid: process.pid, nonce: randomUUID() };
  const path = join(directory, 'owner.json');
  let created = false;
  try {
    const file = await open(path, 'wx', 0o600);
    try { await file.writeFile(JSON.stringify(owner)); created = true; } finally { await file.close(); }
    return await run();
  } finally {
    // Never remove another holder or infer liveness from an old state file.
    const current = await lstat(directory);
    if (current.ino !== info.ino || current.dev !== info.dev || current.isSymbolicLink())
      throw new AcceptanceError('acceptance_factor_lock_changed');
    if (created) {
      const saved = JSON.parse(await readFile(path, 'utf8'));
      if (saved.nonce !== owner.nonce || saved.pid !== owner.pid) throw new AcceptanceError('acceptance_factor_lock_changed');
      await unlink(path);
    }
    await rmdir(directory);
  }
}
