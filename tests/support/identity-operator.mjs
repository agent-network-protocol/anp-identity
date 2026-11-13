import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { AcceptanceError } from './config.mjs';

/** Narrow user-owned test operation against the deployed identity service. */
export async function identityOperator(request) {
  const host = process.env.IDENTITY_SSH_HOST ?? 'awiki';
  if (!/^[a-zA-Z0-9_.-]+$/u.test(host) || host.startsWith('-')) throw new AcceptanceError('acceptance_invalid_ssh_host');
  const code = await readFile(new URL('./identity-operator.py', import.meta.url), 'utf8');
  const quote = value => "'" + value.replaceAll("'", "'\\''") + "'";
  const child = spawn('ssh', ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host,
    'sudo -n /opt/awiki/services/user-service/current/.venv/bin/python -c ' + quote(code)],
    { stdio: ['pipe', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', bytes => { output += bytes.toString(); if (output.length > 16384) child.kill(); });
  child.stderr.resume();
  child.stdin.on('error', () => {});
  child.stdin.end(JSON.stringify(request));
  const timer = setTimeout(() => child.kill(), 30000);
  try {
    const status = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); });
    let result;
    try { result = JSON.parse(output); } catch { throw new AcceptanceError('acceptance_identity_operator_unavailable'); }
    if (status !== 0 || result.error) throw new AcceptanceError('acceptance_identity_operator_failed_' + (result.category ?? 'unknown') + ':' + (result.reason ?? 'unclassified'));
    return result;
  } finally { clearTimeout(timer); }
}
