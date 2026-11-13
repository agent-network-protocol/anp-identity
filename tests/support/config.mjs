import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { homedir } from 'node:os';

const require = createRequire(new URL("../../packages/dsh-anp-identity/package.json", import.meta.url));
const { parseDocument } = require('yaml');

export const IDENTITY_ORIGIN = 'https://awiki.me';
export const DISCOVERY_ORIGIN = 'https://agent-network-protocol.com';
export const AGENT_ORIGIN = 'https://agent.agent-network-protocol.com';

/** Reuse the configured model and endpoint; credentials stay in the task environment. */
export async function loadModelSettings() {
  const path = process.env.AWIKI_DEEPSEEK_CONFIG_FILE ?? join(homedir(), 'awiki-space/match-service/.env');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await file.stat();
    if (!info.isFile() || info.uid !== process.getuid() || info.mode & 0o077 || info.size > 131072)
      throw new AcceptanceError('acceptance_model_config_insecure');
    const settings = new Map();
    for (const line of (await file.readFile('utf8')).split(/\r?\n/u)) {
      const match = /^\s*(AMATCH_CHAT_BASE_URL|AMATCH_CHAT_MODEL)\s*=\s*(.*?)\s*$/u.exec(line);
      if (match) settings.set(match[1], match[2].replace(/^["']|["']$/gu, ''));
    }
    const model = settings.get('AMATCH_CHAT_MODEL'), base = settings.get('AMATCH_CHAT_BASE_URL');
    if (base !== 'https://api.deepseek.com' || !/^[a-z0-9_-]+$/u.test(model ?? ''))
      throw new AcceptanceError('acceptance_model_config_unsupported');
    return { model, baseURL: base + '/anthropic' };
  } finally { await file.close(); }
}

export class AcceptanceError extends Error {
  constructor(code) { super(code); this.name = 'AcceptanceError'; this.code = code; }
}

/** Read only named factors. Never source dotenv or inherit service URLs. */
export async function loadTestFactor({ path = process.env.AWIKI_TEST_FACTOR_FILE
  ?? join(homedir(), 'awiki-space/awiki-me/tests/e2e/configs/e2e.local.yaml'),
  environment = process.env } = {}) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = await file.stat();
    if (!info.isFile() || (info.mode & 0o077) !== 0
      || info.uid !== process.getuid() || info.size > 131072) throw new AcceptanceError('test_factor_file_insecure');
    const source = await file.readFile('utf8');
    let phone, code;
    if (path.endsWith('.env')) {
      const pairs = new Map();
      for (const line of source.split(/\r?\n/u)) {
        const match = /^\s*(?:export\s+)?(DEV_OTP_PHONE|DEV_OTP_CODE)\s*=\s*(.*?)\s*$/u.exec(line);
        if (!match) continue;
        if (pairs.has(match[1])) throw new AcceptanceError('test_factor_duplicate');
        const value = match[2];
        const quoted = /^(["'])(.*?)\1\s*(?:#.*)?$/u.exec(value);
        pairs.set(match[1], quoted ? quoted[2] : value.replace(/\s+#.*$/u, '').trim());
      }
      phone = pairs.get('DEV_OTP_PHONE'); code = pairs.get('DEV_OTP_CODE');
    } else {
      const document = parseDocument(source, { uniqueKeys: true });
      if (document.errors.length) throw new AcceptanceError('test_factor_invalid_yaml');
      const otp = document.toJS({ maxAliasCount: 0 })?.otp;
      phone = otp?.phone; code = otp?.code;
    }
    const overridePhone = environment.AWIKI_E2E_OTP_PHONE?.trim() ?? '';
    const overrideCode = environment.AWIKI_E2E_OTP_CODE?.trim() ?? '';
    if (Boolean(overridePhone) !== Boolean(overrideCode)) throw new AcceptanceError('test_factor_override_incomplete');
    phone = overridePhone || (typeof phone === 'string' ? phone.trim() : '');
    code = overrideCode || (typeof code === 'string' || typeof code === 'number' ? String(code).trim() : '');
    if (!/^\+[1-9][0-9]{6,14}$/u.test(phone) || !/^[0-9]{6}$/u.test(code)) throw new AcceptanceError('test_factor_invalid');
    // Non-enumerable secrets cannot leak through ordinary JSON or diagnostic inspection.
    return Object.freeze(Object.defineProperties({}, {
      phone: { value: phone }, code: { value: code },
      toJSON: { value: () => ({ configured: true }) },
      [Symbol.for('nodejs.util.inspect.custom')]: { value: () => 'TestFactor(<redacted>)' },
    }));
  } catch (error) {
    if (error instanceof AcceptanceError) throw error;
    throw new AcceptanceError('test_factor_unavailable');
  } finally { await file?.close(); }
}
