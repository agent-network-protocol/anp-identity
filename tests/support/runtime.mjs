import { execFile, fork } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, mkdir, readFile, writeFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, delimiter } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { randomUUID } from 'node:crypto';
import { captureInstallation } from './installation-evidence.mjs';
import { AcceptanceError, IDENTITY_ORIGIN, AGENT_ORIGIN, loadModelSettings } from './config.mjs';

const exec = promisify(execFile);
const repo = fileURLToPath(new URL('../../', import.meta.url));
const packageRoot = join(repo, 'packages/dsh-anp-identity');
const consumerName = "@anp-acceptance/identity-consumer";
const cliDefault = resolve(repo, '../deepseek-harness/apps/cli/lib/bin.js');
const ownRequire = createRequire(join(packageRoot, 'package.json'));
const { stringify } = ownRequire('yaml');

/** Execute package commands without printing installation logs or inherited secrets. */
async function run(command, args, options = {}) {
  try { return await exec(command, args, { timeout: 180000, maxBuffer: 2 * 1024 * 1024,
    env: { ...process.env, PATH: dirname(process.execPath) + delimiter + process.env.PATH }, ...options }); }
  catch (error) {
    const npmCode = /npm error code ([A-Z0-9_]+)/u.exec(error.stderr ?? '')?.[1]?.toLowerCase();
    throw new AcceptanceError('acceptance_' + args[0] + '_failed' + (npmCode ? '_' + npmCode : ''));
  }
}
async function pack(directory, destination) {
  const result = await run('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', destination], { cwd: directory });
  const entries = JSON.parse(result.stdout);
  if (entries.length !== 1 || !entries[0].filename?.endsWith('.tgz')) throw new AcceptanceError('acceptance_pack_failed');
  return join(destination, entries[0].filename);
}

/** Real DSH CLI + normal package installation. No module-resolution or provider doubles. */
export async function createRuntime({ identityPackage = process.env.AWIKI_IDENTITY_PACKAGE, subjectEnabled = true, realModel = false, web = false, outputAuditFactor, consumerIsolation = false } = {}) {
  if (Number(process.versions.node.split('.')[0]) < 24
    || Number(process.versions.node.split('.')[0]) === 24 && Number(process.versions.node.split('.')[1]) < 9)
    throw new AcceptanceError('acceptance_requires_node_24_9');
  const cli = resolve(process.env.DSH_CLI ?? cliDefault);
  const modelSettings = realModel ? await loadModelSettings() : undefined;
  try { await stat(cli); } catch { throw new AcceptanceError('acceptance_dsh_cli_missing'); }
  const root = await mkdtemp(join(tmpdir(), 'dsh-acceptance-'));
  const home = join(root, 'dsh-home'), profile = join(home, 'profiles/acceptance');
  let child, dead, pending = new Map(), ready, readyReject;
  let diagnostic = '';
  const outputSecrets = { factorPresent: false, privateKeyPresent: false, compactAssertionPresent: false, modelKeyPresent: false };
  const manifest = JSON.parse(await readFile(join(packageRoot, 'package.json'), 'utf8'));
  const evidence = { runtime: 'actual-dsh-cli', node: process.version, candidate: manifest.name,
    candidateVersion: manifest.version, pid: undefined, installed: undefined };
  async function stop() {
    if (!child || child.exitCode !== null || child.signalCode !== null) return;
    const current = child;
    current.kill('SIGTERM');
    await Promise.race([dead, new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new AcceptanceError('acceptance_host_stop_timeout')), 10000);
      timer.unref();
    })]);
    child = undefined;
  }
  async function start() {
    if (child) throw new AcceptanceError('acceptance_host_already_started');
    diagnostic = '';
    const readiness = new Promise((resolveReady, rejectReady) => { ready = resolveReady; readyReject = rejectReady; });
    // The process environment intentionally points only this child at its isolated state.
    child = fork(cli, ['--profile', 'acceptance', ...(web ? ['--no-open', '--host', '127.0.0.1', '--port', '0'] : [])], {
      cwd: root, silent: true, execArgv: [],
      env: { ...process.env, PATH: dirname(process.execPath) + delimiter + process.env.PATH,
        DSH_HOME: home, DSH_TELEMETRY_DISABLED: '1', DSH_ACCEPTANCE_REAL_MODEL: realModel ? '1' : '0',
        DSH_ACCEPTANCE_CONSUMER_ISOLATION: consumerIsolation ? '1' : '0',
        ...(modelSettings ? { DSH_ACCEPTANCE_MODEL: modelSettings.model } : {}) },
    });
    const current = child;
    const append = bytes => {
      const text = diagnostic + bytes.toString();
      outputSecrets.factorPresent ||= Boolean(outputAuditFactor && [outputAuditFactor.phone, outputAuditFactor.code].some(value => text.includes(value)));
      outputSecrets.privateKeyPresent ||= /-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----/u.test(text);
      outputSecrets.compactAssertionPresent ||= /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/u.test(text);
      outputSecrets.modelKeyPresent ||= Boolean(process.env.DEEPSEEK_API_KEY && text.includes(process.env.DEEPSEEK_API_KEY));
      diagnostic = text.slice(-8192);
    };
    current.stdout.on('data', append); current.stderr.on('data', append);
    current.on('message', message => {
      if (message.ready === true) { evidence.pid = message.pid; ready(); return; }
      if (message.ready === false) { readyReject(new AcceptanceError(message.code)); return; }
      const waiter = pending.get(message.id);
      if (!waiter) return;
      pending.delete(message.id);
      message.ok ? waiter.resolve(message.value) : waiter.reject(new AcceptanceError(message.code));
    });
    dead = new Promise(resolveDead => {
      const finish = () => {
        const error = new AcceptanceError('acceptance_host_exited');
        readyReject(error);
        for (const waiter of pending.values()) waiter.reject(error);
        pending.clear(); resolveDead();
      };
      current.once('exit', finish);
      current.once('error', finish);
    });
    const timer = setTimeout(() => readyReject(new AcceptanceError('acceptance_host_start_timeout')), 30000);
    try { await readiness; } finally { clearTimeout(timer); }
  }
  function rpc(method, input, { timeoutMs = 30000 } = {}) {
    if (!child?.connected) return Promise.reject(new AcceptanceError('acceptance_host_unavailable'));
    const id = randomUUID();
    return new Promise((resolveCall, rejectCall) => {
      const timer = setTimeout(() => { pending.delete(id); rejectCall(new AcceptanceError('acceptance_rpc_timeout')); }, timeoutMs);
      pending.set(id, { resolve: value => { clearTimeout(timer); resolveCall(value); },
        reject: error => { clearTimeout(timer); rejectCall(error); } });
      child.send({ id, method, input }, error => {
        if (error) { clearTimeout(timer); pending.delete(id); rejectCall(new AcceptanceError('acceptance_ipc_failed')); }
      });
    });
  }
  async function dispose() {
    await stop();
    await rm(root, { recursive: true });
  }
  try {
    await mkdir(profile, { recursive: true, mode: 0o700 });
    await mkdir(join(root, 'packs'), { mode: 0o700 });
    await run('npm', ['run', 'build'], { cwd: packageRoot });
    if (!identityPackage) {
      identityPackage = manifest.name === '@agent-network-protocol/dsh-anp-identity'
        ? await pack(packageRoot, join(root, 'packs')) : '@agent-network-protocol/dsh-anp-identity@0.1.16';
    }
    if (!identityPackage.startsWith('@agent-network-protocol/dsh-anp-identity@')) {
      identityPackage = resolve(identityPackage);
      await stat(identityPackage);
      if (!identityPackage.endsWith('.tgz')) throw new AcceptanceError('acceptance_identity_tarball_required');
    } else if (!/^@agent-network-protocol\/dsh-anp-identity@\d+\.\d+\.\d+$/u.test(identityPackage)) {
      throw new AcceptanceError('acceptance_identity_version_required');
    }
    const fixture = await pack(join(repo, 'tests/support/consumer'), join(root, 'packs'));
    const identitySpec = identityPackage.startsWith('@agent-network-protocol/dsh-anp-identity@')
      ? identityPackage.slice(identityPackage.lastIndexOf('@') + 1) : identityPackage;
    const dependencies = { '@agent-network-protocol/dsh-anp-identity': identitySpec, [consumerName]: fixture };
    let subjectTarball = identityPackage;
    if (manifest.name !== '@agent-network-protocol/dsh-anp-identity') {
      subjectTarball = await pack(packageRoot, join(root, 'packs'));
      dependencies[manifest.name] = subjectTarball;
    }
    await writeFile(join(profile, 'package.json'), JSON.stringify({ private: true, type: 'module',
      dependencies, dsh: { profile: { bundles: web ? ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'] : [] } } }), { mode: 0o600 });
    await run('npm', ['install', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund',
      '--registry=https://registry.npmjs.org'], { cwd: profile });
    const installed = createRequire(join(profile, 'package.json'));
    evidence.installed = {
      identity: installed.resolve('@agent-network-protocol/dsh-anp-identity'),
      native: installed.resolve('@agent-network-protocol/anp-identity'),
    };
    evidence.identityVersion = JSON.parse(await readFile(installed.resolve('@agent-network-protocol/dsh-anp-identity/package.json'), 'utf8')).version;
    evidence.installation = await captureInstallation(profile, manifest.name, subjectTarball);
    const adapters = ['@agent-network-protocol/dsh-anp/plugin', '@awiki/dsh-pap/plugin',
      ...(consumerIsolation ? [consumerName + '/anp-consumer', consumerName + '/pap-consumer'] : [])];
    const entries = [
      { id: 'typert', name: '@deepseek-ai/dsh-typert-registry' },
      { id: 'credentials', name: '@deepseek-ai/dsh-credentials-local', config: { path: join(home, '.credentials.yaml'), watch: false } },
      { id: 'identity', name: '@agent-network-protocol/dsh-anp-identity', config: {
        stateRoot: join(root, 'identity'), allowConsumers: [consumerName, ...adapters,
          '@agent-network-protocol/dsh-anp-identity/protocol-bootstrap'],
        userConsumers: [consumerName, ...adapters, '@agent-network-protocol/dsh-anp-identity/protocol-bootstrap'],
        allowProviderConsumers: [], httpAllowedOrigins: Object.fromEntries([consumerName, ...adapters].map(name => [name, [AGENT_ORIGIN]])),
        ...(manifest.name !== '@agent-network-protocol/dsh-anp-identity' ? { domainAccess: { enabled: true, scopes: [], secretStore: 'local-file' } } : {}),
      } },
      { id: 'provider', name: '@agent-network-protocol/dsh-anp-identity/provider', config: {
        stateRoot: join(root, 'identity'), rootKeyProvider: 'local-file', rootKeyProviderId: 'acceptance-task',
        keyringFallbackToLocalFile: false,
      } },
      { id: 'manager', name: '@agent-network-protocol/dsh-anp-identity/management-remote' },
      { id: 'requester', name: '@agent-network-protocol/dsh-anp-identity/protocol-bootstrap', config: {} },
      { id: 'controller', name: consumerName },
    ];
    if (consumerIsolation) entries.push(
      { id: 'isolated-anp-consumer', name: consumerName + '/anp-consumer' },
      { id: 'isolated-pap-consumer', name: consumerName + '/pap-consumer' });
    if (manifest.name !== '@agent-network-protocol/dsh-anp-identity') {
      if (!web) entries.unshift(...['session', 'session-projection', 'agent', 'llm', 'system-prompt', 'tools', 'tool-executor-native', 'agent-loop']
        .map(name => ({ id: 'core-' + name, name: '@deepseek-ai/dsh-' + name,
          ...(name === 'agent-loop' ? { config: { agents: [] } } : {}) })));
      if (manifest.name === '@agent-network-protocol/dsh-anp') {
        entries.push({ id: 'anp', name: manifest.name + '/plugin', config: { enabled: subjectEnabled, autoConnect: true } });
      } else {
        entries.push({ id: 'pap-declaration', name: manifest.name },
          { id: 'pap', name: manifest.name + '/plugin', config: { enabled: subjectEnabled, autoConnect: true } },
          { id: 'pap-manager', name: manifest.name + '/management-remote' },
          { id: 'pap-tools', name: manifest.name + '/tools' });
      }
    }
    if (realModel) {
      if (!process.env.DEEPSEEK_API_KEY) throw new AcceptanceError('acceptance_deepseek_key_required');
      entries.push({ id: 'model-session-persistence', name: '@deepseek-ai/dsh-session-persistence-jsonl',
        config: { root: join(root, 'sessions'), compression: 'none' } });
      entries.push({ id: 'real-deepseek', name: '@deepseek-ai/dsh-llm-deepseek-api-key',
        config: { baseURL: modelSettings.baseURL, apiKeyEnv: 'DEEPSEEK_API_KEY',
          maxTokens: 4096, models: [{ id: modelSettings.model, contextWindow: 128000, maxTokens: 4096 }] } });
      evidence.model = modelSettings.model;
    }
    if (web) {
      entries.splice(entries.findIndex(entry => entry.id === 'typert'), 1);
      entries.splice(entries.findIndex(entry => entry.id === 'credentials'), 1);
    }
    await writeFile(join(profile, 'cordis.patch.yml'), stringify([
      ...(web ? [{ id: 'web-runtime', config: { openBrowser: false, printUrl: false, surfaceContext: true } },
        ...(realModel ? [{ id: 'llm-deepseek', disabled: true }, { id: 'session-persistence-jsonl', disabled: true }] : [])] : []),
      { insert: entries }]), { mode: 0o600 });
    return { root, profile, home, evidence, start, stop, rpc, dispose,
      // Inspect raw captured output in memory; never return the offending bytes.
      outputSecretStatus: () => ({ ...outputSecrets }),
      // Diagnostic text stays private; callers request only recognized stable failure codes.
      diagnosticCode: () => diagnostic.includes('ERR_MODULE_NOT_FOUND') ? 'module_not_found'
        : diagnostic.includes('provider_incompatible') ? 'provider_incompatible' : 'host_start_failed',
      failureDiagnostic: () => diagnostic
        .replace(/Bearer\s+\S+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gu, '[redacted]')
        .replace(/\+[1-9][0-9]{6,14}/gu, '[redacted-phone]')
        .replace(/(code|token|secret|password|otp)["']?\s*[:=]\s*["']?[^\s,"'}]+/giu, '$1=[redacted]')
        .split('\n').slice(-35).join('\n') };
  } catch (error) {
    await dispose();
    throw error;
  }
}
