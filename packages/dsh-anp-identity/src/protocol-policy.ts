/** Durable owner settings and revocable decisions for installed protocol adapters. */
import { mkdir, lstat, readFile, open, rename, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import type { Stats } from 'node:fs'
import lockfile from 'proper-lockfile'
import { syncDirectory } from './sync-directory.js'
import { initialProtocolPolicy, protocolPolicySchema, updateProtocolPolicySchema, protocolDecision, protocolDomain, ProtocolPolicyError, classifyHttpEffect, classifyMcpEffect, classifyMcpScopes,
  type HttpEffectEvidence, type ProtocolClassification,
  type ProtocolPolicy, type UpdateProtocolPolicy, type ManagedProtocol, type ProtocolEffect, type ProtocolDecision } from './protocol-policy-types.js'

/** Additive settings file; no identity, key, grant, credential, or legacy connection is migrated. */
export class ProtocolPolicyStore {
  private readonly root: string
  constructor(stateRoot: string) { this.root = join(stateRoot, 'manager-settings') }
  private safe(info: Stats, directory: boolean): boolean {
    return (directory ? info.isDirectory() : info.isFile()) && !info.isSymbolicLink()
      && (process.platform === 'win32' || !(info.mode & 0o077))
      && (typeof process.getuid !== 'function' || info.uid === process.getuid())
  }
  private async transaction<T>(assertActive: () => void, mutate: (state: ProtocolPolicy) => { value: T; changed: boolean }): Promise<T> {
    assertActive()
    await mkdir(this.root, { recursive: true, mode: 0o700 })
    if (!this.safe(await lstat(this.root), true)) throw new ProtocolPolicyError('protocol_policy_unavailable')
    const release = await lockfile.lock(this.root, { realpath: true, retries: { retries: 80, minTimeout: 10, maxTimeout: 100 } })
    try {
      assertActive()
      const path = join(this.root, 'protocol-access.json')
      let state = initialProtocolPolicy()
      try {
        const info = await lstat(path)
        if (!this.safe(info, false) || info.size > 262144) throw new ProtocolPolicyError('protocol_policy_unavailable')
        state = protocolPolicySchema.parse(JSON.parse(await readFile(path, 'utf8')))
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new ProtocolPolicyError('protocol_policy_unavailable')
      }
      assertActive()
      const result = mutate(state)
      if (result.changed) {
        const bytes = JSON.stringify(state) + '\n'
        if (Buffer.byteLength(bytes) > 262144) throw new ProtocolPolicyError('protocol_policy_unavailable')
        const temp = join(this.root, '.' + randomUUID() + '.tmp')
        try {
          const file = await open(temp, 'wx', 0o600)
          try { await file.writeFile(bytes); await file.sync() } finally { await file.close() }
          assertActive()
          await rename(temp, path)
          await syncDirectory(this.root)
        } finally { await rm(temp, { force: true }) }
      }
      assertActive()
      return structuredClone(result.value)
    } finally { await release() }
  }
  read(assertActive: () => void): Promise<ProtocolPolicy> {
    return this.transaction(assertActive, state => ({ value: state, changed: false }))
  }
  update(raw: UpdateProtocolPolicy, assertActive: () => void): Promise<ProtocolPolicy> {
    const input = updateProtocolPolicySchema.parse(raw)
    return this.transaction(assertActive, state => {
      if (input.expectedVersion !== state.version) throw new ProtocolPolicyError('protocol_policy_conflict')
      if (!Number.isSafeInteger(state.version + 1)) throw new ProtocolPolicyError('protocol_policy_unavailable')
      Object.assign(state, input.policy, { version: state.version + 1 })
      return { value: state, changed: true }
    })
  }
}

/** Created only after an adapter validates its discovery graph. This is not a model tool API. */
export interface ProtocolTargetEvidence {
  discoveryOrigin: string
  destinations: readonly string[]
}
export interface ProtocolOperationEvidence {
  url: string
  effect: ProtocolEffect
  extraPermissions?: boolean
}
/** An opaque per-adapter handle; neither URLs nor caller identity can be supplied at use time. */
export interface ProtocolTarget { readonly protocolTarget: true }
export interface ProtocolAdmission {
  readonly decision: ProtocolDecision
  readonly version: number
  /** Run after all DNS/token/body awaits and immediately before sending. Any policy edit invalidates this admission. */
  assertActive(): Promise<void>
}
export interface ProtocolPolicyClient {
  /** Check existing identity-ledger refusals without creating or consuming a grant. */
  assertNoDenial(request: Request): Promise<void>
  classifyHttp(input: HttpEffectEvidence): ProtocolClassification
  classifyMcp(annotations: unknown): ProtocolClassification
  classifyScopes(scopes: readonly string[]): ProtocolClassification
  register(evidence: ProtocolTargetEvidence): ProtocolTarget
  forget(target: ProtocolTarget): void
  evaluate(target: ProtocolTarget, input: ProtocolOperationEvidence): Promise<ProtocolAdmission>
}

/** Permission never replaces existing destination, identity, consumer, account or credential guards. */
export class ProtocolPolicyAuthority implements Omit<ProtocolPolicyClient, 'assertNoDenial'> {
  private readonly targets = new WeakMap<ProtocolTarget, { domain: string; origins: Set<string> }>()
  constructor(private readonly store: ProtocolPolicyStore, private readonly protocol: ManagedProtocol, private readonly assertCaller: () => void) {}
  classifyHttp(input: HttpEffectEvidence): ProtocolClassification { this.assertCaller(); return classifyHttpEffect(input) }
  classifyMcp(annotations: unknown): ProtocolClassification { this.assertCaller(); return classifyMcpEffect(annotations) }
  classifyScopes(scopes: readonly string[]): ProtocolClassification { this.assertCaller(); return classifyMcpScopes(scopes) }
  register(evidence: ProtocolTargetEvidence): ProtocolTarget {
    this.assertCaller()
    const origin = (value: string) => {
      if (typeof value !== 'string' || value.length > 2048) throw new ProtocolPolicyError('protocol_policy_invalid_target')
      const url = new URL(value)
      protocolDomain(url.hostname)
      if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search || url.pathname !== '/' || url.origin !== value) throw new ProtocolPolicyError('protocol_policy_invalid_target')
      return url.origin
    }
    const source = origin(evidence.discoveryOrigin)
    if (!evidence.destinations.length || evidence.destinations.length > 64) throw new ProtocolPolicyError('protocol_policy_invalid_target')
    const handle = Object.freeze({ protocolTarget: true as const })
    this.targets.set(handle, { domain: new URL(source).hostname, origins: new Set(evidence.destinations.map(origin)) })
    return handle
  }
  forget(target: ProtocolTarget): void { this.targets.delete(target) }
  async evaluate(target: ProtocolTarget, input: ProtocolOperationEvidence): Promise<ProtocolAdmission> {
    this.assertCaller()
    const registered = this.targets.get(target)
    const operation = structuredClone(input)
    if (typeof operation.url !== 'string' || operation.url.length > 8192) throw new ProtocolPolicyError('protocol_policy_invalid_target')
    const url = new URL(operation.url)
    if (!registered || url.protocol !== 'https:' || url.username || url.password || url.hash || !registered.origins.has(url.origin)) throw new ProtocolPolicyError('protocol_policy_invalid_target')
    const state = await this.store.read(this.assertCaller)
    const decision = protocolDecision(state, this.protocol, registered.domain, operation.effect, operation.extraPermissions)
    const check = async () => {
      this.assertCaller()
      if (this.targets.get(target) !== registered) throw new ProtocolPolicyError('protocol_policy_target_revoked')
      const current = await this.store.read(this.assertCaller)
      if (current.version !== state.version || decision === 'deny'
        || protocolDecision(current, this.protocol, registered.domain, operation.effect, operation.extraPermissions) !== decision) throw new ProtocolPolicyError('protocol_policy_changed')
      this.assertCaller()
      if (this.targets.get(target) !== registered) throw new ProtocolPolicyError('protocol_policy_target_revoked')
    }
    return Object.freeze({ decision, version: state.version, assertActive: check })
  }
}
