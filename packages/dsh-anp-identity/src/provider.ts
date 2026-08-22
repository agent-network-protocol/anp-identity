/** Native ANP Identity Provider registration for the Host-only DSH service. */

import { homedir } from 'node:os'
import { isAbsolute, join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { IdentityManagerConfig } from '@agent-network-protocol/anp-identity'
import { IdentityProvider } from '@agent-network-protocol/anp-identity/provider'
import type {} from './index.js'
import {
  ANP_IDENTITY_NATIVE_PROVIDER_PROTOCOL,
  type NativeProviderRegistry,
  type NativeProviderRegistration,
} from './provider-api.js'

export const name = 'anp-identity-native-provider'
export const inject = ['anpIdentity']

export interface Config {
  readonly stateRoot?: string
  readonly rootKeyProvider: 'keyring' | 'local-file' | 'env' | 'injected'
  /** Keyring uses `service/account`; env uses the variable name; injected uses the key id. */
  readonly rootKeyProviderId?: string
  readonly keyringFallbackToLocalFile?: boolean
  /** Programmatic Host injection only. Never place this value in Loader YAML. */
  readonly injectedRootKey?: Buffer
}

export const Config: z<Config> = z.object({
  stateRoot: z.string(),
  rootKeyProvider: z.union([
    z.const('keyring'),
    z.const('local-file'),
    z.const('env'),
    z.const('injected'),
  ]).default('keyring'),
  rootKeyProviderId: z.string(),
  keyringFallbackToLocalFile: z.boolean().default(false),
  injectedRootKey: z.any(),
})

export function apply(ctx: Context, config: Config): void {
  const registry = ctx.anpIdentity as unknown as NativeProviderRegistry
  const dispose = registry.registerProvider(openNativeProvider(config))
  ctx.effect(() => dispose, 'anp-identity: native provider')
}

export async function openNativeProvider(config: Config): Promise<NativeProviderRegistration> {
  const openConfig = resolveNativeConfig(config)
  let provider: IdentityProvider
  try {
    provider = await IdentityProvider.open(openConfig)
  } catch (error) {
    if (readCode(error) !== 'store_not_found') throw error
    const initializeConfig = resolveNativeConfig(config)
    try {
      provider = await IdentityProvider.initialize(initializeConfig)
    } finally {
      zeroInjectedRootKey(initializeConfig)
    }
  } finally {
    zeroInjectedRootKey(openConfig)
  }
  return {
    protocol: ANP_IDENTITY_NATIVE_PROVIDER_PROTOCOL,
    provider,
  }
}

function zeroInjectedRootKey(config: IdentityManagerConfig): void {
  if (config.rootKeyKind === 'injected') config.rootKey.fill(0)
}

function resolveNativeConfig(config: Config): IdentityManagerConfig {
  const configured = config.stateRoot?.trim()
  const dshHome = process.env.DSH_HOME?.trim() || join(homedir(), '.dsh')
  const stateRoot = configured === undefined || configured.length === 0
    ? join(dshHome, 'anp-identity')
    : configured
  if (!isAbsolute(stateRoot)) throw new TypeError('anp-identity: stateRoot must be absolute')
  switch (config.rootKeyProvider) {
    case 'local-file':
      return { stateRoot, rootKeyKind: 'local_private_file' }
    case 'env': {
      const variable = requiredProviderId(config)
      return {
        stateRoot,
        rootKeyKind: 'environment',
        keyId: variable,
        environmentVariable: variable,
      }
    }
    case 'injected': {
      const keyId = requiredProviderId(config)
      if (!Buffer.isBuffer(config.injectedRootKey) || config.injectedRootKey.byteLength !== 32) {
        throw new TypeError('anp-identity: injectedRootKey must be a 32-byte Buffer')
      }
      return {
        stateRoot,
        rootKeyKind: 'injected',
        keyId,
        rootKey: Buffer.from(config.injectedRootKey),
      }
    }
    case 'keyring': {
      const binding = requiredProviderId(config).split('/')
      if (binding.length !== 2 || binding.some(value => value.length === 0)) {
        throw new TypeError('anp-identity: keyring rootKeyProviderId must be service/account')
      }
      return {
        stateRoot,
        rootKeyKind: 'keyring',
        service: binding[0]!,
        account: binding[1]!,
        fallbackToLocalFile: config.keyringFallbackToLocalFile ?? false,
      }
    }
  }
}

function requiredProviderId(config: Config): string {
  const value = config.rootKeyProviderId?.trim()
  if (value === undefined || value.length === 0 || value.length > 512) {
    throw new TypeError('anp-identity: rootKeyProviderId is required for this provider')
  }
  return value
}

function readCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) return undefined
  return typeof error.code === 'string' ? error.code : undefined
}
