import type { Context, Fiber } from '@deepseek-ai/cordis'

/** Installed metadata supplied by the Host Loader, never by a consumer request. */
export interface InstalledConsumerEntry {
  readonly options: { readonly name: string }
  readonly disabled?: boolean
  readonly fiber?: { readonly state: number; readonly ctx?: Context }
}

interface LoaderTree {
  readonly ctx: Context
  readonly store: Readonly<Record<string, ScopedEntry | undefined>>
}

interface ScopedEntry extends InstalledConsumerEntry {
  readonly options: { readonly name: string; readonly id: string }
  readonly loader: { readonly store: object }
  readonly parent: { readonly tree: LoaderTree }
}

interface HostLoader {
  entries(): Iterable<InstalledConsumerEntry>
  readonly store?: object
}

/** The Loader holds an awaitable wrapper; the plugin receives the canonical fiber. */
function canonical(fiber: InstalledConsumerEntry['fiber']): Fiber | undefined {
  return fiber?.ctx?.fiber
}

function liveWithin(fiber: Fiber, root: Fiber): boolean {
  const seen = new Set<Fiber>()
  for (let current = fiber; !seen.has(current); current = current.parent.fiber) {
    seen.add(current)
    if (current.uid === null || ![1, 2].includes(current.state)) return false
    if (current === root) return true
  }
  return false
}

/**
 * Enumerate ordinary consumers, including Loader trees mounted outside its root
 * entry walk. Cordis owns the runtime/fiber registry; Loader owns entry metadata,
 * its containing store and the exact currently installed fiber. All must agree.
 *
 * This does not broaden the separate root-only management/Provider admission.
 * Direct ctx.plugin() calls, inherited parent entries and names on plugin exports
 * do not establish an installed identity.
 */
export function installedConsumerEntries(host: Context): InstalledConsumerEntry[] {
  if (!liveWithin(host.fiber, host.root.fiber)) return []
  const loader = host.get('loader') as HostLoader | undefined
  if (typeof loader?.entries !== 'function') return []
  // The existing root tree remains an explicitly Host-owned admission source.
  const entries = new Set(loader.entries())
  if (!loader.store) return [...entries]
  // Anchor to the Host's real Entry implementation, without accepting a new
  // consumer registration API or depending on a second Loader module copy.
  const prototypes = new Set([...entries].map(entry => Object.getPrototypeOf(entry))
    .filter(prototype => prototype !== null && prototype !== Object.prototype))
  for (const runtime of host.registry.values()) {
    for (const fiber of runtime.fibers) {
      const entry = (fiber as Fiber & { entry?: ScopedEntry }).entry
      if (!entry || !liveWithin(fiber, host.root.fiber)) continue
      if (!prototypes.has(Object.getPrototypeOf(entry))) continue
      if (canonical(entry.fiber) !== fiber || entry.loader?.store !== loader.store) continue
      const tree = entry.parent?.tree
      if (tree?.ctx.root !== host.root || !liveWithin(tree.ctx.fiber, host.root.fiber)) continue
      if (typeof entry.options?.id !== 'string' || tree.store[entry.options.id] !== entry) continue
      entries.add(entry)
    }
  }
  return [...entries]
}

/** Resolve only the exact active installed fiber in this Host's runtime. */
export function resolveInstalledConsumer(host: Context, caller: Context): InstalledConsumerEntry | undefined {
  if (caller.root !== host.root || !liveWithin(caller.fiber, host.root.fiber)) return undefined
  const matches = installedConsumerEntries(host).filter(entry => !entry.disabled
    && canonical(entry.fiber) === caller.fiber && entry.fiber && [1, 2].includes(entry.fiber.state))
  return matches.length === 1 ? matches[0] : undefined
}
