import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'

describe('published DSH identity dependency closure', () => {
  it('installs the exact native wrapper as a normal runtime dependency', async () => {
    const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')) as {
      readonly dependencies?: Record<string, string>
      readonly peerDependencies?: Record<string, string>
      readonly peerDependenciesMeta?: Record<string, unknown>
    }
    expect(manifest.dependencies?.['@agent-network-protocol/anp-identity']).toBe('0.2.0')
    expect(manifest.peerDependencies?.['@agent-network-protocol/anp-identity']).toBeUndefined()
    expect(manifest.peerDependenciesMeta?.['@agent-network-protocol/anp-identity']).toBeUndefined()
  })

  it('activates the shipping Cordis patch as a DSH bundle layer', async () => {
    const manifest = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8')) as {
      readonly dsh?: { readonly bundle?: { readonly patch?: string } }
    }
    expect(manifest.dsh?.bundle?.patch).toBe('./cordis.patch.yml')
    const patch = await readFile(new URL('../cordis.patch.yml', import.meta.url), 'utf8')
    expect(patch.match(/id: anp-identity$/gmu)).toHaveLength(1)
    expect(patch.match(/id: anp-identity-provider$/gmu)).toHaveLength(1)
    expect(patch).toContain("'[\"@awiki/dsh-plugin\"]'")
  })
})
