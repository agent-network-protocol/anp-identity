import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Context } from '@deepseek-ai/cordis'
import Loader from '@deepseek-ai/cordis-plugin-loader'
import { expect, it, vi } from 'vitest'
import AnpIdentityService from '../src/index.js'
import * as adapter from '../src/mcp-signing-provider.js'

it('loads the Identity service without resolving MCP and refuses an installed MCP module without the registry', async () => {
  const root = await mkdtemp(join(tmpdir(), 'anp-optional-mcp-'))
  const ctx = new Context()
  try {
    await ctx.plugin(Loader)
    // The old published MCP export has no signing registry.
    const resolve = vi.spyOn(ctx.loader, 'import').mockResolvedValue({ name: 'mcp-client' })
    await ctx.plugin(AnpIdentityService, { stateRoot: root })
    expect(ctx.get('anpIdentity')).toBeInstanceOf(AnpIdentityService)
    expect(resolve).not.toHaveBeenCalled()
    await expect((async () => {
      await ctx.plugin(adapter, { name: 'anp-identity', bindings: {} })
    })()).rejects.toThrow('requires a DSH MCP client with Host signing provider support')
    expect(resolve).toHaveBeenCalledExactlyOnceWith('@deepseek-ai/dsh-mcp-client')
  } finally {
    await ctx.fiber.dispose()
    await rm(root, { recursive: true, force: true })
  }
})
