// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import { Context } from '@deepseek-ai/cordis'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { IdentityController, type ManagementRemote } from '../src/client/controller.js'
import { ProtocolSettings } from '../src/client/protocol-settings.js'
import { apply as applyClient } from '../src/client/index.js'
import { initialProtocolPolicy, type ProtocolManagementState, type UpdateProtocolPolicy } from '../src/protocol-policy-types.js'

const controllers: IdentityController[] = []
afterEach(() => { cleanup(); for (const controller of controllers.splice(0)) controller.dispose() })
const ok = <T,>(value: T) => ({ ok: true as const, value })
function fixture() {
  let state: ProtocolManagementState = { policy: initialProtocolPolicy(), domainAccessEnabled: true, protocols: [
    { protocol: 'pap', installed: true, enabled: true, ready: true, managedAdapters: 1, unmanagedAdapters: 0 },
    { protocol: 'mcp', installed: true, enabled: true, ready: true, managedAdapters: 0, unmanagedAdapters: 1 },
    { protocol: 'anp', installed: false, enabled: false, ready: false, managedAdapters: 0, unmanagedAdapters: 0 },
  ] }
  const unused = async (): Promise<never> => { throw new Error('Unexpected identity operation') }
  const query = vi.fn(async () => ok(structuredClone(state)))
  const configure = vi.fn(async (input: UpdateProtocolPolicy) => {
    if (input.expectedVersion !== state.policy.version) throw new Error('protocol_policy_conflict')
    state = { ...state, policy: { ...input.policy, schema: 1, version: state.policy.version + 1 } }
    return ok(structuredClone(state.policy))
  })
  const remote: ManagementRemote = { listIdentities: async () => ok([]), listRequests: async () => ok([]),
    retryPublication: unused, publicationStatus: unused, publishIdentity: unused, getRequest: unused, decide: unused, grants: unused,
    revoke: unused, publicDocument: unused, deleteIdentity: unused, markPrompted: unused, reauthorize: unused,
    protocolManagement: query, configureProtocolPolicy: configure }
  const controller = new IdentityController(remote); controllers.push(controller)
  return { controller, remote, query, configure,
    setInstalled(protocols: string[]) { state = { ...state, protocols: state.protocols.map(item => ({ ...item, installed: protocols.includes(item.protocol) })) } },
    resetExternally() { state = { ...state, policy: initialProtocolPolicy() } },
    changeExternally() { state = { ...state, policy: { ...state.policy, version: state.policy.version + 1 } } } }
}
async function open() {
  const f = fixture()
  render(<ProtocolSettings controller={f.controller} />)
  await act(() => f.controller.refresh())
  await screen.findByLabelText('写入模式')
  return f
}
it('shows one unified form, explicit unmanaged status and service links without making them a whitelist', async () => {
  const f = await open()
  expect(screen.getAllByText('协议管理')).toHaveLength(1)
  expect((screen.getByLabelText('写入模式') as HTMLSelectElement).value).toBe('ask')
  expect(screen.getByText('存在未受管适配器（1）')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Matchall' }).getAttribute('href')).toBe('https://matchall.net/')
  expect(screen.getByRole('link', { name: 'Service Agent GitHub 接入说明' }).getAttribute('href')).toBe('https://github.com/AgentConnect/service-agent')
  expect(f.configure).not.toHaveBeenCalled()
})
it('validates exact domains and saves independent per-protocol write whitelist settings with CAS', async () => {
  const f = await open()
  fireEvent.change(screen.getByLabelText('写入模式'), { target: { value: 'whitelist' } })
  fireEvent.click(screen.getByText('添加写入域名'))
  fireEvent.change(screen.getByLabelText('写入域名 1'), { target: { value: '*.example.com' } })
  fireEvent.click(screen.getByText('保存权限'))
  expect(await screen.findByRole('alert')).toHaveProperty('textContent', '请填写有效域名，并为每个域名选择至少一个协议')
  expect(f.configure).not.toHaveBeenCalled()
  fireEvent.change(screen.getByLabelText('写入域名 1'), { target: { value: 'SERVICE.EXAMPLE' } })
  fireEvent.change(screen.getByLabelText('写入白名单外'), { target: { value: 'deny' } })
  fireEvent.click(screen.getByLabelText('写入域名 1 MCP'))
  fireEvent.click(screen.getByText('保存权限'))
  await waitFor(() => expect(f.configure).toHaveBeenCalledOnce())
  expect(f.configure.mock.calls[0]![0]).toEqual({ expectedVersion: 0, policy: {
    read: initialProtocolPolicy().read,
    write: { mode: 'whitelist', outside: 'deny', domains: [{ domain: 'service.example', protocols: ['anp', 'pap'] }] },
  } })
  await waitFor(() => expect(f.controller.getSnapshot().protocolSaving).toBe(false))
})
it('preserves an unsaved domain draft and blocks stale saves when another page changes policy', async () => {
  const f = await open()
  fireEvent.change(screen.getByLabelText('写入模式'), { target: { value: 'whitelist' } })
  fireEvent.click(screen.getByText('添加写入域名'))
  fireEvent.change(screen.getByLabelText('写入域名 1'), { target: { value: 'draft.example' } })
  f.changeExternally(); await act(() => f.controller.refresh())
  await screen.findByText('配置已在其他页面更新；草稿已保留，请重新加载并核对后再保存')
  expect((screen.getByLabelText('写入域名 1') as HTMLInputElement).value).toBe('draft.example')
  expect((screen.getByText('保存权限') as HTMLButtonElement).disabled).toBe(true)
  expect(f.configure).not.toHaveBeenCalled()
  fireEvent.click(screen.getByText('重新加载配置'))
  await waitFor(() => expect((screen.getByLabelText('写入模式') as HTMLSelectElement).value).toBe('ask'))
})
it('keeps a failed save visible and preserves the draft rather than announcing success', async () => {
  const f = await open(); f.configure.mockRejectedValueOnce(new Error('Unavailable'))
  fireEvent.change(screen.getByLabelText('写入模式'), { target: { value: 'allow_all' } })
  fireEvent.click(screen.getByText('保存权限'))
  await screen.findByText('保存失败或配置已被其他页面修改，请重新加载并核对后再保存')
  expect((screen.getByLabelText('写入模式') as HTMLSelectElement).value).toBe('allow_all')
  expect(f.controller.getSnapshot().protocolManagement?.policy.write.mode).toBe('ask')
  await act(() => f.controller.refresh())
  expect(screen.getByText('保存失败或配置已被其他页面修改，请重新加载并核对后再保存')).toBeTruthy()
})
it('protocol query failure does not block the separate identity/approval refresh path', async () => {
  const f = fixture(); f.query.mockRejectedValue(new Error('Corrupt preferences'))
  await f.controller.refresh()
  await waitFor(() => expect(f.controller.getSnapshot().protocolError).toContain('无法读取协议权限'))
  expect(f.controller.getSnapshot().loading).toBe(false)
  expect(f.controller.getSnapshot().error).toBeNull()
})
it.each([['anp'], ['pap'], ['anp', 'pap']])('registers exactly one shared navigation section for installed %j', async (...protocols) => {
  const f = fixture(); f.setInstalled(protocols)
  const ctx = new Context()
  const sections = new Map<string, { inject?: () => { controller: IdentityController } }>()
  let sharedRegistrations = 0, unmounts = 0
  ctx.provide('remote', { $mount: async () => async () => { unmounts++ } })
  ctx.provide('remote.anpIdentityManager', f.remote)
  ctx.provide('slots', {
    inject(_name: string, callback: () => () => void) { return callback() },
    register(input: { id: string; name: string; inject?: () => { controller: IdentityController } }, _component: unknown) {
      if (input.id === 'protocol-management') sharedRegistrations++
      if (input.name === 'settings.section') sections.set(input.id, input)
      return () => { sections.delete(input.id) }
    },
  })
  let dispose: (() => Promise<void>) | undefined
  try {
    dispose = await applyClient(ctx)
    await waitFor(() => expect(sections.has('protocol-management')).toBe(true))
    const active = sections.get('anp-identity')!.inject!().controller
    await act(() => active.refresh()); await act(() => active.refresh())
    expect(sharedRegistrations).toBe(1)
    expect(sections.has('pap-companies')).toBe(false)
    f.setInstalled([]); await act(() => active.refresh())
    await waitFor(() => expect(sections.has('protocol-management')).toBe(false))
  } finally { try { await dispose?.() } finally { await ctx.fiber.dispose() } }
  expect(sections.size).toBe(0); expect(unmounts).toBe(1)
})

it('reloads authoritative policy after a data reset instead of reusing the old page version', async () => {
  const f = await open()
  f.changeExternally(); await act(() => f.controller.refresh())
  await waitFor(() => expect(f.controller.getSnapshot().protocolManagement?.policy.version).toBe(1))
  f.query.mockRejectedValueOnce(new Error('Temporary disconnect'))
  await act(() => f.controller.refresh())
  await screen.findByText(/无法读取协议权限/)
  f.resetExternally()
  const reads = f.query.mock.calls.length
  fireEvent.click(screen.getByText('重新加载配置'))
  await waitFor(() => expect(f.query.mock.calls.length).toBeGreaterThan(reads))
  await waitFor(() => expect(f.controller.getSnapshot().protocolError).toBeNull())
  expect(f.controller.getSnapshot().protocolManagement?.policy.version).toBe(0)
  fireEvent.change(screen.getByLabelText('写入模式'), { target: { value: 'allow_all' } })
  fireEvent.click(screen.getByText('保存权限'))
  await waitFor(() => expect(f.configure).toHaveBeenCalledWith(expect.objectContaining({ expectedVersion: 0, policy: expect.objectContaining({ write: expect.objectContaining({ mode: 'allow_all' }) }) })))
})
it('does not discard the edit or clear an error when authoritative reload fails', async () => {
  const f = await open()
  fireEvent.change(screen.getByLabelText('写入模式'), { target: { value: 'allow_all' } })
  f.query.mockRejectedValueOnce(new Error('Unreadable settings'))
  fireEvent.click(screen.getByText('重新加载配置'))
  await screen.findByText(/无法读取协议权限/)
  expect((screen.getByLabelText('写入模式') as HTMLSelectElement).value).toBe('allow_all')
  expect(f.configure).not.toHaveBeenCalled()
})

it('does not let a delayed poll roll back a successful permission save', async () => {
  const f = await open()
  const old = structuredClone(f.controller.getSnapshot().protocolManagement!)
  let release!: (value: ReturnType<typeof ok<ProtocolManagementState>>) => void
  f.query.mockImplementationOnce(() => new Promise(resolve => { release = resolve }))
  await act(() => f.controller.refresh())
  fireEvent.change(screen.getByLabelText('写入模式'), { target: { value: 'allow_all' } })
  fireEvent.click(screen.getByText('保存权限'))
  await waitFor(() => expect(f.controller.getSnapshot().protocolManagement?.policy.version).toBe(1))
  await act(async () => { release(ok(old)); await Promise.resolve() })
  expect(f.controller.getSnapshot().protocolManagement?.policy.version).toBe(1)
  expect(f.controller.getSnapshot().protocolManagement?.policy.write.mode).toBe('allow_all')
  expect(f.controller.getSnapshot().protocolError).toBeNull()
})
