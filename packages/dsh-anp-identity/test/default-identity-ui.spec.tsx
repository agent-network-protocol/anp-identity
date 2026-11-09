// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { IdentityController, identityKey, type ManagementRemote } from '../src/client/controller.js'
import { IdentitySettings } from '../src/client/views.js'
import type { DefaultIdentitySettings } from '../src/default-identity-types.js'

const controllers: IdentityController[] = []
afterEach(() => { cleanup(); controllers.splice(0).forEach(controller => controller.dispose()) })
const ok = <T,>(value: T) => ({ ok: true as const, value })
const reference = { storeId: 'store', identityId: 'one', did: 'did:wba:identity.example:one' }
async function fixture() {
  let settings: DefaultIdentitySettings = { schema: 1, version: 0, identity: null }
  const unused = async (): Promise<never> => { throw new Error('unexpected_identity_operation') }
  const save = vi.fn(async input => {
    if (input.expectedVersion !== settings.version) throw new Error('default_identity_conflict')
    settings = { schema: 1, version: settings.version + 1, identity: input.identity }
    return ok(structuredClone(settings))
  })
  const remote: ManagementRemote = {
    listIdentities: async () => ok([{ reference, state: 'active', catalogState: 'active', label: 'Public identity', integrations: [], createdAt: '2026-11-09', lastUsedAt: '2026-11-09', grantedConsumers: [] }]),
    listRequests: async () => ok([]), grants: async () => ok([]), publicationStatus: async () => ok({ state: 'not_published', reference } as any),
    getRequest: unused, decide: unused, revoke: unused, publicDocument: unused, deleteIdentity: unused, markPrompted: unused,
    reauthorize: unused, publishIdentity: unused, retryPublication: unused,
    defaultIdentity: async () => ok(structuredClone(settings)), configureDefaultIdentity: save,
  }
  const controller = new IdentityController(remote); controllers.push(controller)
  render(<IdentitySettings controller={controller} />)
  await act(async () => { await controller.refresh(); await controller.refreshDefaultIdentity() })
  await screen.findByLabelText('默认身份')
  return { controller, save, externalChange() { settings = { schema: 1, version: settings.version + 1, identity: reference } } }
}
it('separates viewing an identity from saving the persistent default through the shared Remote', async () => {
  const f = await fixture()
  expect((screen.getByLabelText('默认身份') as HTMLSelectElement).value).toBe('automatic')
  await act(() => f.controller.selectIdentity(identityKey(reference)))
  expect(f.save).not.toHaveBeenCalled()
  fireEvent.change(screen.getByLabelText('默认身份'), { target: { value: identityKey(reference) } })
  fireEvent.click(screen.getByText('保存默认身份'))
  await waitFor(() => expect(f.save).toHaveBeenCalledWith({ expectedVersion: 0, identity: reference }))
  await waitFor(() => expect(f.controller.getSnapshot().defaultIdentity?.version).toBe(1))
})
it('refreshes Agent edits without replacing an unsaved UI draft or silently overwriting a newer version', async () => {
  const f = await fixture()
  fireEvent.change(screen.getByLabelText('默认身份'), { target: { value: identityKey(reference) } })
  f.externalChange()
  await act(() => f.controller.refreshDefaultIdentity())
  expect(screen.getByText('配置已由其他页面或 Agent 修改。草稿已保留，请刷新配置后重新选择。')).toBeTruthy()
  expect((screen.getByText('保存默认身份') as HTMLButtonElement).disabled).toBe(true)
  expect(f.save).not.toHaveBeenCalled()
  fireEvent.click(screen.getByText('刷新默认身份'))
  await waitFor(() => expect((screen.getByLabelText('默认身份') as HTMLSelectElement).value).toBe(identityKey(reference)))
})
