import { expect, it } from 'vitest'
import { normalizeOperation } from '../src/user-operation.js'

it('discloses query-bearing HTTP operations without persisting query secrets and still binds their exact values', async () => {
  const normalized = await normalizeOperation({ action: 'http', request: new Request('https://api.example.com/profile?action=delete&token=secret-one', { method: 'POST' }) })
  const changed = await normalizeOperation({ action: 'http', request: new Request('https://api.example.com/profile?action=read&token=secret-two', { method: 'POST' }) })
  expect(normalized.frozen.summary).toContain('包含查询参数')
  expect(JSON.stringify(normalized.frozen)).not.toMatch(/secret-one|action=delete|token=/)
  expect(normalized.frozen.fingerprint).not.toBe(changed.frozen.fingerprint)
  expect(normalized.input.action === 'http' && normalized.input.request.url).toContain('action=delete&token=secret-one')
})

it('leaves query-free summaries unchanged and discloses an explicitly empty query', async () => {
  const plain = await normalizeOperation({ action: 'http', request: new Request('https://api.example.com/profile') })
  const empty = await normalizeOperation({ action: 'http', request: new Request('https://api.example.com/profile?') })
  expect(plain.frozen.summary).toBe('GET https://api.example.com/profile')
  expect(empty.frozen.summary).toContain('包含查询参数')
})
