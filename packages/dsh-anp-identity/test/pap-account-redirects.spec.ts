import { readFile } from 'node:fs/promises'
import { expect, it } from 'vitest'
import { publicationRedirectUri, exactHttps } from '../src/publication-http.js'

it('preserves the shared V2 PAP account redirect vectors without widening V1 or public fetch URLs', async () => {
  const fixture = JSON.parse(await readFile(new URL('./fixtures/pap-account-redirects.json', import.meta.url), 'utf8')) as {
    vectors: Array<{ uri: string; valid_v2_account: boolean; valid_v1: boolean }>
  }
  for (const vector of fixture.vectors) {
    const account = () => publicationRedirectUri(vector.uri, { mcpMachine: false, papSession: true, papAccount: true })
    const legacy = () => publicationRedirectUri(vector.uri)
    if (vector.valid_v2_account) expect(account()).toBe(vector.uri)
    else expect(account).toThrow()
    if (vector.valid_v1) expect(legacy()).toBe(vector.uri)
    else expect(legacy).toThrow()
    expect(() => publicationRedirectUri(vector.uri, { mcpMachine: true, papSession: false, papAccount: false })).toThrow()
    expect(() => publicationRedirectUri(vector.uri, { mcpMachine: false, papSession: true, papAccount: false })).toThrow()
    if (vector.uri.startsWith('http://')) expect(() => exactHttps(vector.uri, true)).toThrow()
  }
})
