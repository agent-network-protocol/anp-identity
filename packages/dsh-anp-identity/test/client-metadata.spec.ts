import { expect, it } from 'vitest'
import { identityClientVersionHeader } from '../src/client-metadata.js'

it('uses the real identity product and preserves an actual numeric package build without inventing one', () => {
  const name = '@agent-network-protocol/dsh-anp-identity'
  expect(identityClientVersionHeader({ name, version: '0.1.6' })).toBe('dsh-identity/1106/0.1.6')
  expect(identityClientVersionHeader({ name, version: '0.1.6+12' })).toBe('dsh-identity/1106/0.1.6+12')
  for (const value of [null, {}, { name: 'awiki-me', version: '0.1.6+12' },
    { name, version: '0.1.6+abc' }, { name, version: '0.1.6+01' }, { name, version: 'awiki-me/1106/1.0.0+12' }]) {
    expect(() => identityClientVersionHeader(value)).toThrow('bootstrap_invalid_package_version')
  }
})
