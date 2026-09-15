import assert from 'node:assert/strict'
import test from 'node:test'
import { validateAnpResolution } from './stage-node-package.mjs'

const registry = 'registry+https://github.com/rust-lang/crates.io-index'
const local = { name: 'anp', version: '1.0.3', source: null }
const published = { ...local, source: registry }

test('local candidates and registry artifacts keep distinct source gates', () => {
  assert.equal(validateAnpResolution({ packages: [local] }, '1.0.3', true), local)
  assert.equal(validateAnpResolution({ packages: [published] }, '1.0.3', false), published)
  assert.throws(() => validateAnpResolution({ packages: [local] }, '1.0.3', false), /published registry/)
  assert.throws(() => validateAnpResolution({ packages: [published] }, '1.0.3', true), /local ANP/)
})

test('neither source mode accepts missing, duplicate, git, or mismatched ANP', () => {
  for (const candidate of [false, true]) {
    for (const packages of [[], [local, published], [{ ...local, source: 'git+https://example.invalid/anp' }],
      [{ ...(candidate ? local : published), version: '1.0.2' }]]) {
      assert.throws(() => validateAnpResolution({ packages }, '1.0.3', candidate))
    }
  }
})
