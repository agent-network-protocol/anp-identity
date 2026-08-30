'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const test = require('node:test')

const root = path.resolve(__dirname, '..')
const manifest = require('../package.json')
const targets = [
  ['darwin-arm64', 'darwin', 'arm64'],
  ['darwin-x64', 'darwin', 'x64'],
  ['linux-arm64-gnu', 'linux', 'arm64'],
  ['linux-x64-gnu', 'linux', 'x64'],
  ['win32-x64-msvc', 'win32', 'x64'],
]

test('root wrapper pins exactly five platform packages without embedding a native addon', () => {
  assert.equal(manifest.version, '0.2.0')
  assert.equal(manifest.publishConfig.registry, 'https://registry.npmjs.org')
  assert.equal(manifest.files.some((entry) => entry.endsWith('.node')), false)
  assert.deepEqual(
    Object.entries(manifest.optionalDependencies).sort(),
    targets.map(([target]) => [
      `@agent-network-protocol/anp-identity-${target}`,
      manifest.version,
    ]).sort(),
  )
})

test('platform package manifests match the generated napi loader contract', () => {
  const loader = fs.readFileSync(path.join(root, 'native.cjs'), 'utf8')
  for (const [target, os, cpu] of targets) {
    const platform = JSON.parse(fs.readFileSync(path.join(root, 'npm', target, 'package.json'), 'utf8'))
    assert.equal(platform.name, `@agent-network-protocol/anp-identity-${target}`)
    assert.equal(platform.version, manifest.version)
    assert.deepEqual(platform.os, [os])
    assert.deepEqual(platform.cpu, [cpu])
    assert.equal(platform.main, `./anp-identity.${target}.node`)
    assert.match(loader, new RegExp(`@agent-network-protocol/anp-identity-${target}`))
  }
})
