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

test('source lock freezes all published platform dependencies for clean installs', () => {
  const lock = JSON.parse(fs.readFileSync(path.join(root, 'package-lock.json'), 'utf8'))
  assert.equal(lock.packages[''].version, manifest.version)
  assert.deepEqual(lock.packages[''].optionalDependencies, manifest.optionalDependencies)
  for (const [name, version] of Object.entries(manifest.optionalDependencies)) {
    const entry = lock.packages[`node_modules/${name}`]
    assert.ok(entry, `missing lock entry for ${name}`)
    assert.equal(entry.version, version, `unresolved platform dependency: ${name}`)
    assert.equal(entry.optional, true)
    assert.ok(entry.resolved?.startsWith('https://registry.npmjs.org/'), name)
    assert.match(entry.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/)
  }
})

test('source CI and native artifact builds use the declared ANP version', () => {
  const repository = path.resolve(root, '../..')
  const cargo = fs.readFileSync(path.join(repository, 'Cargo.toml'), 'utf8')
  const version = cargo.match(/^anp\s*=.*version\s*=\s*"=([^"]+)"/m)?.[1]
  assert.ok(version, 'ANP must have an exact declared version')
  for (const name of ['ci.yml', 'native-node-artifacts.yml']) {
    const workflow = fs.readFileSync(path.join(repository, '.github/workflows', name), 'utf8')
    const refs = [...workflow.matchAll(/repository: agent-network-protocol\/anp\s+ref: ([^\s]+)/g)]
    assert.equal(refs.length, 2, `${name}: expected two reviewed ANP checkouts`)
    for (const [, ref] of refs) assert.equal(ref, version, `${name}: stale ANP checkout`)
  }
})

test('root wrapper pins exactly five platform packages without embedding a native addon', () => {
  assert.match(manifest.version, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/)
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
