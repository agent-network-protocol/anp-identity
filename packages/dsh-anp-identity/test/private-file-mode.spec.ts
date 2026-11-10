import { expect, it } from 'vitest'
import { hasPublicPosixPermissions } from '../src/private-file-mode.js'

it('does not interpret Windows synthesized stat permissions as an ACL', () => {
  expect(hasPublicPosixPermissions(0o666, 'win32')).toBe(false)
  expect(hasPublicPosixPermissions(0o777, 'win32')).toBe(false)
})

it.each(['linux', 'darwin'] as const)('retains private file and directory checks on %s', platform => {
  expect(hasPublicPosixPermissions(0o600, platform)).toBe(false)
  expect(hasPublicPosixPermissions(0o700, platform)).toBe(false)
  expect(hasPublicPosixPermissions(0o644, platform)).toBe(true)
  expect(hasPublicPosixPermissions(0o755, platform)).toBe(true)
})
