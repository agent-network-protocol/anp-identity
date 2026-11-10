/** Windows stat mode bits do not describe the ACL protecting a file. */
export function hasPublicPosixPermissions(mode: number, platform: NodeJS.Platform = process.platform): boolean {
  return platform !== 'win32' && (mode & 0o077) !== 0
}
