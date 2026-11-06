/** Internal first-registration proof refresh. No caller-supplied document or proof options. */
import { randomBytes } from 'node:crypto'
import { isDeepStrictEqual } from 'node:util'
import type { JsonValue, PublicIdentity } from '@agent-network-protocol/anp-identity'
import type { ProviderLease } from '@agent-network-protocol/anp-identity/provider'
import { pluginError } from './errors.js'

/** Refresh only the proof of the exact, still-unpublished local E1 creation snapshot.
 * @param native - The manager's short-lived, provider-bound native lease.
 * @param identity - The local snapshot selected by the existing registration flow.
 * @param origin - The fixed registration service origin.
 * @returns The signed document and a final local snapshot fence for the physical send.
 */
export async function prepareInitialRegistrationProof(native: ProviderLease, identity: PublicIdentity, origin: string): Promise<{
  document: JsonValue
  assertCurrent(native: ProviderLease): Promise<void>
}> {
  const expected = structuredClone(identity)
  const reference = expected.reference
  const domain = new URL(origin).hostname
  const document = structuredClone(expected.document) as Record<string, JsonValue>
  const root = expected.activeKeys.filter(key => key.purposes.includes('root_control'))
  if (!reference.did.startsWith('did:wba:' + domain + ':') || expected.state !== 'active' || expected.revision !== 1
    || document.id !== reference.did || root.length !== 1 || root[0]!.algorithm !== 'ed25519') throw pluginError('provider_incompatible')
  const status = await native.hostStatus(reference)
  if (status.rootCapability !== 'active' || !status.rootKeyFingerprint
    || status.checkpoint?.documentVersion !== 1 || status.checkpoint.registryVersion !== 1) throw pluginError('provider_unavailable')
  const assertCurrent = async (current: ProviderLease) => {
    if (await current.resumeDocumentChange(reference) || await current.resumeIdentityTransition(reference.did)) throw pluginError('catalog_conflict')
    const liveStatus = await current.hostStatus(reference)
    const live = await current.publicIdentity(reference)
    if (!isDeepStrictEqual(liveStatus, status) || !isDeepStrictEqual(live, expected)) throw pluginError('catalog_conflict')
  }
  await assertCurrent(native)
  delete document.proof
  const created = new Date().toISOString()
  const challenge = randomBytes(32).toString('base64url')
  const signed = await native.signDocumentProof(reference, { kid: root[0]!.kid, document,
    options: { proofPurpose: 'assertionMethod', proofType: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', created, domain, challenge } })
  const unsigned = structuredClone(signed) as Record<string, JsonValue>
  const proof = unsigned.proof as Record<string, JsonValue> | undefined
  delete unsigned.proof
  if (!isDeepStrictEqual(unsigned, document) || !proof || proof.verificationMethod !== root[0]!.kid
    || proof.proofPurpose !== 'assertionMethod' || proof.type !== 'DataIntegrityProof' || proof.cryptosuite !== 'eddsa-jcs-2022'
    || proof.created !== created || proof.domain !== domain || proof.challenge !== challenge) throw pluginError('provider_incompatible')
  await assertCurrent(native)
  return { document: signed, assertCurrent }
}
