'use strict'

const native = require('./native.cjs')

async function call(operation) {
  try {
    return await operation
  } catch (error) {
    const match = /ANP_IDENTITY_CODE:([^:]+):(.*)$/s.exec(String(error.message))
    if (match) {
      error.code = match[1]
      error.message = match[2]
    }
    throw error
  }
}

function callSync(operation) {
  try {
    return operation()
  } catch (error) {
    const match = /ANP_IDENTITY_CODE:([^:]+):(.*)$/s.exec(String(error.message))
    if (match) {
      error.code = match[1]
      error.message = match[2]
    }
    throw error
  }
}

class IdentityProvider {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  static async initialize(config) {
    return new IdentityProvider(await call(native.IdentityProvider.initialize(config)))
  }

  static async open(config) {
    return new IdentityProvider(await call(native.IdentityProvider.open(config)))
  }

  acquireLease(request) {
    return new ProviderLease(callSync(() => this.#inner.acquireLease(request)))
  }
}

class ProviderLease {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  dispose() {
    return this.#inner.dispose()
  }

  async info() {
    const value = await call(this.#inner.info())
    return {
      storeId: value.store_id,
      schemaCompatible: value.schema_compatible,
      identityCount: value.identity_count,
      health: value.health,
    }
  }

  async recover() {
    const value = await call(this.#inner.recover())
    return { identityCount: value.identity_count }
  }

  async list() {
    return (await call(this.#inner.list())).map(identityDescriptor)
  }

  async publicIdentity(reference) {
    return publicIdentity(await call(this.#inner.publicIdentity(reference)))
  }

  async hostStatus(reference) {
    const value = await call(this.#inner.hostStatus(reference))
    return {
      rootCapability: value.root_capability,
      rootKeyFingerprint: value.root_key_fingerprint,
      checkpoint: value.checkpoint == null ? undefined : checkpoint(value.checkpoint),
    }
  }

  recoverIdentity(reference) {
    return call(this.#inner.recoverIdentity(reference))
  }

  async create(request) {
    return publicIdentity(await call(this.#inner.create(createRequest(request))))
  }

  delete(reference) {
    return call(this.#inner.delete(reference))
  }

  verify(reference, request) {
    return call(this.#inner.verify(reference, request))
  }

  sign(reference, request) {
    return call(this.#inner.sign(reference, request))
  }

  signOriginProof(reference, request) {
    return call(this.#inner.signOriginProof(reference, request))
  }

  signObjectProof(reference, request) {
    return call(this.#inner.signObjectProof(reference, proofRequest(request)))
  }

  signDocumentProof(reference, request) {
    return call(this.#inner.signDocumentProof(reference, documentProofRequest(request)))
  }

  async prepareHttpSignature(request) {
    return httpAttempt(await call(this.#inner.prepareHttpSignature(request)))
  }

  prepareLegacyDidWba(reference, request) {
    return call(
      this.#inner.prepareLegacyDidWba(
        reference,
        request.kid,
        request.serviceDomain,
        request.version,
      ),
    )
  }

  async prepareDocumentChange(reference, request) {
    return new ProviderDocumentChangeSession(
      await call(
        this.#inner.prepareDocumentChange(reference, documentChangeRequest(request)),
      ),
    )
  }

  async resumeDocumentChange(reference) {
    const session = await call(this.#inner.resumeDocumentChange(reference))
    return session == null ? undefined : new ProviderDocumentChangeSession(session)
  }

  adoptVerifiedDocument(reference, remote) {
    return call(this.#inner.adoptVerifiedDocument(reference, verifiedRemoteDocument(remote)))
  }

  async beginDeviceEnrollment(request) {
    return new ProviderEnrollmentSession(
      await call(this.#inner.beginDeviceEnrollment(deviceEnrollmentRequest(request))),
    )
  }

  async beginRequestSigningEnrollment(request) {
    return new ProviderEnrollmentSession(
      await call(
        this.#inner.beginRequestSigningEnrollment(requestSigningEnrollmentRequest(request)),
      ),
    )
  }

  async resumeEnrollment(reference) {
    const session = await call(this.#inner.resumeEnrollment(reference))
    return session == null ? undefined : new ProviderEnrollmentSession(session)
  }

  importWrappedRoot(reference, envelope) {
    return call(this.#inner.importWrappedRoot(reference, wrappedRootEnvelope(envelope)))
  }

  confirmRootPromotion(reference, request) {
    return call(
      this.#inner.confirmRootPromotion(reference, {
        remote: verifiedRemoteDocument(request.remote),
      }),
    )
  }

  signPendingRootObjectProof(reference, request) {
    return call(this.#inner.signPendingRootObjectProof(reference, proofRequest(request)))
  }

  async ecdhSealed(request) {
    return sealedDelivery(await call(this.#inner.ecdhSealed(request)))
  }

  async exportRootKeySealed(request) {
    return sealedDelivery(await call(this.#inner.exportRootKeySealed(request)))
  }

  async prepareLegacyRootImport(request) {
    const prepared = await call(
      this.#inner.prepareLegacyRootImport({
        ...request,
        evidence: rootImportEvidence(request.evidence),
      }),
    )
    return new PreparedRootImport(prepared)
  }

  async prepareIdentityMaterialImport(request) {
    const prepared = await call(
      this.#inner.prepareIdentityMaterialImport({
        remote: verifiedRemoteDocument(request.remote),
        didWba: request.didWba,
        keys: request.keys.map((key) => ({
          kid: key.kid,
          purpose: key.purpose,
          encoding: key.encoding,
        })),
        requestId: request.requestId,
      }),
    )
    return new PreparedIdentityMaterialImport(prepared)
  }

  async prepareProviderAdoption(request) {
    const prepared = await call(
      this.#inner.prepareProviderAdoption({
        stateRoot: request.stateRoot,
        target: request.target,
        requestId: request.requestId,
      }),
    )
    return new PreparedProviderAdoption(prepared)
  }
}

class ProviderDocumentChangeSession {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  async candidate() {
    return preparedChange(await call(this.#inner.candidate()))
  }

  hostPhase() {
    return call(this.#inner.hostPhase())
  }

  async beginPublication() {
    return publicationAttempt(await call(this.#inner.beginPublication()))
  }

  async complete(attempt, result) {
    return documentChangeOutcome(
      await call(this.#inner.complete(nativePublicationAttempt(attempt), publicationResult(result))),
    )
  }

  async reconcile(observation) {
    return documentChangeOutcome(
      await call(this.#inner.reconcile(verifiedRemoteDocument(observation))),
    )
  }
}

class ProviderEnrollmentSession {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  async proposal() {
    return enrollmentProposal(await call(this.#inner.proposal()))
  }

  signDeviceAssertion(payload) {
    return call(this.#inner.signDeviceAssertion(payload))
  }

  async deriveDeviceSharedSecretSealed(request) {
    return sealedDelivery(await call(this.#inner.deriveDeviceSharedSecretSealed(request)))
  }

  activate(remote) {
    return call(this.#inner.activate(verifiedRemoteDocument(remote)))
  }

  cancel() {
    return call(this.#inner.cancel())
  }
}

class PreparedRootImport {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  offer() {
    return importOffer(this.#inner.offer())
  }

  complete(token, envelope) {
    return call(this.#inner.complete(token, nativeEnvelope(envelope)))
  }
}

class PreparedIdentityMaterialImport {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  offer() {
    const value = this.#inner.offer()
    return {
      target: identityReference(value.target),
      recipientPublicKey: Buffer.from(value.recipient_public_key),
      requestId: value.request_id,
      token: value.token,
      authorization: authorizationContext(value.authorization),
      itemAad: value.item_aad_b64u,
    }
  }

  async complete(token, envelopes) {
    return publicIdentity(
      await call(this.#inner.complete(token, envelopes.map(nativeEnvelope))),
    )
  }
}

class PreparedProviderAdoption {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  offer() {
    const value = this.#inner.offer()
    return {
      storeId: value.store_id,
      rootKeyFingerprint: value.root_key_fingerprint,
      recipientPublicKey: Buffer.from(value.recipient_public_key),
      requestId: value.request_id,
      token: value.token,
      authorization: authorizationContext(value.authorization),
      aad: value.aad_b64u,
    }
  }

  async complete(token, envelope) {
    const value = await call(this.#inner.complete(token, nativeEnvelope(envelope)))
    return {
      storeId: value.store_id,
      provider: value.provider,
      rootKeyFingerprint: value.root_key_fingerprint,
      generation: value.generation,
    }
  }
}

function importOffer(value) {
  return {
    recipientPublicKey: Buffer.from(value.recipient_public_key),
    requestId: value.request_id,
    token: value.token,
    authorization: authorizationContext(value.authorization),
    aad: value.aad_b64u,
  }
}

function authorizationContext(value) {
  return {
    providerInstanceId: value.provider_instance_id,
    parentLeaseId: value.parent_lease_id,
    consumer: value.consumer,
    capability: value.capability,
    storeId: value.store_id,
    expiresAt: value.expires_at,
  }
}

function sealedEnvelope(value) {
  return {
    protocol: value.protocol,
    suite: value.suite,
    encappedKey: value.encapped_key_b64u,
    ciphertext: value.ciphertext_b64u,
  }
}

function sealedDelivery(value) {
  return {
    envelope: sealedEnvelope(value.envelope),
    authorization: authorizationContext(value.authorization),
    aad: value.aad,
  }
}

function nativeEnvelope(value) {
  return {
    protocol: value.protocol,
    suite: value.suite,
    encapped_key_b64u: value.encappedKey,
    ciphertext_b64u: value.ciphertext,
  }
}

function httpAttempt(value) {
  return {
    bindingDigest: value.binding_digest,
    kid: value.kid,
    headerPatch: value.header_patch,
  }
}

function rootImportEvidence(value) {
  return {
    transfer_id: value.transferId,
    source_did: value.sourceDid,
    target_did: value.targetDid,
    sender_device_id: value.senderDeviceId,
    recipient_device_id: value.recipientDeviceId,
    recipient_agreement_kid: value.recipientAgreementKid,
    root_kid: value.rootKid,
    checkpoint: {
      document_version: value.checkpoint.documentVersion,
      registry_version: value.checkpoint.registryVersion,
      document_digest: value.checkpoint.documentDigest,
    },
    accepted_at: value.acceptedAt,
  }
}

function verifiedRemoteDocument(value) {
  return {
    document: value.document,
    evidence: {
      document_version: value.evidence.documentVersion,
      registry_version: value.evidence.registryVersion,
      document_digest: value.evidence.documentDigest,
    },
  }
}

function checkpoint(value) {
  return {
    documentVersion: value.document_version,
    registryVersion: value.registry_version,
    documentDigest: value.document_digest,
  }
}

function identityDescriptor(value) {
  return { reference: identityReference(value.reference), state: value.state }
}

function identityReference(value) {
  return { storeId: value.store_id, identityId: value.identity_id, did: value.did }
}

function publicIdentity(value) {
  return {
    reference: identityReference(value.reference),
    state: value.state,
    revision: value.revision,
    document: value.document,
    activeKeys: value.active_keys.map((key) => ({
      kid: key.kid,
      algorithm: key.algorithm,
      purposes: key.purposes,
    })),
    capabilities: { didWba: value.capabilities.did_wba },
  }
}

function createRequest(value) {
  return {
    profile: value.profile,
    domain: value.domain,
    port: value.port,
    path_segments: value.pathSegments,
    capabilities: { did_wba: value.capabilities?.didWba ?? false },
    managed_keys: value.managedKeys.map((key) => ({ fragment: key.fragment, role: key.role })),
    external_keys: (value.externalKeys ?? []).map((key) => ({
      kid: key.kid,
      role: key.role,
      material:
        key.material.format === 'jwk'
          ? { format: 'jwk', public_key_jwk: key.material.publicKeyJwk }
          : { format: 'multibase', value: key.material.value },
    })),
    services: (value.services ?? []).map(nativeService),
    agent_description_url: value.agentDescriptionUrl,
    extensions: (value.extensions ?? []).map((extension) => ({
      type: extension.type,
      value: {
        devices: extension.value.devices.map((device) => ({
          device_id: device.deviceId,
          signing_key_id: device.signingKeyId,
          e2ee_key_id: device.e2eeKeyId,
          profiles: device.profiles ?? [],
        })),
      },
    })),
  }
}

function documentChangeRequest(value) {
  return {
    changes: value.changes.map((entry) => {
      switch (entry.change) {
        case 'rotate_signing_key':
          return { change: entry.change, old_kid: entry.oldKid, new_fragment: entry.newFragment }
        case 'add_authentication_key':
          return { change: entry.change, key: publicKeyInput(entry.key) }
        case 'remove_authentication_key':
          return { change: entry.change, kid: entry.kid }
        case 'add_device':
          return {
            change: entry.change,
            device: {
              device_id: entry.device.deviceId,
              signing_key: publicKeyInput(entry.device.signingKey),
              agreement_key: publicKeyInput(entry.device.agreementKey),
              profiles: entry.device.profiles ?? [],
            },
          }
        case 'remove_device':
          return { change: entry.change, device_id: entry.deviceId }
        case 'replace_services':
          return { change: entry.change, services: entry.services.map(nativeService) }
        default:
          return entry
      }
    }),
  }
}

function publicKeyInput(value) {
  return { kid: value.kid, public_key_multibase: value.publicKeyMultibase }
}

function nativeService(value) {
  return {
    id: value.id,
    service_type: value.serviceType,
    service_endpoint: value.serviceEndpoint,
    service_did: value.serviceDid,
    profiles: value.profiles ?? [],
    security_profiles: value.securityProfiles ?? [],
  }
}

function preparedChange(value) {
  return {
    operationId: value.operation_id,
    candidateDocument: value.candidate_document,
    candidateDigest: value.candidate_digest,
  }
}

function publicationAttempt(value) {
  return {
    operationId: value.operation_id,
    candidateDigest: value.candidate_digest,
    publicationGeneration: value.publication_generation,
  }
}

function nativePublicationAttempt(value) {
  return {
    operation_id: value.operationId,
    candidate_digest: value.candidateDigest,
    publication_generation: value.publicationGeneration,
  }
}

function publicationResult(value) {
  if (value.result !== 'confirmed') return value
  return {
    result: 'confirmed',
    evidence: {
      document_version: value.evidence.documentVersion,
      registry_version: value.evidence.registryVersion,
      document_digest: value.evidence.documentDigest,
    },
  }
}

function documentChangeOutcome(value) {
  if (value.outcome !== 'committed') return value
  return { outcome: 'committed', identity: publicIdentity(value.identity) }
}

function proofRequest(value) {
  return {
    key: value.kid == null ? 'default' : { kid: value.kid },
    document: value.document,
    issuer_did: value.issuerDid,
    created: value.created,
  }
}

function documentProofRequest(value) {
  return {
    key: value.kid == null ? 'default' : { kid: value.kid },
    document: value.document,
    options: {
      proof_purpose: value.options?.proofPurpose,
      proof_type: value.options?.proofType,
      cryptosuite: value.options?.cryptosuite,
      created: value.options?.created,
      domain: value.options?.domain,
      challenge: value.options?.challenge,
    },
  }
}

function deviceEnrollmentRequest(value) {
  return {
    remote: verifiedRemoteDocument(value.remote),
    device_id: value.deviceId,
    device_signing_fragment: value.deviceSigningFragment,
    device_agreement_fragment: value.deviceAgreementFragment,
    profiles: value.profiles ?? [],
    capabilities: { did_wba: value.capabilities?.didWba ?? false },
  }
}

function requestSigningEnrollmentRequest(value) {
  return {
    remote: verifiedRemoteDocument(value.remote),
    fragment: value.fragment,
    capabilities: { did_wba: value.capabilities?.didWba ?? false },
  }
}

function enrollmentProposal(value) {
  const kind =
    value.kind.kind === 'device'
      ? {
          kind: 'device',
          deviceId: value.kind.device_id,
          signingKey: enrollmentKey(value.kind.signing_key),
          agreementKey: enrollmentKey(value.kind.agreement_key),
          profiles: value.kind.profiles,
        }
      : { kind: 'request_signing', signingKey: enrollmentKey(value.kind.signing_key) }
  return {
    enrollmentId: value.enrollment_id,
    identity: identityReference(value.identity),
    kind,
    rootKeyFingerprint: value.root_key_fingerprint,
    checkpoint: checkpoint(value.checkpoint),
  }
}

function enrollmentKey(value) {
  return { kid: value.kid, publicKeyMultibase: value.public_key_multibase }
}

function wrappedRootEnvelope(value) {
  return {
    type: value.type,
    version: value.version,
    context: {
      source_did: value.context.sourceDid,
      target_did: value.context.targetDid,
      sender_device_id: value.context.senderDeviceId,
      recipient_device_id: value.context.recipientDeviceId,
      recipient_agreement_kid: value.context.recipientAgreementKid,
      root_kid: value.context.rootKid,
      checkpoint: {
        document_version: value.context.checkpoint.documentVersion,
        registry_version: value.context.checkpoint.registryVersion,
        document_digest: value.context.checkpoint.documentDigest,
      },
      created_at: value.context.createdAt,
      expires_at: value.context.expiresAt,
    },
    ephemeral_public_b64u: value.ephemeralPublic,
    nonce_b64u: value.nonce,
    ciphertext_b64u: value.ciphertext,
    signature_b64u: value.signature,
  }
}

module.exports = { IdentityProvider }
