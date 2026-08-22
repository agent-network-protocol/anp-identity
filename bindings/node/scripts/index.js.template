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

class IdentityManager {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  static async initialize(config) {
    return new IdentityManager(await call(native.IdentityManager.initialize(config)))
  }

  static async open(config) {
    return new IdentityManager(await call(native.IdentityManager.open(config)))
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

  async list() {
    return (await call(this.#inner.list())).map(identityDescriptor)
  }

  async create(request) {
    return new ManagedIdentity(await call(this.#inner.create(createRequest(request))))
  }

  async get(reference) {
    return new ManagedIdentity(await call(this.#inner.get(reference)))
  }

  delete(reference) {
    return call(this.#inner.delete(reference))
  }

  async recover() {
    const value = await call(this.#inner.recover())
    return { identityCount: value.identity_count }
  }
}

class ManagedIdentity {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  reference() {
    return call(this.#inner.reference())
  }

  async publicIdentity() {
    return publicIdentity(await call(this.#inner.publicIdentity()))
  }

  sign(request) {
    return call(this.#inner.sign(request))
  }

  verify(request) {
    return call(this.#inner.verify(request))
  }

  signOriginProof(request) {
    return call(this.#inner.signOriginProof(request))
  }

  async prepareDocumentChange(request) {
    return new DocumentChangeSession(
      await call(this.#inner.prepareDocumentChange(documentChangeRequest(request))),
    )
  }

  async resumeDocumentChange() {
    const session = await call(this.#inner.resumeDocumentChange())
    return session == null ? undefined : new DocumentChangeSession(session)
  }
}

class DocumentChangeSession {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  async candidate() {
    return preparedChange(await call(this.#inner.candidate()))
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
    services: (value.services ?? []).map((service) => ({
      id: service.id,
      service_type: service.serviceType,
      service_endpoint: service.serviceEndpoint,
      service_did: service.serviceDid,
      profiles: service.profiles ?? [],
      security_profiles: service.securityProfiles ?? [],
    })),
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
          return {
            change: entry.change,
            services: entry.services.map((service) => ({
              id: service.id,
              service_type: service.serviceType,
              service_endpoint: service.serviceEndpoint,
              service_did: service.serviceDid,
              profiles: service.profiles ?? [],
              security_profiles: service.securityProfiles ?? [],
            })),
          }
        default:
          return entry
      }
    }),
  }
}

function publicKeyInput(value) {
  return { kid: value.kid, public_key_multibase: value.publicKeyMultibase }
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
  return { result: 'confirmed', evidence: publicationEvidence(value.evidence) }
}

function verifiedRemoteDocument(value) {
  return { document: value.document, evidence: publicationEvidence(value.evidence) }
}

function publicationEvidence(value) {
  return {
    document_version: value.documentVersion,
    registry_version: value.registryVersion,
    document_digest: value.documentDigest,
  }
}

function documentChangeOutcome(value) {
  if (value.outcome !== 'committed') return value
  return { outcome: 'committed', identity: publicIdentity(value.identity) }
}

module.exports = { DocumentChangeSession, IdentityManager, ManagedIdentity }
