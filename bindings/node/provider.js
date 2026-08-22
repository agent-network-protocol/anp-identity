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

  async acquireLease(request) {
    return new ProviderLease(await call(this.#inner.acquireLease(request)))
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

  async list() {
    return (await call(this.#inner.list())).map(identityDescriptor)
  }

  async publicIdentity(reference) {
    return publicIdentity(await call(this.#inner.publicIdentity(reference)))
  }

  async create(request) {
    return publicIdentity(await call(this.#inner.create(createRequest(request))))
  }

  sign(reference, request) {
    return call(this.#inner.sign(reference, request))
  }

  signOriginProof(reference, request) {
    return call(this.#inner.signOriginProof(reference, request))
  }

  async prepareHttpSignature(request) {
    return httpAttempt(await call(this.#inner.prepareHttpSignature(request)))
  }

  async ecdhSealed(request) {
    return sealedEnvelope(await call(this.#inner.ecdhSealed(request)))
  }

  async exportRootKeySealed(request) {
    return sealedEnvelope(await call(this.#inner.exportRootKeySealed(request)))
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
    managed_keys: value.managedKeys,
    external_keys: [],
    services: [],
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

module.exports = { IdentityProvider }
