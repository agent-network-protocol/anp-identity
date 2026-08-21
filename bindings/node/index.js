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

class DidStore {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  static canonicalDocumentDigest(document) {
    return native.DidStore.canonicalDocumentDigest(document)
  }

  static async initializeInjected(root, keyId, rootKey) {
    return new DidStore(await call(native.DidStore.initializeInjected(root, keyId, rootKey)))
  }

  static async openInjected(root, keyId, rootKey) {
    return new DidStore(await call(native.DidStore.openInjected(root, keyId, rootKey)))
  }

  static async initializeEnv(root, keyId, envVar) {
    return new DidStore(await call(native.DidStore.initializeEnv(root, keyId, envVar)))
  }

  static async openEnv(root, keyId, envVar) {
    return new DidStore(await call(native.DidStore.openEnv(root, keyId, envVar)))
  }

  static async initializeLocalFile(root) {
    return new DidStore(await call(native.DidStore.initializeLocalFile(root)))
  }

  static async openLocalFile(root) {
    return new DidStore(await call(native.DidStore.openLocalFile(root)))
  }

  static async initializeKeyring(root, service, account, fallbackToLocalFile) {
    return new DidStore(
      await call(native.DidStore.initializeKeyring(root, service, account, fallbackToLocalFile)),
    )
  }

  static async openKeyring(root, service, account) {
    return new DidStore(await call(native.DidStore.openKeyring(root, service, account)))
  }

  generation() {
    return call(this.#inner.generation())
  }

  manifest() {
    return call(this.#inner.manifest())
  }

  reload() {
    return call(this.#inner.reload())
  }

  listIdentities() {
    return call(this.#inner.listIdentities())
  }

  async createIdentity(spec) {
    return new DidIdentity(await call(this.#inner.createIdentity(spec)))
  }

  prepareEnrollment(spec) {
    return call(this.#inner.prepareEnrollment(spec))
  }

  async openIdentity(did) {
    return new DidIdentity(await call(this.#inner.openIdentity(did)))
  }

  deleteIdentityNamespace(did, expectedGeneration) {
    return call(this.#inner.deleteIdentityNamespace(did, expectedGeneration))
  }
}

class DidIdentity {
  #inner

  constructor(inner) {
    this.#inner = inner
  }

  reload() {
    return call(this.#inner.reload())
  }

  snapshot() {
    return call(this.#inner.snapshot())
  }

  async pendingRevision() {
    return (await call(this.#inner.pendingRevision())) ?? undefined
  }

  sign(kid, message) {
    return call(this.#inner.sign(kid, message))
  }

  verify(kid, message, signature) {
    return call(this.#inner.verify(kid, message, signature))
  }

  publicKeyBytes(kid) {
    return call(this.#inner.publicKeyBytes(kid))
  }

  ecdh(kid, peerPublic) {
    return call(this.#inner.ecdh(kid, peerPublic))
  }

  legacyDidWbaHeader(kid, serviceDomain, version) {
    return call(this.#inner.legacyDidWbaHeader(kid, serviceDomain, version))
  }

  httpSignatureHeaders(kid, requestUrl, requestMethod, headers, body, options) {
    return call(
      this.#inner.httpSignatureHeaders(
        kid,
        requestUrl,
        requestMethod,
        headers ?? null,
        body ?? null,
        options ?? null,
      ),
    )
  }

  prepareUpdate(spec) {
    return call(this.#inner.prepareUpdate(spec))
  }

  beginPublication(revisionId) {
    return call(this.#inner.beginPublication(revisionId))
  }

  markPublicationUncertain(revisionId) {
    return call(this.#inner.markPublicationUncertain(revisionId))
  }

  markPublished(revisionId) {
    return call(this.#inner.markPublished(revisionId))
  }

  commitUpdate(revisionId) {
    return call(this.#inner.commitUpdate(revisionId))
  }

  abortUpdate(revisionId) {
    return call(this.#inner.abortUpdate(revisionId))
  }

  reconcileUpdate(revisionId, observedRemoteDocument) {
    return call(this.#inner.reconcileUpdate(revisionId, observedRemoteDocument))
  }

  endRetirement(kid) {
    return call(this.#inner.endRetirement(kid))
  }

  deleteRevokedKey(kid) {
    return call(this.#inner.deleteRevokedKey(kid))
  }

  exportWrappedRoot(spec) {
    return call(this.#inner.exportWrappedRoot(spec))
  }

  importWrappedRoot(envelope) {
    return call(this.#inner.importWrappedRoot(envelope))
  }

  confirmRootPromotion(spec) {
    return call(this.#inner.confirmRootPromotion(spec))
  }

  adoptVerifiedDocument(document, evidence) {
    return call(this.#inner.adoptVerifiedDocument(document, evidence))
  }
}

module.exports = { DidIdentity, DidStore }
