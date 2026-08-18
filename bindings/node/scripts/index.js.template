'use strict'

const native = require('./native.cjs')

async function call(operation) {
  try {
    return await operation
  } catch (error) {
    const match = /ANP_DID_CODE:([^:]+):(.*)$/s.exec(String(error.message))
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

  static async initializeInjected(root, keyId, rootKey) {
    return new DidStore(await call(native.DidStore.initializeInjected(root, keyId, rootKey)))
  }

  static async openInjected(root, keyId, rootKey) {
    return new DidStore(await call(native.DidStore.openInjected(root, keyId, rootKey)))
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

  listIdentities() {
    return call(this.#inner.listIdentities())
  }

  async createIdentity(spec) {
    return new DidIdentity(await call(this.#inner.createIdentity(spec)))
  }

  async openIdentity(did) {
    return new DidIdentity(await call(this.#inner.openIdentity(did)))
  }
}

class DidIdentity {
  #inner

  constructor(inner) {
    this.#inner = inner
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

  httpSignatureHeaders(kid, requestUrl, requestMethod, headers, body) {
    return call(
      this.#inner.httpSignatureHeaders(kid, requestUrl, requestMethod, headers ?? null, body ?? null),
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
}

module.exports = { DidIdentity, DidStore }
