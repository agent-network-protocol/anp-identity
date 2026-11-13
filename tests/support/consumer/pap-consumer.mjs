import { bindProtocolIdentityClient } from '@agent-network-protocol/dsh-anp-identity/protocol-client';
import { bindIdentityClient } from '@agent-network-protocol/dsh-anp-identity/user-client';
import { createPublicKey, verify, randomUUID } from 'node:crypto';

export const name = '@anp-acceptance/identity-consumer/pap-consumer';
export const inject = ['anpIdentity'];
export function apply(ctx) {
  let lease, scope, key;
  ctx.provide('acceptancePapConsumer', async (method, input) => {
    if (method === 'openOtherGrant') { await bindIdentityClient(ctx).openAuthorizedIdentity(input); return { opened: true }; }
    if (method === 'bind') {
      lease = await bindProtocolIdentityClient(ctx).registerValidatedTarget(input);
      scope = lease.bindPapScope({ userId: 'signed-out' });
      key = await lease.createDelegatedKey(scope, randomUUID());
      return { purpose: key.purpose, publicThumbprint: key.thumbprint };
    }
    if (!lease) throw new Error('acceptance_protocol_lease_missing');
    if (method === 'delegate') {
      const compact = await lease.issuePapDelegation(scope, { keyRef: key.keyRef, ttlSeconds: 60 });
      const identity = await lease.getOAuthClientIdentity();
      const [header, claims, signature] = compact.split('.');
      return { verified: verify('sha256', Buffer.from(header + '.' + claims),
        { key: createPublicKey({ key: identity.publicJwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')),
        clientId: identity.clientId };
    }
    if (method === 'wrongPurpose') {
      await lease.signDpopProof(scope, { keyRef: key.keyRef, httpMethod: 'GET',
        httpUri: 'https://agent.agent-network-protocol.com/pap/api/protocols' });
      return { signed: true };
    }
    if (method === 'dispose') { lease.dispose(); return { disposed: true }; }
    throw new Error('acceptance_method_rejected');
  });
  ctx.effect(() => () => lease?.dispose());
}
