import { bindIdentityClient } from '@agent-network-protocol/dsh-anp-identity/user-client';
import { randomUUID } from 'node:crypto';

export const name = '@anp-acceptance/identity-consumer/anp-consumer';
export const inject = ['anpIdentity'];
export function apply(ctx) {
  const retained = new Map();
  let approved, consumedReuseRejected = 0;
  let catalogUrl;
  const target = async () => {
    if (!catalogUrl) {
      const response = await fetch('https://agent-network-protocol.com/.well-known/agent-descriptions',
        { redirect: 'error', signal: AbortSignal.timeout(15000) });
      if (response.status !== 200) throw new Error('acceptance_discovery_failed');
      const directory = await response.json();
      const agent = directory.items?.find(item => item['@id'] === 'https://agent.agent-network-protocol.com/agents/official/ad.json');
      if (directory['@type'] !== 'CollectionPage' || !agent) throw new Error('acceptance_discovery_failed');
      catalogUrl = new URL('/anp/api/protocols', agent['@id']).href;
    }
    return catalogUrl;
  };
  const command = async (method, input) => {
    const client = bindIdentityClient(ctx);
    if (method === 'tool-status') return { consumedReuseRejected };
    if (method === 'access') return client.requestAccess({ ...input,
      operation: { action: 'http', request: new Request(await target()) } });
    if (method === 'open') { await client.openAuthorizedIdentity(input); return { opened: true }; }
    if (method === 'read') {
      if (!retained.has(input.grantId)) retained.set(input.grantId, await client.openAuthorizedIdentity(input.grantId));
      const response = await retained.get(input.grantId).authenticatedHttp.dispatch(
        new Request(await target()), input.executionId);
      const body = await response.json();
      return { status: response.status, versions: body.versions };
    }
    throw new Error('acceptance_method_rejected');
  };
  ctx.provide('acceptanceAnpConsumer', command);
  if (process.env.DSH_ACCEPTANCE_REAL_MODEL === '1') ctx.inject(['tools'], inner => {
    inner.tools.register({
      name: 'acceptance_identity_catalog',
      description: 'Identity acceptance consumer: read the official protocol catalog through a real authorized identity. The owner approves in the identity UI. This tool cannot approve, create identities, or manage grants.',
      parameters: { type: 'object', properties: {}, additionalProperties: false },
      output: { schema: { type: 'object', additionalProperties: true },
        render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
      execute: async (args, execution) => {
        if (!execution.agent || execution.signal?.aborted || Object.keys(args ?? {}).length)
          return { ok: false, error: 'invalid_parameters' };
        const read = grantId => command('read', { grantId, executionId: randomUUID() });
        try {
          if (approved?.mode === 'permanent') return { ok: true, value: await read(approved.grantId) };
          if (approved?.mode === 'once') {
            try { await read(approved.grantId); return { ok: false, error: 'acceptance_consumed_grant_reused' }; }
            catch (error) {
              if (!['grant_conflict', 'grant_inactive'].includes(error.code)) throw error;
              consumedReuseRejected++;
            }
          }
          const client = bindIdentityClient(ctx);
          let request = await command('access', { requestId: randomUUID(),
            purpose: 'Read the official protocol catalog with the selected identity',
            ...(approved ? { identity: approved.identity } : {}) });
          const deadline = Date.now() + 90000;
          while (request.status === 'pending') {
            if (execution.signal?.aborted || Date.now() >= deadline) {
              await client.cancelAccessRequest(request.id, request.version);
              return { ok: false, error: 'authorization_cancelled' };
            }
            await new Promise(resolve => setTimeout(resolve, 100));
            request = await client.getAccessRequest(request.id);
          }
          if (request.status !== 'approved') return { ok: false, error: 'authorization_' + request.status };
          approved = request;
          return { ok: true, value: await read(request.grantId) };
        } catch (error) {
          return { ok: false, error: /^[a-z][a-z0-9_]{0,80}$/u.test(error.code ?? '') ? error.code : 'acceptance_consumer_failed' };
        }
      },
    });
  });
  ctx.effect(() => () => retained.clear());
}
