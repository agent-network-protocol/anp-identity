import { bindIdentityClient } from '@agent-network-protocol/dsh-anp-identity/user-client';
import { createUserMessage } from '@deepseek-ai/dsh-llm';
import { channel } from 'node:diagnostics_channel';

export const name = "@anp-acceptance/identity-consumer";
export const inject = ['anpIdentity', 'anpIdentityManager',
  ...(process.env.DSH_ACCEPTANCE_CONSUMER_ISOLATION === '1' ? ['acceptanceAnpConsumer', 'acceptancePapConsumer'] : []),
  ...(process.env.DSH_ACCEPTANCE_REAL_MODEL === '1' ? ['tools', 'agents', 'agentLoop', 'sessions'] : [])];

/** Private subprocess controller for deterministic system tests; never a model tool. */
export function apply(ctx) {
  if (!process.send) throw new Error('acceptance_ipc_required');
  const objects = new Map();
  let stopped = false;
  let agentHandle;
  let businessRequests = 0;
  let oauthRequests = 0;
  let factorRequests = 0;
  const discoveryResponses = [];
  let publicationFault = { armed: false, applied: false, prepared: false, updates: [] };
  const publicationTransport = { rpcRequests: 0, undiciHooks: 0, bodies: 0, encodedResponses: 0 };
  const publicationResponse = body => {
    publicationTransport.bodies++;
    let update = false;
    try {
      const value = JSON.parse(body.toString('utf8')).result;
      update = value && Object.keys(value).sort().join(',') === 'checkpoint,did'
        && typeof value.did === 'string' && Number.isInteger(value.checkpoint?.document_version);
      if (update) publicationFault.updates.push({ documentVersion: value.checkpoint.document_version,
        registryVersion: value.checkpoint.registry_version });
    } catch {}
    const lose = update && publicationFault.prepared && !publicationFault.applied;
    if (lose) publicationFault.applied = true;
    return lose ? Buffer.from('{') : body;
  };
  const observeRequest = event => {
    try {
      const request = event.request;
      const origin = request.origin ? new URL(String(request.origin)).hostname : String(request.getHeader('host') ?? '').split(':')[0];
      const path = String(request.path ?? '').split('?')[0];
      if (publicationFault.armed && origin === 'awiki.me' && path === '/user-service/v1/did-auth/rpc') publicationTransport.rpcRequests++;
      if (origin === 'awiki.me' && request.method === 'POST'
        && ['/user-service/v1/handle/rpc', '/user-service/v1/auth/email-send'].includes(path)) factorRequests++;
      if (publicationFault.armed && origin === 'awiki.me' && path === '/user-service/v1/agent-clients/device/prepare'
        && request.method === 'POST') publicationFault.prepared = true;
      // Current DSH dispatches through Undici 8; an unsupported transport must fail the fault assertion.
      if (publicationFault.armed && origin === 'awiki.me' && path === '/user-service/v1/did-auth/rpc'
        && request.method === 'POST' && request.origin && typeof request.onResponseData === 'function'
        && typeof request.onResponseStart === 'function' && typeof request.onResponseEnd === 'function') {
        publicationTransport.undiciHooks++;
        const onHeaders = request.onResponseStart.bind(request), onData = request.onResponseData.bind(request), onComplete = request.onResponseEnd.bind(request);
        const chunks = [];
        let eligible = false, size = 0;
        request.onResponseStart = (status, headers, ...rest) => {
          const encoded = Array.isArray(headers) ? headers.some((value, index) => index % 2 === 0 && String(value).toLowerCase() === 'content-encoding')
            : Object.keys(headers).some(name => name.toLowerCase() === 'content-encoding');
          eligible = status === 200 && !encoded;
          if (!eligible && status === 200) publicationTransport.encodedResponses++;
          return onHeaders(status, headers, ...rest);
        };
        request.onResponseData = chunk => {
          if (!eligible) return onData(chunk);
          size += chunk.length;
          if (size > 131072) throw new Error('Publication fault response exceeds budget');
          chunks.push(Buffer.from(chunk)); return true;
        };
        request.onResponseEnd = trailers => {
          if (eligible) onData(publicationResponse(Buffer.concat(chunks)));
          return onComplete(trailers);
        };
      }
      if (/\/(?:oauth|authorize|token|refresh)(?:\/|$)/u.test(path)) oauthRequests++;
      if (origin === 'agent.agent-network-protocol.com' && (/^\/(?:anp|agents)\//u.test(path) || path.startsWith('/pap/api/'))) businessRequests++;
    } catch {}
  };
  for (const name of ['http.client.request.start', 'undici:request:create']) {
    const subscription = channel(name);
    subscription.subscribe(observeRequest);
    ctx.effect(() => () => subscription.unsubscribe(observeRequest));
  }
  const observeDiscovery = event => {
    try {
      const request = event.request;
      const host = request.origin ? new URL(String(request.origin)).hostname : String(request.getHeader('host') ?? '').split(':')[0];
      const path = String(request.path ?? '').split('?')[0];
      if (!['agent-network-protocol.com', 'agent.agent-network-protocol.com'].includes(host)
        || !['/.well-known/poppy.json', '/pap/openapi.json'].includes(path)) return;
      const names = ['authorization', 'signature', 'signature-input', 'poppy-session', 'dpop'];
      const credentials = request.getHeader ? names.some(name => Boolean(request.getHeader(name)))
        : typeof request.headers === 'string' ? /(?:^|\r\n)(?:authorization|signature|signature-input|poppy-session|dpop):/iu.test(request.headers)
        : Array.isArray(request.headers) ? request.headers.some((value, index) => index % 2 === 0 && names.includes(String(value).toLowerCase())) : null;
      if (discoveryResponses.length < 32) discoveryResponses.push({ host, path, status: event.response.statusCode, credentials });
    } catch {}
  };
  for (const name of ['http.client.response.finish', 'undici:request:headers']) {
    const subscription = channel(name);
    subscription.subscribe(observeDiscovery);
    ctx.effect(() => () => subscription.unsubscribe(observeDiscovery));
  }
  const ordinary = () => bindIdentityClient(ctx);
  const manager = () => ctx.get('anpIdentityManager');
  const managerMethods = new Set(['listIdentities', 'listRequests', 'getRequest', 'decide', 'grants',
    'revoke', 'deleteIdentity', 'publicDocument', 'publicationStatus', 'registrationOnboardingStatus',
    'registrationBootstrapStatus', 'startIdentityRegistration', 'submitRegistrationOtp',
    'registrationServiceSettings', 'configureRegistrationService', 'retryPublication']);
  async function command(method, input) {
    if (stopped) throw Object.assign(new Error('acceptance_disposed'), { code: 'acceptance_disposed' });
    if (method === 'health') return ctx.anpIdentity.health();
    if (method === 'fault/publication-receipt') {
      publicationFault = { armed: true, applied: false, prepared: false, updates: [] };
      return { armed: true };
    }
    if (method === 'fault/publication-status') return { applied: publicationFault.applied, updates: [...publicationFault.updates], transport: { ...publicationTransport } };
    if (method === 'publication/abort-boundary') return { abortAvailable: typeof manager().abortPublication === 'function' };
    if (method.startsWith('isolation/anp/')) return ctx.get('acceptanceAnpConsumer')(method.slice(14), input);
    if (method.startsWith('isolation/pap/')) return ctx.get('acceptancePapConsumer')(method.slice(14), input);
    if (method === 'network/status') return { businessRequests, oauthRequests, discoveryResponses, factorRequests };
    if (method === 'network/reset') { businessRequests = 0; oauthRequests = 0; factorRequests = 0; discoveryResponses.length = 0; return { businessRequests }; }
    if (method === 'browser') {
      const server = ctx.get('webServer'), connection = ctx.get('connection');
      if (!server || !connection) throw new Error('acceptance_web_unavailable');
      const origin = server.getOrigin();
      if (!origin.startsWith('http://127.0.0.1:')) throw new Error('acceptance_web_not_loopback');
      return { origin, authenticatedUrl: connection.authenticatedUrl(origin) };
    }
    if (method === 'tools') return ctx.tools.definitions().map(tool => tool.name);
    if (method === 'model/task' || method === 'model/followup' || method === 'model/resume') {
      if (process.env.DSH_ACCEPTANCE_REAL_MODEL !== '1' || typeof input.task !== 'string' || input.task.length > 4000)
        throw new Error('acceptance_model_request_rejected');
      if (method === 'model/task' && agentHandle) throw new Error('acceptance_model_session_already_used');
      if (method === 'model/followup' && !agentHandle) throw new Error('acceptance_model_session_missing');
      if (method === 'model/resume' && (agentHandle || !/^[0-9a-f-]{36}$/u.test(input.sessionId ?? '')))
        throw new Error('acceptance_model_resume_rejected');
      let stage = 'create';
      try {
      if (method === 'model/resume') agentHandle = await ctx.agents.resume({ resumeSessionId: input.sessionId,
        agentOptions: { provider: 'deepseek-official', model: process.env.DSH_ACCEPTANCE_MODEL, maxTokens: 4096 } });
      agentHandle ??= await ctx.agents.create({ sessionId: crypto.randomUUID(), meta: { cwd: process.cwd() },
        agentOptions: { provider: 'deepseek-official', model: process.env.DSH_ACCEPTANCE_MODEL, maxTokens: 4096 } });
      const agent = agentHandle.agent, calls = [];
      let output = '';
      const results = ctx.on('tools/result', (exec, result) => {
        if (exec.agent?.id === agent.id) calls.push({ name: exec.name, callId: exec.callId, isError: result.isError,
          ...(typeof exec.arguments?.operationRef === 'string' ? { operationRef: exec.arguments.operationRef } : {}),
          ...(result.isError ? {} : { value: result.value }) });
      });
      const events = ctx.on('session/event', (session, event) => {
        if (session.id === agent.id && event.type === 'assistant/message')
          output = event.data.message.content.filter(block => block.type === 'text').map(block => block.text).join('');
      });
      try {
        stage = 'idle'; await agent.whenIdle();
        stage = 'followup';
        agent.followup(createUserMessage({ content: [{ type: 'text', text: input.task }], source: { kind: 'user' } }));
        stage = 'turn'; await agent.whenIdle();
        stage = 'flush';
        const session = ctx.sessions.get(agent.id);
        if (!session) throw Object.assign(new Error('Model session disappeared'), { code: 'session_not_live' });
        await ctx.sessions.flush(session);
        return { model: process.env.DSH_ACCEPTANCE_MODEL, sessionId: agent.id, calls, output };
      } finally { results(); events(); }
      } catch (error) {
        if (stage === 'flush') {
          let detail = String(error.message ?? 'Session flush failed').slice(0, 600);
          for (const value of [process.env.DEEPSEEK_API_KEY, process.env.AWIKI_E2E_OTP_PHONE, process.env.AWIKI_E2E_OTP_CODE])
            if (value) detail = detail.replaceAll(value, '[redacted]');
          process.stderr.write('acceptance-session-flush: ' + detail + '\n');
        }
        const category = typeof error.code === 'string' ? error.code.toLowerCase() : (error.name ?? 'error').toLowerCase();
        throw Object.assign(new Error('Model task failed'), { code: 'acceptance_model_' + stage + '_' + (/^[a-z_]{1,40}$/u.test(category) ? category : 'error') });
      }
    }
    if (method === 'tool') {
      if (!/^(?:anp_|pap_|identity_)[a-z_]+$/u.test(input.name)) throw new Error('acceptance_tool_rejected');
      agentHandle ??= await ctx.agents.create({ sessionId: crypto.randomUUID() });
      const result = await ctx.tools.execute({ agent: agentHandle.agent, signal: AbortSignal.timeout(15000),
        calls: [{ type: 'tool_call', id: crypto.randomUUID(), name: input.name, arguments: JSON.stringify(input.arguments) }] });
      return result.results[0].result;
    }
    if (method === 'capabilities') return {
      anpDomain: typeof ctx.anpIdentity.bindAnpDomainConsumer === 'function'
        && typeof ctx.anpIdentity.resolveDomainAccess === 'function',
      papHost: typeof ctx.anpIdentity.bindPapHostConsumer === 'function',
      protocols: typeof ctx.anpIdentity.bindProtocolConsumer === 'function',
    };
    if (method.startsWith('manager/')) {
      const member = method.slice(8);
      if (!managerMethods.has(member)) throw new Error('acceptance_method_rejected');
      return manager()[member](input);
    }
    if (method === 'create') return ordinary().requestCreateIdentity(input);
    if (method === 'getCreate') return ordinary().getCreateRequest(input);
    if (method === 'cancelCreate') return ordinary().cancelCreateRequest(input.requestId, input.expectedVersion);
    if (method === 'access') {
      const operation = input.operation?.action === 'http'
        ? { action: 'http', request: new Request(input.operation.url, { method: 'GET' }) }
        : input.operation;
      return ordinary().requestAccess({ ...input, ...(operation ? { operation } : {}) });
    }
    if (method === 'getAccess') return ordinary().getAccessRequest(input);
    if (method === 'open') { await ordinary().openAuthorizedIdentity(input); return { opened: true }; }
    if (method === 'cancelAccess') return ordinary().cancelAccessRequest(input.requestId, input.expectedVersion);
    if (method === 'read') {
      if (!objects.has(input.grantId)) objects.set(input.grantId, await ordinary().openAuthorizedIdentity(input.grantId));
      return objects.get(input.grantId).publicIdentity(input.executionId);
    }
    if (method === 'execution') return ordinary().getExecution(input);
    if (method === 'http') {
      const url = new URL(input.url);
      if (url.origin !== 'https://agent.agent-network-protocol.com'
        || !['/anp/catalog.json', '/agents/official/ad.json', '/anp/openapi.json'].includes(url.pathname))
        throw new Error('acceptance_target_rejected');
      if (!objects.has(input.grantId)) objects.set(input.grantId, await ordinary().openAuthorizedIdentity(input.grantId));
      const response = await objects.get(input.grantId).authenticatedHttp.dispatch(new Request(url), input.executionId);
      const value = await response.json();
      return { status: response.status, value };
    }
    throw new Error('acceptance_method_rejected');
  }
  const listener = message => {
    if (!message || typeof message.id !== 'string' || typeof message.method !== 'string') return;
    Promise.resolve().then(() => command(message.method, message.input)).then(
      value => process.send?.({ id: message.id, ok: true, value }),
      error => process.send?.({ id: message.id, ok: false,
        code: typeof error?.code === 'string' && /^[a-z][a-z0-9_]{0,80}$/u.test(error.code)
          ? error.code : 'acceptance_operation_failed' }),
    );
  };
  process.on('message', listener);
  const disconnect = () => ctx.get('appExit')?.(1);
  process.once('disconnect', disconnect);
  ctx.effect(() => () => process.off('disconnect', disconnect));
  ctx.effect(() => async () => { stopped = true; objects.clear(); process.off('message', listener); await agentHandle?.dispose(); });
  setImmediate(async () => {
    try {
      const appReady = ctx.get('appReady');
      if (!appReady) throw new Error('acceptance_app_readiness_required');
      await new Promise(resolve => appReady.onReady(resolve));
      if (process.env.DSH_ACCEPTANCE_REAL_MODEL === '1') {
        const entries = [...ctx.get('loader').entries()];
        for (const id of ['real-deepseek', 'model-session-persistence']) {
          if (entries.find(entry => entry.options.id === id)?.fiber?.state !== 2)
            throw Object.assign(new Error('Required model plugin is inactive'), { code: 'acceptance_required_model_plugin_inactive' });
        }
      }
      const deadline = Date.now() + 15000;
      while ((await ctx.anpIdentity.health()).status === 'unavailable') {
        if (Date.now() >= deadline) throw new Error('provider_unavailable');
        await new Promise(resolve => setTimeout(resolve, 50));
      }
      // The actual Loader must have committed this installed consumer's Fiber.
      ordinary();
      process.send?.({ ready: true, pid: process.pid });
    } catch (error) { process.send?.({ ready: false,
      code: typeof error?.code === 'string' && /^[a-z][a-z0-9_]{0,80}$/u.test(error.code)
        ? error.code : 'acceptance_provider_unavailable' }); }
  });
}
