/** A published native ANP Identity signs for the upstream MCP client through the real Loader. */
import type { Context } from '@deepseek-ai/cordis';
import type { RequestListener } from 'node:http';
import { randomBytes, randomUUID } from 'node:crypto';
import { stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { expect, it, vi } from 'vitest';
import type { ProtocolUsePolicy } from '../src/protocol-client.js';
import * as adapter from '../src/mcp-signing-provider.js';
import { createProductHostFixture } from './helpers/product-host-fixture.js';

type Network = (input: string | URL | Request, init?: RequestInit, beforeSend?: () => Promise<void>) => Promise<Response>;
const transport = vi.hoisted(() => ({ send: undefined as Network | undefined }));
vi.mock('#cimd-upstream-wire', async original => ({ ...await original<Record<string, unknown>>(),
  machineFetch: (...args: Parameters<Network>) => {
    if (!transport.send) throw new Error('Missing isolated product-test transport');
    return transport.send(...args);
  },
}));

const upstream = process.env.DSH_CIMD_UPSTREAM_SOURCE;
const userService = process.env.DSH_IDENTITY_USER_SERVICE_SOURCE;
const python = process.env.DSH_IDENTITY_PYTHON;
const asRoot = process.env.DSH_MCP_PRODUCT_AS_SOURCE;
const DSN = process.env.DATABASE_URL;
const MCP = '@deepseek-ai/dsh-mcp-client';
const ADAPTER = '@agent-network-protocol/dsh-anp-identity/mcp-signing-provider';
const scopes = ['agent.self.read', 'catalog.read'];
type ProductContext = Context & { tools: { schemas(): Array<{ name: string }> } };
type Pool = { query(sql: string): Promise<{ rows: Array<{ n: number }> }>; end(): Promise<void> };
type Tls = { cert: string; start(handler: RequestListener, hostname: string): Promise<{ origin: string }>; fetcher(): unknown; close(): Promise<void> };
type Store = { configureRequestLimits(input: object): Promise<void>; configurePolicy(input: object): Promise<void>;
  provisionResourceServer(id: string, secret: string, resources: string[]): Promise<void> };

const load = async (root: string, path: string): Promise<unknown> => {
  try { return await import(/* @vite-ignore */ pathToFileURL(join(root, path)).href); }
  catch (cause) { throw new Error(`Could not load product fixture module ${path}`, { cause }); }
};

it.skipIf(!upstream || !userService || !python || !asRoot || !DSN || process.platform !== 'linux')(
  'loads the ANP signer in cordis.yml and admits only the actual MCP Loader consumer', async () => {
    const database = new URL(DSN!);
    expect(database.hostname).toBe('');
    expect(database.pathname).toBe('/cimd_component');
    expect(database.searchParams.get('host')).toMatch(/^\/tmp\/cimd-pg\.[^/]+\/socket$/u);

    const { default: pg } = await load(asRoot!, 'node_modules/pg/lib/index.js') as { default: { Pool: new (input: object) => Pool } };
    const { tlsFixture } = await load(asRoot!, 'tests/helpers.ts') as { tlsFixture(): Promise<Tls> };
    const { PostgresStore } = await load(asRoot!, 'packages/store-postgres/store.ts') as { PostgresStore: new (pool: Pool, issuer: string) => Store };
    const { ClientAuthenticator } = await load(asRoot!, 'packages/oauth-core/client.ts') as { ClientAuthenticator: new (fetcher: unknown, issuer: string) => unknown };
    const { createAuthorizationServer } = await load(asRoot!, 'packages/oauth-as/app.ts') as { createAuthorizationServer(store: Store, auth: unknown, scopes: string[]): RequestListener };
    const { TokenVerifier } = await load(asRoot!, 'packages/oauth-rs/index.ts') as { TokenVerifier: new (fetcher: unknown, options: object) => unknown };
    const { createMcpApp } = await load(asRoot!, 'examples/minimal-mcp-server/app.ts') as { createMcpApp(verifier: unknown): RequestListener };
    const path = 'packages/mcp/mcp-client/lib/types/';
    const mcp = await load(upstream!, path + 'index.js');
    const { createTestMachineFetch } = await load(upstream!, path + 'machine-http.js') as { createTestMachineFetch(options: { origin: string; ca: string }): Network };
    const { default: systemPrompt } = await load(upstream!, 'packages/core/system-prompt/lib/index.js') as { default: unknown };
    const { default: tools } = await load(upstream!, 'packages/core/tools/lib/index.js') as { default: unknown };
    const nativeExecutor = await load(upstream!, 'packages/core/tool-executor-native/lib/index.js');
    const { default: include } = await load(upstream!, 'vendor/include/lib/index.js') as { default: unknown };
    const { executeToolFixture } = await load(upstream!, 'packages/test-support/tool-testkit/lib/index.js') as {
      executeToolFixture(ctx: Context, input: object): Promise<{ isError: boolean; content: { type: string; text?: string }[] }>;
    };

    const pool = new pg.Pool({ connectionString: DSN, max: 4 });
    const tls = await tlsFixture();
    let fixture: Awaited<ReturnType<typeof createProductHostFixture>> | undefined;
    let authorizationServer: RequestListener | undefined;
    let resourceServer: RequestListener | undefined;
    let tokens = 0;
    let publications = 0;
    let resourceRequests = 0;
    try {
      const publisher = await tls.start((request, response) => {
        const material = fixture?.publicMaterials;
        if (!material || request.method !== 'GET') { response.writeHead(404).end(); return; }
        const value = JSON.parse(material.metadata) as { client_id: string; jwks_uri: string };
        const part = request.url === new URL(value.client_id).pathname ? material.metadata
          : request.url === new URL(value.jwks_uri).pathname ? material.jwks : undefined;
        if (!part) { response.writeHead(404).end(); return; }
        publications++;
        response.writeHead(200, { 'content-type': 'application/json' }).end(part);
      }, 'identity.example');
      const as = await tls.start((request, response) => {
        if (request.url === '/oauth/token' && request.method === 'POST') tokens++;
        if (authorizationServer) authorizationServer(request, response); else response.writeHead(503).end();
      }, 'localhost');
      const rs = await tls.start((request, response) => {
        if (request.url === '/mcp') resourceRequests++;
        if (resourceServer) resourceServer(request, response); else response.writeHead(503).end();
      }, 'localhost');
      const resource = `${rs.origin}/mcp`;
      const store = new PostgresStore(pool, as.origin);
      await store.configureRequestLimits({ globalMinute: 240, originMinute: 120, clientMinute: 60, sourceMinute: 120 });
      await store.configurePolicy({ resource, scopes, ttl: 300, maxNewClientsHour: 10, maxRequestsClientMinute: 30,
        maxRequestsMinute: 120, custodyCondition: 'Native ANP Identity product test', enabled: true });
      const secret = randomBytes(32).toString('base64url');
      await store.provisionResourceServer('cimd-provider-rs', secret, [resource]);
      authorizationServer = createAuthorizationServer(store, new ClientAuthenticator(tls.fetcher(), as.origin), scopes);
      resourceServer = createMcpApp(new TokenVerifier(tls.fetcher(), { issuer: as.origin, introspectionEndpoint: `${as.origin}/oauth/introspect`,
        resource, rsId: 'cimd-provider-rs', rsSecret: secret, allowedScopes: scopes }));
      const lanes = new Map([as.origin, rs.origin].map(origin => [origin, createTestMachineFetch({ origin, ca: tls.cert })]));
      transport.send = (input, init, beforeSend) => {
        const lane = lanes.get(new URL(input instanceof Request ? input.url : String(input)).origin);
        if (!lane) throw new Error('Unexpected isolated product-test origin');
        return lane(input, init, beforeSend);
      };
      fixture = await createProductHostFixture({ source: userService!, python: python!, publicationOrigin: publisher.origin });
      const identityRef = fixture.publicRef;
      const policy: ProtocolUsePolicy = { id: 'cimd-product', version: 1, consumer: MCP, owner: '@agent-network-protocol/dsh-anp-identity',
        identity: identityRef, profiles: ['mcp_machine'], issuers: [as.origin], resources: [resource], publicTargets: false,
        scopes, expiresAt: Date.now() + 600000 };
      const stateRoot = join(fixture.root, 'machine-state');
      const configPath = join(fixture.root, 'cordis.yml');
      const mcpConfig = { transport: 'streamable-http', serverName: 'product', url: resource,
        failOnStartupError: true, reconnect: { enabled: false }, authentication: { mode: 'cimd-client-credentials', provider: 'anp-identity',
          credentialRef: 'default', connectionId: 'native-provider', stateRoot, encryptionKeyRef: 'CIMD_PRODUCT_KEY', issuer: as.origin, requestedScopes: scopes } };
      await writeFile(configPath, `- name: '${MCP}'\n  config: ${JSON.stringify(mcpConfig)}\n`);
      const modules = { [ADAPTER]: adapter, [MCP]: mcp, 'cordis:include': include, '@deepseek-ai/dsh-system-prompt': systemPrompt,
        '@deepseek-ai/dsh-tools': tools, '@deepseek-ai/dsh-tool-executor-native': nativeExecutor };
      const mount = async (protocolPolicies: ProtocolUsePolicy[], signer: boolean) => {
        const ctx = await fixture!.reopen({ protocolPolicies, modules, entries: [
          { name: '@deepseek-ai/dsh-system-prompt' }, { name: '@deepseek-ai/dsh-tools' }, { name: '@deepseek-ai/dsh-tool-executor-native' },
          ...(signer ? [{ name: ADAPTER, config: { bindings: { default: { identityRef, policyRef: policy.id } } } }] : []),
        ] }) as ProductContext;
        ctx.baseUrl = pathToFileURL(upstream! + '/').href;
        ctx.loader.builtins.include = include;
        ctx.loader.internal = { version: 'v2', import: async (name: string) => {
          if (!Object.hasOwn(modules, name)) throw new Error('Unexpected product-test plugin');
          return modules[name as keyof typeof modules];
        } } as unknown as NonNullable<typeof ctx.loader.internal>;
        const credentials = ctx.get('credentials') as { set(ref: string, value: string): Promise<void>; resolve(ref: string): Promise<unknown> };
        if (!await credentials.resolve('CIMD_PRODUCT_KEY')) await credentials.set('CIMD_PRODUCT_KEY', randomBytes(32).toString('base64url'));
        await ctx.loader.create({ name: 'cordis:include', config: { path: pathToFileURL(configPath).href } });
        await ctx.loader.await();
        const entry = [...ctx.loader.entries()].find(candidate => candidate.options.name === MCP);
        if (!entry?.fiber) throw new Error('The MCP row from cordis.yml was not installed by the Loader');
        return { ctx, fiber: entry.fiber };
      };

      const name = 'mcp__product__identity_get';
      const unavailable = await mount([policy], false);
      await expect(unavailable.fiber.await()).rejects.toThrow(/initial connection or tool synchronization failed/u);
      expect(unavailable.ctx.tools.schemas().map(value => value.name)).not.toContain(name);
      const denied = await mount([], true);
      await expect(denied.fiber.await()).rejects.toThrow(/initial connection or tool synchronization failed/u);
      expect(denied.ctx.tools.schemas().map(value => value.name)).not.toContain(name);
      expect(tokens).toBe(0);
      const { ctx, fiber } = await mount([policy], true);
      await fiber.await();
      expect(ctx.tools.schemas().map(value => value.name)).toContain(name);
      const result = await executeToolFixture(ctx, { name, arguments: {}, callId: randomUUID(), signal: new AbortController().signal });
      expect(result.isError).toBe(false);
      const text = result.content.find(item => item.type === 'text')?.text;
      expect(JSON.parse(text!)).toMatchObject({ client_id: JSON.parse(fixture.publicMaterials.metadata).client_id, resource });
      expect(tokens).toBe(1);
      expect(publications).toBeGreaterThanOrEqual(2);
      expect(Number((await pool.query('SELECT count(*)::integer AS n FROM clients')).rows[0]?.n)).toBe(1);

      const providerEntry = [...ctx.loader.entries()].find(entry => entry.options.name === ADAPTER);
      if (!providerEntry) throw new Error('The signer row was not installed by the Loader');
      await ctx.loader.update(providerEntry.id, { disabled: true });
      await ctx.loader.await();
      const before = resourceRequests;
      const revoked = await executeToolFixture(ctx, { name, arguments: {}, callId: randomUUID(), signal: new AbortController().signal });
      expect(revoked.isError).toBe(true);
      expect(resourceRequests).toBe(before);
      expect(tokens).toBe(1);
    } finally {
      try { await fixture?.dispose(); }
      finally { transport.send = undefined; try { await tls.close(); } finally { await pool.end(); } }
    }
    expect(fixture?.evidence.cleanup.complete).toBe(true);
    await expect(stat(fixture!.root)).rejects.toMatchObject({ code: 'ENOENT' });
  }, 180000,
);
