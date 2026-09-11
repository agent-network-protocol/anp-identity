import { randomUUID } from 'node:crypto';
import { Remote, TypertRemoteService } from '@deepseek-ai/dsh-typert-protocol';
import { bindIdentityClient } from '@agent-network-protocol/dsh-anp-identity/user-client';
import contribution from './remote.js';

export default class HttpDemo extends TypertRemoteService {
  static inject = ['anpIdentity', 'typert'];
  client: any; config: any; pending: any; reference: any; grantId?: string;
  busy = false; stopped = false;
  state: any = { phase: 'idle', events: [], result: null, checks: null, error: null };
  constructor(ctx: any) {
    super(ctx, 'anpHttpDemo');
    this.config = JSON.parse(requireConfig());
    // Bind lazily after the authoritative Loader publishes its installed entry.
    const ordinary = () => this.client ??= bindIdentityClient(ctx);
    ctx.effect(() => ctx.typert.register({ package: contribution.package, face: 'host', schemas: [], model: { services: [], events: [], objects: [] }, invocations: contribution.descriptors }));
    const timer = setInterval(() => { if (!this.stopped && !this.busy && this.pending) void this.advance(ordinary); }, 500);
    ctx.effect(() => () => { this.stopped = true; clearInterval(timer); });
    this.getClient = ordinary;
  }
  getClient: any;
  event(text: string) { this.state.events.push({ text, time: new Date().toLocaleTimeString('zh-CN', { hour12: false }) }); this.state.events = this.state.events.slice(-30); }
  snapshot() { return { ...this.state, origin: this.config.origin, identity: this.reference?.did ?? null }; }
  @Remote status() { return this.snapshot(); }
  @Remote async start() {
    if (this.busy || this.pending) return this.snapshot();
    this.busy = true;
    try {
      const id = randomUUID();
      this.state = { phase: 'creating', events: [], result: null, checks: null, error: null };
      this.reference = undefined; this.grantId = undefined;
      const request = await this.getClient().requestCreateIdentity({ requestId: `demo-create-${id}`, purpose: '为 HTTP 签名演示创建一个独立测试身份，不发布到域名。', parameters: { label: 'HTTP 签名演示', handle: `demo-${id}`, domain: 'localhost', path: `/demo/${id}` } });
      this.pending = { kind: 'create', id: request.id };
      this.event('演示插件已申请创建身份，等待你的确认');
    } catch (error) { this.failed(error); } finally { this.busy = false; }
    return this.snapshot();
  }
  async advance(ordinary: any) {
    this.busy = true;
    try {
      const job = this.pending;
      const request = job.kind === 'create' ? await ordinary().getCreateRequest(job.id) : await ordinary().getAccessRequest(job.id);
      if (request.status === 'pending' || (job.kind === 'create' && request.status === 'approved' && request.executionStatus === 'running')) return;
      if (request.status !== 'approved') { this.pending = undefined; this.state.phase = 'denied'; this.event('请求未获允许，演示已停止，不会绕过确认'); return; }
      this.pending = undefined;
      if (job.kind === 'create') {
        if (request.executionStatus !== 'succeeded' || !request.result?.reference) throw new Error('creation_result_unavailable');
        this.reference = request.result.reference; this.state.phase = 'publishing'; this.event('身份已创建；创建本身没有授予使用权限');
        const read = await ordinary().requestAccess({ requestId: `demo-read-${randomUUID()}`, identity: this.reference, purpose: '读取公开 DID 文档并提供给本地 Demo Server，用于验签；不传输私钥。', operation: { action: 'read' } });
        this.pending = { kind: 'read', id: read.id };
        this.event('申请读取公开身份文档，等待授权');
      } else if (job.kind === 'read') {
        const lease = await ordinary().openAuthorizedIdentity(request.grantId);
        const identity = await lease.publicIdentity(`demo-read-exec-${randomUUID()}`);
        await this.server('/enroll', identity.document);
        if (request.mode === 'permanent') this.grantId = request.grantId;
        this.state.phase = 'ready'; this.event('Server 已保存公开文档；可以申请并发送签名请求');
      } else await this.dispatch(request.grantId);
    } catch (error) { this.failed(error); } finally { this.busy = false; }
  }
  makeRequest() { return new Request(`${this.config.origin}/hello`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: 'Hello from the ANP identity demo plugin!' }), signal: AbortSignal.timeout(15000) }); }
  @Remote async send() {
    if (this.busy || this.pending || !this.reference || !['ready', 'success'].includes(this.state.phase)) return this.snapshot();
    this.busy = true;
    try {
      this.state.error = null; this.state.checks = null;
      if (this.grantId) await this.dispatch(this.grantId);
      else {
        const request = await this.getClient().requestAccess({ requestId: `demo-http-${randomUUID()}`, identity: this.reference, purpose: '以这个身份向本地 Demo Server 发送一条带签名的 HTTPS POST 请求。', operation: { action: 'http', request: this.makeRequest() } });
        this.pending = { kind: 'http', id: request.id }; this.state.phase = 'authorizing'; this.event('已申请签名 HTTP 操作，等待你的授权');
      }
    } catch (error) { this.failed(error); } finally { this.busy = false; }
    return this.snapshot();
  }
  async dispatch(grantId: string) {
    this.state.phase = 'sending'; this.event('Host 使用请求密钥生成签名，并发送真实 HTTPS 请求');
    const lease = await this.getClient().openAuthorizedIdentity(grantId);
    const response = await lease.authenticatedHttp.dispatch(this.makeRequest(), `demo-http-exec-${randomUUID()}`);
    const result = await response.json();
    this.state.result = { httpStatus: response.status, ...result };
    if (!response.ok || !result.verified) throw new Error(result.error ?? 'server_verification_failed');
    this.state.phase = 'success'; this.event('Demo Server 独立验签通过，返回 HTTP 200');
  }
  async server(path: string, body: unknown) {
    const response = await fetch(`${this.config.origin}${path}`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-demo-control': this.config.control }, body: JSON.stringify(body), signal: AbortSignal.timeout(10000) });
    const result = await response.json(); if (!response.ok) throw new Error(result.error ?? 'demo_server_error'); return result;
  }
  @Remote async checks() {
    if (this.busy || this.state.phase !== 'success') return this.snapshot();
    this.busy = true;
    try { this.state.checks = await this.server('/checks', {}); this.event('Server 完成正文篡改、签名篡改和重放检查'); }
    catch (error) { this.state.error = safeCode(error); } finally { this.busy = false; }
    return this.snapshot();
  }
  failed(error: any) { this.pending = undefined; this.state.phase = 'error'; this.state.error = safeCode(error); this.event('操作停止，请查看错误或重新开始；不会自动重试一次性授权'); }
}
import { readFileSync } from 'node:fs';
function requireConfig() { return readFileSync(process.env.ANP_HTTP_DEMO_CONFIG!, 'utf8'); }
function safeCode(error: any) { const value = error?.code ?? error?.message; return typeof value === 'string' && /^[A-Za-z0-9_/-]{1,100}$/.test(value) ? value : 'demo_operation_failed'; }
