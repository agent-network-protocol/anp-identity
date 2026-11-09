import type { Context } from '@deepseek-ai/cordis';

import { AGENT_WORKFLOW_GUIDANCE, connectionGuide } from './agent-guidance-text.js';
export { IDENTITY_PROMPT, AGENT_WORKFLOW_GUIDANCE, connectionGuide } from './agent-guidance-text.js';

export function registerIdentityGuidance(ctx: Context, handlers: {
  status(): Promise<unknown>;
  request(): Promise<unknown>;
}): void {
  ctx.inject(['tools'], inner => {
    const tools = inner.get('tools') as { register(value: object): unknown; definitions?(): readonly {name:string}[] };
    const output = { schema: { type: 'object', additionalProperties: true },
      render: (_args: unknown, value: unknown) => [{ type: 'text', text: JSON.stringify(value) }] };
    let active = true;
    inner.effect(() => () => { active = false; });
    const register = (name: string, description: string, parameters: object, run: (args: any) => Promise<unknown>) =>
      tools.register({ name, description, parameters, output, execute: async (args: any, execution: {agent?:unknown;signal?:AbortSignal}) => {
        if (!active || !execution.agent || execution.signal?.aborted) return { ok: false, error: 'identity_guidance_unavailable' };
        if (args !== undefined && (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(args).some(key => !Object.hasOwn((parameters as {properties:object}).properties, key)))) return { ok:false,error:'invalid_parameters' };
        try { const value = await run(args ?? {}); return active && !execution.signal?.aborted ? {ok:true,value} : {ok:false,error:'identity_guidance_unavailable'}; }
        catch { return { ok:false,error:'identity_guidance_unavailable',action:'打开 设置 → 身份管理；不要搜索源码、密钥或其他 CLI。' }; }
      } });
    const empty = { type: 'object', properties: {}, additionalProperties: false };
    register('identity_status', '公共身份 / ANP Identity 状态。查询本机公开身份、发布状态和当前注册阶段；不要查源码、匿名 ID、私钥目录或 awiki-cli。未创建时使用 identity_request_creation。', empty, handlers.status);
    register('identity_request_creation', '创建公共身份、创建用于登录三方服务的身份时，首先调用此工具。只打开用户的“身份管理”创建表单，不直接创建私钥、审批、发短信或注册。手机号/邮箱/验证码由用户在界面输入，绝不在聊天中收集；调用后等待用户操作，不要重复调用或搜索文件/CLI。', empty, handlers.request);
    register('identity_connection_guide', 'ANP访问、MCP连接、PAP调用的快速引导和实际可用工具名。即使身份/协议插件尚未配置也可调用。说明发现顺序、授权、参数格式和错误恢复，避免盲查文件或猜测接口。', {
      type:'object',additionalProperties:false,properties:{protocol:{type:'string',enum:['all','anp','mcp','pap']}},required:[],
    }, async args => {
      const protocol = args.protocol === undefined ? 'all' : args.protocol; if (!['all','anp','mcp','pap'].includes(protocol)) throw new Error('invalid_protocol');
      return connectionGuide(protocol, (tools.definitions?.() ?? []).map(x=>x.name).filter(name=>/^(?:anp_|pap_|mcp__|mcp_connect$)/u.test(name)));
    });
  });
  ctx.inject(['systemPrompt'], inner => {
    const prompt = inner.get('systemPrompt') as { context(input: object): unknown };
    prompt.context({ name: 'public-identity-and-protocol-guide', order: 60, required: true,
      interpolate: false, text: AGENT_WORKFLOW_GUIDANCE });
  });
}
