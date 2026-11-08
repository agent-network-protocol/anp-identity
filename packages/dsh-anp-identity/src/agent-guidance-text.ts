export const IDENTITY_PROMPT = '帮我创建一个公共身份，用于登录三方服务（MCP、ANP、PAP）。需要手机号、邮箱或验证码时，请引导我在“身份管理”页面填写，不要在聊天里收集。';
export const AGENT_WORKFLOW_GUIDANCE = `公共身份 / ANP Identity is provided by the installed identity plugin, not a workspace or AWiki CLI task.
Only call tool names actually exposed in the current tool set; if missing, ask the owner to enable the plugin.
When the user asks to create a 公共身份, 创建身份 or identity for third-party login, immediately call identity_request_creation (or identity_status). Do not inspect source, shell history, credential files, identity vaults, browser private fields or awiki-cli. intentId identifies only the form request, not a creation approval. requestId in an active flow is the real approval request. The tool requests an owner form; it never creates keys, approves, sends verification codes or registers automatically.
Use identity_connection_guide for ANP/MCP/PAP access. Contact details and OTPs must be entered by the user in 身份管理, never in chat or tool arguments. If approval/user input is needed, stop and tell the user where to act. Do not claim an identity is published until status says published.
Only use discovered opaque references and user-enabled operations. Never retry an uncertain write or silently switch protocols to bypass an error.`;

export function connectionGuide(protocol: string, availableTools: readonly string[]) {
  const example = 'agent-network-protocol.com';
  const shared = { example, registeredTools: [...availableTools], identitySettings: '设置 → 身份管理',
    safety: ['Do not inspect files, private keys, tokens or unrelated identity CLIs.',
      'Wait for exact identity approvals; do not request OTPs in chat.',
      'Read before writing; publish a post only on explicit user request.',
      'A failed/uncertain POST is not safe to replay.'] };
  const guides = {
    anp: {
      order: ['anp_discover({domain:"agent-network-protocol.com"})', 'anp_describe({agentRef})',
        'anp_read({resourceRef}) for the discovered OpenAPI interface', 'anp_call({operationRef,...}) for a discovered operation'],
      prerequisites: 'A configured/enabled ANP plugin and an owner-approved public identity for signed reads/calls. No guessed URLs or references.',
      missing: 'If anp_discover is not available, ask the owner to enable/configure the installed ANP plugin; do not install another CLI.',
    },
    pap: {
      order: ['pap_status()', 'Owner: PAP 连接 → select a published identity → discover Company agent-network-protocol.com → connect → enable an operation',
        'pap_operations()', 'pap_request({operationRef, query:{page:"1"}}) using that enabled operation'],
      parameters: 'path/query values must be strings; JSON body values keep their JSON types. Do not supply a URL, sessionRef, token or policyRef to pap_request.',
      authentication: 'no_as means signed-out PAP Session: no browser account login, OAuth token or account scopes. Account login is a separate owner action only when required.',
      missing: 'disabled/not_configured/permission_denied: check owner configuration, enabled operation and parameter types; never bypass them.',
    },
    mcp: {
      discovery: 'https://agent-network-protocol.com/.well-known/oauth-protected-resource',
      exampleConnection: { url: 'https://agent.agent-network-protocol.com/mcp', issuer: 'https://agent.agent-network-protocol.com',
        scopes: ['protocol.read','message.write'], note: 'Use current discovery metadata if it differs; never send tokens to the website root.' },
      order: ['Read resource, authorization_servers and scopes_supported from the discovery document.',
        'Owner configures the actual resource MCP URL (not the website root), issuer, identityRef and exact policyRef.',
        'Use available mcp__<configuredServer>__<tool> tools and their declared input schemas.'],
      authentication: 'For this example use cimd-client-credentials. The built-in MCP client obtains private_key_jwt/token; do not read signing keys, paste tokens or use browser login.',
      missing: 'No mcp__ tool means no active configured connection. Ask the owner to configure it; do not guess a serverName or curl business requests.',
    },
  };
  return { ...shared, guides: protocol === 'all' ? guides : { [protocol]: guides[protocol as keyof typeof guides] } };
}
