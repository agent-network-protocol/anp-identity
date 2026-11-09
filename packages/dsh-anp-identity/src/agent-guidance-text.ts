export const IDENTITY_PROMPT = '帮我创建一个公共身份，用于登录三方服务（MCP、ANP、PAP）。需要手机号、邮箱或验证码时，请引导我在“身份管理”页面填写，不要在聊天里收集。';
export const AGENT_WORKFLOW_GUIDANCE = `公共身份 / ANP Identity is provided by the installed identity plugin, not a workspace or AWiki CLI task.
Only call tool names actually exposed in the current tool set; if missing, ask the owner to enable the plugin.
When the user asks to create a 公共身份, 创建身份 or identity for third-party login, immediately call identity_request_creation (or identity_status). Do not inspect source, shell history, credential files, identity vaults, browser private fields or awiki-cli. intentId identifies only the form request, not a creation approval. requestId in an active flow is the real approval request. The tool requests an owner form; it never creates keys, approves, sends verification codes or registers automatically.
For domain access use pap_connect({domain}), mcp_connect({domain}), and anp_discover({domain}); these perform discovery and connection without per-domain setup. Use identity_connection_guide for ANP/MCP/PAP access. Contact details and OTPs must be entered by the user in 身份管理, never in chat or tool arguments. When access approval is required, the global approval dialog opens automatically and the tool waits for the owner. Tell the user to use the dialog, never send them to Settings to find a new access request. Never approve on their behalf or replay an uncertain write. Do not claim an identity is published until status says published.
Only use discovered opaque references. Read operations use the global read policy; discovered writes or extra permissions require a separate exact owner consent dialog, never a permanent write grant. Never retry an uncertain write or silently switch protocols to bypass an error.`;

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
      prerequisites: 'Public discovery does not need an identity. Domain mode selects the Host default published identity for signed requests; discovered GET/HEAD reads use the global read policy without another approval. Writes or extra permissions open an exact-request approval dialog; wait for the owner, not Settings navigation. No per-domain configuration or guessed URLs.',
      missing: 'If anp_discover is not available, ask the owner to enable/configure the installed ANP plugin; do not install another CLI.',
    },
    pap: {
      order: ['pap_connect({domain:"agent-network-protocol.com"}) discovers Company and connects a signed-out Session automatically; only read operations are enabled by domain mode',
        'pap_operations()', 'pap_request({operationRef, query:{page:"1"}}) using a discovered operation; writes wait for the exact owner consent dialog'],
      parameters: 'path/query values must be strings; JSON body values keep their JSON types. Do not supply a URL, sessionRef, token or policyRef to pap_request.',
      authentication: 'no_as means signed-out PAP Session: no browser account login, OAuth token or account scopes. Account login is a separate owner action only when required.',
      missing: 'domain_access_disabled: enable global domain access once. default_identity_required: select one default identity once. Do not ask the owner to configure each domain. Discovered writes use pap_request to open a one-operation consent dialog; blocked operations remain blocked. Account login remains a separate explicit owner action. permission_denied: check operation permissions and parameter types.',
    },
    mcp: {
      discovery: 'https://agent-network-protocol.com/.well-known/oauth-protected-resource',
      exampleConnection: { url: 'https://agent.agent-network-protocol.com/mcp', issuer: 'https://agent.agent-network-protocol.com',
        scopes: ['protocol.read'], note: 'Use current discovery metadata if it differs; never send tokens to the website root.' },
      order: ['mcp_connect({domain:"agent-network-protocol.com"}) automatically discovers and validates the actual resource, AS and permitted scopes, selects the Host default identity and connects.',
        'Use available mcp__<configuredServer>__<tool> tools and their declared input schemas.'],
      authentication: 'For this example use cimd-client-credentials. The built-in MCP client obtains private_key_jwt/token; do not read signing keys, paste tokens or use browser login.',
      missing: 'No mcp__ business tools: first call mcp_connect with the domain. It may report connection/authentication failure; absence alone does not prove missing configuration. Missing mcp_connect means the global connector must be enabled once. Never request per-domain URLs, keys or tokens.',
    },
  };
  return { ...shared, guides: protocol === 'all' ? guides : { [protocol]: guides[protocol as keyof typeof guides] } };
}
