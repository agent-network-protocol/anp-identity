import { useEffect, useState, useSyncExternalStore } from 'react'
import { Button } from '@deepseek-ai/dsh-client-ui-primitives'
import { protocolNames, protocolPolicyInputSchema, type ProtocolPolicy, type ProtocolPolicyInput } from '../protocol-policy-types.js'
import type { IdentityController } from './controller.js'

const labels = { allow_all: '全部允许', whitelist: '仅白名单', ask: '每次确认', deny: '全部禁止' } as const
/** Shared settings contribution owned by Identity, independent of PAP/ANP installation order. */
export function ProtocolSettings({ controller }: { controller: IdentityController }) {
  const view = useSyncExternalStore(controller.subscribe, controller.getSnapshot)
  const saved = view.protocolManagement
  const [draft, setDraft] = useState<ProtocolPolicyInput | null>(null)
  const [version, setVersion] = useState(0)
  const [dirty, setDirty] = useState(false)
  const [inputError, setInputError] = useState<string | null>(null)
  const load = (policy: ProtocolPolicy | undefined = saved?.policy) => {
    if (!policy) return
    setDraft({ read: structuredClone(policy.read), write: structuredClone(policy.write) })
    setVersion(policy.version); setDirty(false); setInputError(null)
    controller.dismissProtocolSaveError()
  }
  useEffect(() => { if (!dirty && saved) load() }, [saved?.policy.version, dirty])
  const edit = (action: 'read' | 'write', rule: ProtocolPolicyInput['read']) => {
    if (!draft) return
    setDraft({ ...draft, [action]: rule }); setDirty(true); setInputError(null)
  }
  const stale = !!saved && saved.policy.version !== version
  return <section className="anpi anpi-protocols">
    <h2>协议管理</h2>
    <p className="anpi-muted">输入域名后自动发现与连接，统一使用已发布的默认身份</p>
    {view.protocolError && <p role="alert" className="anpi-error">{view.protocolError}</p>}
    {view.protocolSaveError && <p role="alert" className="anpi-error">{view.protocolSaveError}</p>}
    {!saved || !draft ? <Button onClick={async () => { const policy = await controller.reloadProtocolPolicy(); if (policy) load(policy) }}>重新加载协议配置</Button> : <>
      <div className="anpi-section"><h3>协议状态</h3>
        {!saved.domainAccessEnabled && <p className="anpi-small">Host 尚未开启全局域名接入；此页面不会代替 Host 启用协议或创建身份</p>}
        {saved.protocols.map(item => <div className="anpi-row" key={item.protocol}>
          <span>{item.protocol.toUpperCase()}</span>
          <span className="anpi-small">{!item.installed ? '未安装' : !item.enabled ? '未启用' : item.unmanagedAdapters ? `存在未受管适配器（${item.unmanagedAdapters}）` : item.ready ? '已受管 · 身份就绪' : '已受管 · 身份未就绪'}</span>
        </div>)}
        <p className="anpi-small">未受管的 MCP 连接不受本页规则控制，需要更新或接入官方客户端权限钩子；“身份就绪”不代表已连接某个远端服务</p>
      </div>
      <div className="anpi-section"><h3>权限管理</h3>
        <p className="anpi-small">只读操作须有明确、无冲突的发现声明；未知操作、支付和额外权限仍需单独确认。允许访问不会绕过远端认证或账户权限</p>
        {(['read', 'write'] as const).map(action => {
          const rule = draft[action], title = action === 'read' ? '读取' : '写入'
          return <fieldset key={action} disabled={view.protocolSaving}>
            <legend>{title}权限</legend>
            <label>{title}模式<select aria-label={`${title}模式`} value={rule.mode} onChange={event => edit(action, { ...rule, mode: event.target.value as typeof rule.mode })}>
              {Object.entries(labels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select></label>
            {rule.mode === 'whitelist' && <>
              <label>白名单外<select aria-label={`${title}白名单外`} value={rule.outside} onChange={event => edit(action, { ...rule, outside: event.target.value as 'ask' | 'deny' })}>
                <option value="ask">每次确认</option><option value="deny">全部禁止</option>
              </select></label>
              {rule.domains.map((entry, index) => <div className="anpi-protocol-domain" key={index}>
                <label>域名<input aria-label={`${title}域名 ${index + 1}`} placeholder="example.com" value={entry.domain} onChange={event => edit(action, { ...rule, domains: rule.domains.map((item, at) => at === index ? { ...item, domain: event.target.value } : item) })} /></label>
                <div className="anpi-actions">{protocolNames.map(protocol => <label key={protocol}>
                  <input type="checkbox" aria-label={`${title}域名 ${index + 1} ${protocol.toUpperCase()}`} checked={entry.protocols.includes(protocol)} onChange={event => edit(action, { ...rule, domains: rule.domains.map((item, at) => at !== index ? item : { ...item, protocols: event.target.checked ? [...item.protocols, protocol] : item.protocols.filter(value => value !== protocol) }) })} /> {protocol.toUpperCase()}
                </label>)}<Button size="sm" onClick={() => edit(action, { ...rule, domains: rule.domains.filter((_, at) => at !== index) })}>移除域名 {index + 1}</Button></div>
              </div>)}
              <Button disabled={rule.domains.length >= 256} onClick={() => edit(action, { ...rule, domains: [...rule.domains, { domain: '', protocols: [...protocolNames] }] })}>添加{title}域名</Button>
              <p className="anpi-small">域名精确匹配，不自动包含子域名；发现后的服务地址仅在已验证的发现绑定内适用</p>
            </>}
            {action === 'write' && rule.mode === 'allow_all' && <p className="anpi-small">保存后，已发现且明确分类的普通写入可持续执行而不逐次弹窗，直到你修改本规则；这不授予通用签名或密钥访问</p>}
          </fieldset>
        })}
        {stale && dirty && <p role="alert" className="anpi-error">配置已在其他页面更新；草稿已保留，请重新加载并核对后再保存</p>}
        {inputError && <p role="alert" className="anpi-error">{inputError}</p>}
        <div className="anpi-actions">
          <Button disabled={!dirty || stale || view.protocolSaving || !!view.protocolError} onClick={async () => {
            const parsed = protocolPolicyInputSchema.safeParse(draft)
            if (!parsed.success) { setInputError('请填写有效域名，并为每个域名选择至少一个协议'); return }
            if (await controller.configureProtocolPolicy({ expectedVersion: version, policy: parsed.data })) setDirty(false)
          }}>{view.protocolSaving ? '保存中…' : '保存权限'}</Button>
          <Button disabled={view.protocolSaving} onClick={async () => { const policy = await controller.reloadProtocolPolicy(); if (policy) load(policy) }}>重新加载配置</Button>
          <Button disabled={view.protocolSaving} onClick={() => { void controller.refresh() }}>刷新状态</Button>
        </div>
      </div>
    </>}
    <div className="anpi-section"><h3>支持公共身份的服务</h3>
      <p><a href="https://agent-network-protocol.com/" target="_blank" rel="noreferrer">Agent Network Protocol 官网</a>：ANP 协议文档与社区信息</p>
      <p><a href="https://matchall.net/" target="_blank" rel="noreferrer">Matchall</a>：公共匹配服务</p>
      <p className="anpi-small">以上服务支持 ANP、PAP、MCP 公共身份接入。展示目录不是权限白名单，收录不授予写入权限，未收录域名也可以发现和连接</p>
      <p className="anpi-small">欢迎支持我们的公共身份方案！请查看 <a href="https://github.com/AgentConnect/service-agent" target="_blank" rel="noreferrer">Service Agent GitHub 接入说明</a>，通过互通验证后可申请将你的域名加入插件服务目录</p>
    </div>
  </section>
}
