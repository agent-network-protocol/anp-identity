import type { RegistrationBootstrapStatus } from '../registration-bootstrap.js';
import { composeRegistrationPhone } from '../registration-onboarding-types.js';
import { IDENTITY_PROMPT } from '../agent-guidance-text.js';
import type { RegistrationServiceSettings } from '../registration-service-types.js';
import {
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import { Button, Modal } from "@deepseek-ai/dsh-client-ui-primitives";
import type {
  AuthorizationMode,
  AuthorizationRequest,
  CapabilitySnapshot,
} from "../authorization-types.js";
import {
  IdentityController,
  identityKey,
  identityReference,
} from "./controller.js";
import type {
  ManagedIdentitySummary,
  RequestReview,
} from "../management-types.js";

export const FULL_PERMISSION_NOTICE =
  "当前默认授予该身份的全部使用权限，暂不支持逐项选择。";
const modeLabel = (mode: AuthorizationMode): string =>
  mode === "once" ? "单次授权" : "永久授权";
const identityLabel = (identity: ManagedIdentitySummary): string =>
  identity.label || identity.reference.did;
const capabilityNames: Record<string, string> = {
  "identity:read": "公开身份信息",
  "identity:sign": "签名",
  "identity:http-auth": "网站认证",
};
const isExactSnapshot = (snapshot: CapabilitySnapshot | undefined): boolean =>
  snapshot?.version === 'anp-domain/1' || snapshot?.version === 'domain-operation/1';
function CopyRow({
  label,
  value,
  controller,
}: {
  label: string;
  value?: string | undefined;
  controller: IdentityController;
}): ReactNode {
  return (
    <div className={`anpi-copy${label === "DID" ? " anpi-copy-did" : ""}`}>
      <span className="anpi-field-label">{label}</span>
      <span className={`anpi-break anpi-field-value${value ? "" : " anpi-muted"}`}>{value || "未设置"}</span>
      {value && (
        <Button
          size="sm"
          aria-label={`复制 ${label}`}
          onClick={() => {
            void controller.copy(value);
          }}
        >
          复制
        </Button>
      )}
    </div>
  );
}
function Scope({
  snapshot,
}: {
  snapshot?: CapabilitySnapshot | undefined;
}): ReactNode {
  if (isExactSnapshot(snapshot)) return <p className="anpi-small">仅授权当前请求的网站认证，不包含永久权限、通用签名或其他操作。</p>;
  return (
    <>
      <h3>全部使用权限</h3>
      {snapshot ? (
        <>
          <ul>
            {snapshot.capabilities.map((capability) => (
              <li key={capability}>
                {capabilityNames[capability] ?? capability}
              </li>
            ))}
          </ul>
          <p>签名用途：{snapshot.signingPurposes.join("、") || "无"}</p>
          {!!snapshot.oauthAudiences?.length && <p>OAuth 目标：{snapshot.oauthAudiences.join("、")}</p>}
          <p className="anpi-break">
            网站：{snapshot.httpOrigins.includes('*') ? '全部 HTTPS 域名（通配权限）' : snapshot.httpOrigins.join("、") || "无"}
          </p>
        </>
      ) : (
        <p>无法读取权限范围，暂不能授权。</p>
      )}
      <p className="anpi-small">{FULL_PERMISSION_NOTICE}</p>
      <p className="anpi-small">{snapshot?.capabilities.includes('identity:sign') ? '签名可在外部使用，不受网站列表限制。' : '仅允许公开身份读取与精确 HTTP 请求认证，不提供设备断言或通用签名权限。'}</p>
    </>
  );
}

function RegistrationForm({ controller }: { controller: IdentityController }): ReactNode {
  const view = useSyncExternalStore(controller.subscribe, controller.getSnapshot);
  const [label, setLabel] = useState("三方服务公共身份");
  const [handle, setHandle] = useState("");
  const [method, setMethod] = useState<"phone" | "email">("phone");
  const [contact, setContact] = useState("");
  const [dialingCode, setDialingCode] = useState("+86");
  const [customCode, setCustomCode] = useState("+");
  const [contactError, setContactError] = useState<string | null>(null);
  const [profile, setProfile] = useState<"e1" | "web">("e1");
  const [origin] = useState(view.registrationService?.origin ?? "https://awiki.me");
  return <form onSubmit={event => {
    event.preventDefault();
    const code = dialingCode === "other" ? customCode : dialingCode;
    const phone = method === "phone" ? composeRegistrationPhone(code, contact) : undefined;
    if (method === "phone" && !phone) {
      setContactError(!/^\+[1-9][0-9]{0,3}$/u.test(code) ? "国家码格式不正确，请填写 +国家码，例如 +86。"
        : code === "+86" ? "中国大陆手机号应为有效的11位数字。国家码已在左侧选择，手机号框不要重复填写 +86。"
        : "手机号格式不正确，请只填写号码，不含国家码；国家码请在左侧选择。");
      return;
    }
    if (!/^[a-z][a-z0-9-]{2,39}$/u.test(handle)) { setContactError("Handle 请使用3–40位小写字母、数字或连字符，并以字母开头。"); return; }
    setContactError(null);
    void controller.startIdentityRegistration({ label, handle, profile, expectedOrigin: origin,
      expectedVersion: view.onboarding?.version ?? 0, ...(method === "phone" ? { phone: phone! } : { email: contact.trim() }) });
  }}>
    <p>注册服务：{origin}</p>
    <label>身份名称<input aria-label="身份名称" required maxLength={128} value={label} onChange={event => setLabel(event.target.value)} /></label>
    <label>Handle<input aria-label="Handle" required minLength={3} maxLength={40} value={handle} onChange={event => setHandle(event.target.value)} placeholder="your-name" /></label>
    <p className="anpi-small">3–40 位小写字母、数字和连字符，以字母开头，不含域名。创建的是新的公共身份，不是导入已有私钥。</p>
    <label>验证方式<select aria-label="验证方式" value={method} onChange={event => { setMethod(event.target.value as "phone" | "email"); setContact(""); setContactError(null); }}>
      <option value="phone">手机号</option><option value="email">邮箱</option></select></label>
    {method === "phone" ? <div style={{display:"grid",gridTemplateColumns:"minmax(125px,35%) minmax(0,1fr)",gap:12}}>
      <label>国家/地区码<select aria-label="国家/地区码" value={dialingCode} onChange={event=>{setDialingCode(event.target.value);setContactError(null);}}>
        <option value="+86">中国大陆 +86</option><option value="+852">中国香港 +852</option>
        <option value="+853">中国澳门 +853</option><option value="+886">中国台湾 +886</option>
        <option value="+1">美国/加拿大 +1</option><option value="+65">新加坡 +65</option>
        <option value="+81">日本 +81</option><option value="+44">英国 +44</option>
        <option value="+49">德国 +49</option><option value="+33">法国 +33</option>
        <option value="+61">澳大利亚 +61</option><option value="+91">印度 +91</option>
        <option value="other">其他国家/地区</option>
      </select>{dialingCode==="other"&&<input aria-label="自定义国家码" value={customCode} onChange={event=>{setCustomCode(event.target.value);setContactError(null);}} placeholder="+国家码" />}</label>
      <label>手机号<input aria-label="注册手机号" type="tel" inputMode="numeric" autoComplete="off" required value={contact}
        onChange={event=>{setContact(event.target.value);setContactError(null);}} placeholder={dialingCode==="+86"?"11位手机号，不含国家码":"号码，不含国家码"} /></label>
    </div> : <label>邮箱<input aria-label="注册邮箱" type="email" autoComplete="off" required value={contact}
        onChange={event=>{setContact(event.target.value);setContactError(null);}} placeholder="you@example.com" /></label>}
    {method==="phone"&&<p className="anpi-small">默认中国大陆 +86。国家码与手机号分开填写，提交时会合并为国际格式。</p>}
    {contactError && <p role="alert">{contactError}</p>}
    <details><summary>高级：身份类型</summary><select aria-label="身份类型" value={profile} onChange={event => setProfile(event.target.value as "e1" | "web")}><option value="e1">E1（默认）</option><option value="web">Web（无根控制）</option></select></details>
    <p className="anpi-small">本次用途为 MCP / ANP / PAP 登录，不包含消息能力或账户回调授权。提交只申请创建；你还需在下一步批准，随后才发送验证码并验证、发布。不会自动授权第三方访问。</p>
    <p className="anpi-small">手机号、邮箱和验证码不提供给 Agent；不要把验证码发到聊天中。</p>
    <div className="anpi-footer"><Button type="button" disabled={view.pending} onClick={() => controller.closeModal()}>稍后</Button>
      <Button type="submit" disabled={view.pending || origin !== view.registrationService?.origin || !label.trim() || !handle.trim() || !contact.trim()}>申请创建并注册</Button></div>
  </form>;
}

function RegistrationServiceForm({ controller, settings, pending }: {
  controller: IdentityController; settings: RegistrationServiceSettings; pending: boolean;
}): ReactNode {
  const [draft, setDraft] = useState(settings.origin);
  const [version, setVersion] = useState(settings.version);
  const [dirty, setDirty] = useState(false);
  useEffect(() => {
    if (!dirty) { setDraft(settings.origin); setVersion(settings.version); }
  }, [settings.origin, settings.version, dirty]);
  return <div className="anpi-section">
    <h3>身份服务</h3>
    <form onSubmit={event => {
      event.preventDefault();
      void controller.configureRegistrationService(draft, version).then(saved => { if (saved) setDirty(false); });
    }}>
      <label>身份服务地址 <input aria-label="身份服务地址" type="url" required value={draft}
        placeholder="https://awiki.me" disabled={pending}
        onChange={event => { setDraft(event.target.value); setDirty(true); }} /></label>
      <Button disabled={pending || !dirty || !draft.trim()} type="submit">保存服务地址</Button>
      {dirty && <Button disabled={pending} type="button" onClick={() => {
        setDraft(settings.origin); setVersion(settings.version); setDirty(false);
      }}>重新载入已保存地址</Button>}
    </form>
    <p className="anpi-small">默认 https://awiki.me。这里只保存新注册使用的 HTTPS 根地址，不发送验证码、不创建身份。</p>
    <p className="anpi-small">已有身份和正在进行的注册继续使用原服务。跨服务注册必须创建新的身份及注册流程，不能只修改已有 DID 的域名。</p>
  </div>;
}

/** Shared owner-only registration progress for settings and the approval continuation. */
function RegistrationProgress({ controller, bootstrap, approvalCompleted = false }: {
  controller: IdentityController; bootstrap: RegistrationBootstrapStatus; approvalCompleted?: boolean;
}): ReactNode {
  const view = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const [otp, setOtp] = useState('');
  const handle = bootstrap.reference && view.identities.find(identity => identityKey(identity.reference) === identityKey(bootstrap.reference!))?.handle;
  return <div className="anpi-section" role="status">
        <h3>协议身份注册</h3>
        {bootstrap.origin && <p className="anpi-small">注册服务：{bootstrap.origin}</p>}
        {bootstrap.clientVersion && <p className="anpi-small">客户端版本头：{bootstrap.clientVersion}</p>}
        <p>{({ awaiting_approval: approvalCompleted ? '创建已批准，正在准备验证' : '等待创建审批', awaiting_email_verification: '等待邮箱激活确认', awaiting_phone_verification: '等待短信验证码', registering: '注册中',
          publishing: '发布中', published: '已发布', registration_uncertain: '注册结果不确定，需要管理处理', blocked: '注册暂不可用', disposed: '已停止' })[bootstrap.phase]}</p>
        {bootstrap.phase === 'awaiting_approval' && <div>
          {!approvalCompleted && view.requests.some(request => request.id === bootstrap.requestId && request.status === 'pending') ? <>
            <p className="anpi-small">下一步请确认创建。本步骤尚未发送验证码；批准创建且短信请求成功后，才会出现验证码输入框。</p>
            <Button disabled={view.pending || view.modal !== null} onClick={() => { void controller.openRequest(bootstrap.requestId); }}>继续创建审批</Button>
          </> : <p className="anpi-small">创建已批准，正在准备注册并请求验证码，请稍候。请勿重复创建；结果会在这里更新。</p>}
        </div>}
        {bootstrap.phase === 'published' && <p className="anpi-small">注册与发布已完成；还需由 Host 配置协议用途许可和消费者连接。</p>}
        {bootstrap.reason === 'client_upgrade_required' && <p className="anpi-small">短信未发送：注册服务拒绝了当前客户端版本（client.upgrade_required），这不是验证码错误。请让服务管理员核对上方服务地址和客户端版本准入；不要重复创建身份。</p>}
        {bootstrap.reason === 'phone_unavailable' && <p className="anpi-small">短信验证码请求未确认成功，请检查服务端手机号注册配置。不会自动重发或绕过验证。</p>}
        {bootstrap.phase === 'blocked' && ['phone_unavailable','client_upgrade_required'].includes(bootstrap.reason ?? '') &&
          <div><p className="anpi-small">修复服务或版本准入后，可手动重试发送验证码。沿用当前身份，不会再次创建或重放注册。</p>
            <Button disabled={view.pending} onClick={() => { void controller.retryRegistrationSms(); }}>重试发送验证码</Button></div>}
        {bootstrap.phase === 'awaiting_phone_verification'  && <form onSubmit={event => {
          event.preventDefault(); const code = otp; setOtp(''); void controller.submitRegistrationOtp(code);
        }}>
          <p className="anpi-small">发送请求已受理不等于短信已送达。请使用此注册服务为当前 Handle 签发的验证码，不能复用其他环境或登录流程的验证码。</p>
          <label>短信验证码 <input aria-label="短信验证码" type="password" inputMode="numeric" autoComplete="one-time-code"
            maxLength={6} value={otp} onChange={event => setOtp(event.target.value)} /></label>
          <button type="submit" disabled={view.pending || !/^[0-9]{6}$/u.test(otp)}>验证并注册</button>
        </form>}
        {handle && <CopyRow label="Handle" value={handle} controller={controller} />}
        {bootstrap.reference && <CopyRow label="DID" value={bootstrap.reference.did} controller={controller} />}
        {bootstrap.clientId && <CopyRow label="CIMD" value={bootstrap.clientId} controller={controller} />}
        {bootstrap.reference && <CopyRow label="本地身份引用" value={JSON.stringify(bootstrap.reference)} controller={controller} />}
  </div>;
}

/** Actual settings-section contribution, not a stand-alone preview. */
export function IdentitySettings({
  controller,
}: {
  controller: IdentityController;
}): ReactNode {
  const view = useSyncExternalStore(
    controller.subscribe,
    controller.getSnapshot,
  );
  const [tab, setTab] = useState<"identities" | "requests">("identities");
  const [history, setHistory] = useState(false);
  const identity = controller.selected();
  const blocked =
    identity?.deleteBlockedReason ||
    (view.grants.length || identity?.integrations.length
      ? "请先解除插件和集成关联"
      : "");
  return (
    <section className="anpi">
      <div className="anpi-row"><h2>身份管理</h2>
        <Button disabled={view.pending || !view.onboarding?.available || view.onboarding.inProgress}
          onClick={() => controller.openRegistration()}>创建公共身份</Button></div>
      <p className="anpi-muted">管理此 DSH 中保存的身份</p>
      <div className="anpi-section"><h3>让 Agent 帮你创建</h3>
        <p className="anpi-small">{IDENTITY_PROMPT}</p>
        <Button onClick={() => { void controller.copy(IDENTITY_PROMPT); }}>复制示例提示词</Button>
        <p className="anpi-small">Agent 会打开创建入口；Handle、手机号/邮箱和验证码只在本页面填写。创建、验证、发布及第三方使用授权是不同步骤。</p>
      </div>
      {view.registrationService && <RegistrationServiceForm controller={controller} settings={view.registrationService} pending={view.pending} />}
      {view.bootstraps.map(bootstrap => <div key={bootstrap.id}>
        {view.modal?.kind === 'registration-progress' && view.modal.requestId === bootstrap.requestId ? null :
          <RegistrationProgress controller={controller} bootstrap={bootstrap} />}
        {['awaiting_email_verification', 'awaiting_phone_verification', 'registering', 'publishing', 'registration_uncertain', 'blocked'].includes(bootstrap.phase) && <Button disabled={view.pending || view.modal !== null}
          onClick={() => controller.openRegistrationProgress(bootstrap.requestId)}>继续注册</Button>}
      </div>)}
      <div className="anpi-tabs" role="tablist" aria-label="身份管理">
        <button
          role="tab"
          aria-selected={tab === "identities"}
          onClick={() => {
            setTab("identities");
          }}
        >
          我的身份
        </button>
        <button
          role="tab"
          aria-selected={tab === "requests"}
          onClick={() => {
            setTab("requests");
          }}
        >
          授权请求
          {view.requests.length > 0 && (
            <span className="anpi-count">{view.requests.length}</span>
          )}
        </button>
      </div>
      {view.error && !view.modal && (
        <div role="alert" className="anpi-error">
          {view.error}
          <Button
            onClick={() => {
              void controller.refresh();
            }}
          >
            重试
          </Button>
        </div>
      )}
      {view.notice && (
        <p role="status" className="anpi-small">
          {view.notice}
        </p>
      )}
      {view.loading ? (
        <p role="status">正在读取身份…</p>
      ) : tab === "requests" ? (
        <>
          <div className="anpi-row">
            <h3>{history ? "已处理" : "待处理请求"}</h3>
            <Button
              onClick={() => {
                setHistory(!history);
                if (!history) void controller.loadHistory();
              }}
            >
              {history ? "待处理" : "已处理"}
            </Button>
          </div>
          <p className="anpi-small">
            {history ? "历史记录不会恢复权限。" : "查看请求后，在弹窗中确认。"}
          </p>
          <RequestList
            controller={controller}
            requests={history ? view.history : view.requests}
            history={history}
          />
        </>
      ) : view.identities.length === 0 ? (
        <p>身份由插件申请创建</p>
      ) : (
        <div className="anpi-columns">
          <nav className="anpi-identities" aria-label="我的身份">
            {view.identities.map((item) => (
              <button
                key={identityKey(identityReference(item))}
                aria-current={
                  identityKey(identityReference(item)) === view.selectedKey
                    ? "true"
                    : undefined
                }
                onClick={() => {
                  void controller.selectIdentity(
                    identityKey(identityReference(item)),
                  );
                }}
              >
                <span className="anpi-identity-label">
                  <strong title={item.handle || identityLabel(item)}>{item.handle || identityLabel(item)}</strong>
                  <small title={item.reference.did}>{item.reference.did}</small>
                </span>
              </button>
            ))}
          </nav>
          {identity && (
            <div className="anpi-detail" key={view.selectedKey}>
              <h3>{identity.handle || identityLabel(identity)}</h3>
              <div className="anpi-fields">
              <CopyRow
                label="Handle"
                value={identity.handle}
                controller={controller}
              />
              <CopyRow
                label="DID"
                value={identity.reference.did}
                controller={controller}
              />
              </div>
              {view.publication && <div className="anpi-section">
                <h3>对外身份</h3>
                <p>{({local: "尚未发布", awaiting_configuration: "等待身份托管配置", publishing: "发布中", published: "已发布", failed: "发布未完成"})[view.publication.state]}</p>
                {view.publication.capabilities && <p>{[
                  view.publication.capabilities.mcpMachine ? 'MCP 机器访问（无需回调地址）' : '',
                  view.publication.capabilities.papSession ? 'PAP 会话' : '',
                  view.publication.capabilities.papAccount ? 'PAP 账户授权' : '',
                ].filter(Boolean).join(' · ')}</p>}
                {view.publication.clientId && <CopyRow label="CIMD" value={view.publication.clientId} controller={controller} />}
                {view.publication.state === "failed" && <Button disabled={view.pending} onClick={() => { void controller.retryPublication(); }}>重试发布</Button>}
              </div>}
              <div className="anpi-section">
                <h3>你授权的插件</h3>
                {view.grants.length === 0 && (
                  <p className="anpi-muted">暂无授权的插件</p>
                )}
                {view.grants.map((grant) => (
                  <div className="anpi-row" key={grant.id}>
                    <div>
                      <strong>{grant.caller.displayName}</strong>
                      <p className="anpi-small">
                        全部权限 · {modeLabel(grant.mode)}
                      </p>
                    </div>
                    <div className="anpi-actions">
                      <Button
                        variant="outline"
                        onClick={() => {
                          void controller.openPermissions(grant.id);
                        }}
                      >
                        权限详情
                      </Button>
                      <Button
                        disabled={view.pending}
                        onClick={() => {
                          void controller.openRevoke(grant.id);
                        }}
                      >
                        撤销
                      </Button>
                    </div>
                  </div>
                ))}
                <p className="anpi-small">{FULL_PERMISSION_NOTICE}</p>
              </div>
              {identity.integrations.length > 0 && (
                <div className="anpi-section">
                  <h3>现有集成</h3>
                  {identity.integrations.map((item) => (
                    <div key={`${item.kind}:${item.consumer}`}>
                      <strong>{item.displayName}</strong>
                      <p className="anpi-small">
                        {item.kind === "provider"
                          ? "由宿主管理"
                          : "旧版集成，由宿主管理"}
                      </p>
                    </div>
                  ))}
                </div>
              )}
              <div className="anpi-section">
                <Button
                  aria-expanded={view.documentOpen}
                  onClick={() => {
                    void controller.toggleDocument();
                  }}
                >
                  {view.documentOpen ? "⌄" : "›"} 查看 DID 文档
                </Button>
                {view.documentOpen && (
                  <>
                    <pre className="anpi-document">{view.document}</pre>
                    <Button
                      onClick={() => {
                        if (view.document) void controller.copy(view.document);
                      }}
                    >
                      复制 JSON
                    </Button>
                  </>
                )}
              </div>
              <div className="anpi-section anpi-actions">
                <Button
                  variant="outline"
                  disabled={Boolean(blocked) || view.pending}
                  onClick={() => {
                    controller.openDelete();
                  }}
                >
                  删除身份
                </Button>
                {blocked && <span className="anpi-small">{blocked}</span>}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
function RequestList({
  controller,
  requests,
  history,
}: {
  controller: IdentityController;
  requests: readonly AuthorizationRequest[];
  history: boolean;
}): ReactNode {
  if (!requests.length)
    return <p>{history ? "暂无已处理记录" : "暂无待处理的授权请求"}</p>;
  const statusLabels = {
    pending: "待处理",
    approved: "已允许",
    denied: "已拒绝",
    cancelled: "已取消",
    expired: "已过期",
  };
  return (
    <div className="anpi-request-list">
      {requests.map((request) => (
        <article className="anpi-row" key={request.id}>
          <div className="anpi-break">
            <strong>{request.caller.displayName}</strong>
            <p className="anpi-small">{request.caller.consumer}</p>
            <p>{request.kind === "create" ? "申请创建身份" : "申请使用身份"}</p>
            <p className="anpi-small">{request.purpose}</p>
            <p className="anpi-small">
              {request.kind === "create"
                ? `${request.parameters.label} · ${request.parameters.domain}${request.parameters.path}`
                : `全部使用权限${request.operation?.httpOrigin ? ` · ${request.operation.httpOrigin}` : ""}`}
            </p>
            {history && (
              <p>
                {statusLabels[request.status]}
                {request.kind === "create" && request.executionStatus
                  ? ` · ${request.executionStatus === "succeeded" ? "身份已创建" : request.executionStatus === "running" ? "创建中" : request.executionStatus === "deleted" ? "身份已删除" : "创建结果待核对"}`
                  : request.kind === "access" && request.mode
                    ? ` · ${modeLabel(request.mode)}`
                    : ""}
              </p>
            )}
          </div>
          <div className="anpi-request-action">
            <time dateTime={new Date(request.createdAt).toISOString()}>
              {new Date(request.createdAt).toLocaleString()}
            </time>
            {history ? (
              request.status !== "pending" && (
                <>
                  <Button
                    onClick={() => {
                      void controller.openResult(request.id);
                    }}
                  >
                    {request.kind === "create" &&
                    request.status === "approved" &&
                    (request.executionStatus === "unknown" ||
                      request.executionStatus === "running")
                      ? "核对结果"
                      : "查看结果"}
                  </Button>
                  {!(
                    request.kind === "create" && request.status === "approved"
                  ) && (
                    <Button
                      onClick={() => {
                        void controller.reauthorize(request);
                      }}
                    >
                      重新申请
                    </Button>
                  )}
                </>
              )
            ) : (
              <Button
                variant="outline"
                onClick={() => {
                  void controller.openRequest(request.id);
                }}
              >
                查看请求
              </Button>
            )}
          </div>
        </article>
      ))}
    </div>
  );
}

/** Complement the DSH primitive with focus containment and background inertness. */
function useModalFocus(
  root: React.RefObject<HTMLDivElement>,
  controller: IdentityController,
): void {
  useEffect(() => {
    const node = root.current;
    if (!node) return;
    const dialog = node.closest('[role="dialog"]') as HTMLElement | null;
    if (!dialog) return;
    const previous: [HTMLElement, boolean][] = [];
    let branch: HTMLElement | null = dialog;
    while (branch && branch !== document.body) {
      const parent: HTMLElement | null = branch.parentElement;
      if (!parent) break;
      for (const child of parent.children)
        if (child !== branch && child instanceof HTMLElement) {
          previous.push([child, child.inert]);
          child.inert = true;
        }
      branch = parent;
    }
    const focusable = (): HTMLElement[] => [
      ...dialog.querySelectorAll<HTMLElement>(
        'button:not(:disabled), input:not(:disabled), select:not(:disabled), [tabindex="0"]',
      ),
    ];
    (focusable()[0] ?? dialog).focus();
    const key = (event: KeyboardEvent): void => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopImmediatePropagation();
        controller.closeModal();
      } else if (event.key === "Tab") {
        const items = focusable();
        const first = items[0];
        const last = items.at(-1);
        if (!first || !last) {
          event.preventDefault();
          return;
        }
        if (
          event.shiftKey &&
          (document.activeElement === first ||
            !dialog.contains(document.activeElement))
        ) {
          event.preventDefault();
          last.focus();
        } else if (
          !event.shiftKey &&
          (document.activeElement === last ||
            !dialog.contains(document.activeElement))
        ) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", key, true);
    return () => {
      document.removeEventListener("keydown", key, true);
      for (const [element, inert] of previous) element.inert = inert;
    };
  }, [controller, root]);
}
export function IdentityOverlay({
  controller,
}: {
  controller: IdentityController;
}): ReactNode {
  const view = useSyncExternalStore(
    controller.subscribe,
    controller.getSnapshot,
  );
  if (!view.modal) return null;
  const modal = view.modal;
  const key = modal.kind === "registration" ? "registration" :
    modal.kind === "registration-progress" ? `registration-progress:${modal.requestId}` :
    modal.kind === "request" || modal.kind === "result"
      ? `${modal.review.request.id}:${modal.review.request.version}`
      : modal.kind === "permissions" || modal.kind === "revoke"
        ? `${modal.kind}:${modal.grant.id}`
        : identityKey(identityReference(modal.identity));
  return <IdentityModal key={key} controller={controller} />;
}
function IdentityModal({
  controller,
}: {
  controller: IdentityController;
}): ReactNode {
  const view = useSyncExternalStore(
    controller.subscribe,
    controller.getSnapshot,
  );
  const root = useRef<HTMLDivElement>(null);
  useModalFocus(root, controller);
  const modal = view.modal;
  const [confirmation, setConfirmation] = useState("");
  if (!modal) return null;
  let title: string;
  let content: ReactNode;
  if (modal.kind === "registration") {
    title = "创建公共身份";
    content = <RegistrationForm controller={controller} />;
  } else if (modal.kind === "registration-progress") {
    const bootstrap = view.bootstraps.find(flow => flow.requestId === modal.requestId);
    const completed = bootstrap?.phase === 'published';
    const stopped = bootstrap?.phase === 'disposed';
    title = completed ? "注册完成" : stopped ? "注册流程已停止" : "完成身份注册";
    content = <>
      {bootstrap ? <RegistrationProgress controller={controller} bootstrap={bootstrap} approvalCompleted /> :
        <p role="status">正在读取注册状态，请稍候…</p>}
      <p className="anpi-small">{completed ? '身份注册与发布已完成，无需再次注册。连接第三方服务属于独立的授权配置。'
        : stopped ? '此注册流程已停止。'
        : '创建身份、验证联系方式和发布是不同步骤。你可以稍后继续，不会丢失当前流程。'}</p>
      <Button disabled={view.pending} onClick={() => controller.closeModal()}>{completed ? '完成' : stopped ? '关闭' : '稍后继续'}</Button>
    </>;
  } else if (modal.kind === "result") {
    title = "请求结果";
    const request = modal.review.request;
    const grant = modal.review.grant;
    content = (
      <>
        <h3>{request.caller.displayName}</h3>
        <p className="anpi-small">{request.caller.consumer}</p>
        <p>{request.purpose}</p>
        {request.kind === "create" ? (
          <>
            <p>
              创建结果：
              {request.executionStatus === "succeeded"
                ? "身份已创建"
                : request.executionStatus === "deleted"
                  ? "身份已删除"
                  : request.executionStatus === "running"
                    ? "创建仍在处理中"
                    : request.status === "approved"
                      ? "结果尚不能确定，请稍后核对；不要重复创建。"
                      : request.status === "denied"
                        ? "已拒绝"
                        : request.status === "cancelled"
                          ? "已取消"
                          : "已过期"}
            </p>
            {request.result && (
              <>
                <p>身份名称：{request.result.label}</p>
                <CopyRow
                  label="DID"
                  value={request.result.reference.did}
                  controller={controller}
                />
              </>
            )}
            {request.executionStatus === "succeeded" && (
              <p className="anpi-small">
                仅创建身份，不代表身份文档已发布或已授予使用权限。
              </p>
            )}
            {request.executionStatus === "deleted" && (
              <p className="anpi-small">
                此处只展示历史公开引用，不会恢复身份或重新创建。
              </p>
            )}
          </>
        ) : (
          <>
            <p>
              申请决定：
              {request.status === "approved"
                ? "已允许"
                : request.status === "denied"
                  ? "已拒绝"
                  : request.status === "cancelled"
                    ? "已取消"
                    : "已过期"}
            </p>
            {request.status === "approved" && (
              <p>
                当前授权：
                {grant
                  ? (
                      {
                        active: "有效",
                        consumed: "已使用",
                        expired: "已过期",
                        revoked: "已撤销",
                      } as const
                    )[grant.status]
                  : "无法读取当前授权状态"}
              </p>
            )}
            {grant && (
              <>
                <p>授权方式：{modeLabel(grant.mode)}</p>
                <CopyRow
                  label="DID"
                  value={grant.identity.did}
                  controller={controller}
                />
              </>
            )}
            <p className="anpi-small">查看历史记录不会恢复使用权限。</p>
          </>
        )}
        <div className="anpi-footer">
          <Button
            onClick={() => {
              controller.closeModal();
            }}
          >
            关闭
          </Button>
        </div>
      </>
    );
  } else if (modal.kind === "request") {
    const request = modal.review.request;
    title = request.kind === 'access' && isExactSnapshot(modal.review.snapshot)
      ? '确认本次操作'
      : `允许${request.caller.displayName}${request.kind === "create" ? "创建" : "使用"}身份？`;
    content = (
      <>
        <p className="anpi-small">{request.caller.consumer}</p>
        <p>{request.purpose}</p>
        {request.kind === "create" ? (
          <>
            <dl className="anpi-parameters">
              <dt>身份名称</dt>
              <dd>{request.parameters.label}</dd>
              <dt>Handle</dt>
              <dd>{request.parameters.handle ?? "未提供"}</dd>
              <dt>DID 域名</dt>
              <dd>{request.parameters.domain}</dd>
              <dt>身份路径</dt>
              <dd>{request.parameters.path}</dd>
              <dt>用途</dt><dd>{request.parameters.usage === 'protocol' ? 'MCP / PAP 协议身份（独立设备权限）' : '普通插件身份'}</dd>
              <dt>身份方法</dt><dd>{request.parameters.profile ?? 'e1'}</dd>
              {request.parameters.usage === 'protocol' && <><dt>设备能力</dt><dd>{request.parameters.identityOnly ? '仅公共身份（不含消息能力）' : '身份与消息能力'}</dd></>}
            </dl>
            <p>参数由插件提供，请确认后继续。</p>
            <p className="anpi-small">Handle 由申请插件提供，保存不代表已在服务端注册或验证。</p>
            <p className="anpi-small">
              用于生成身份标识和确定文档地址，创建时不会自动发布。
            </p>
            <p className="anpi-small">身份与私钥保存在当前 DSH 宿主。</p>
            <p className="anpi-small">仅创建身份，不会同时授予使用权限。</p>
            {modal.review.unavailableReason && (
              <p role="alert">{modal.review.unavailableReason}</p>
            )}
            <DecisionActions
              controller={controller}
              disabled={Boolean(modal.review.unavailableReason)}
              approve={() => {
                void controller.decide({ decision: "approve" });
              }}
              label="允许创建"
            />
          </>
        ) : (
          <AccessForm controller={controller} review={modal.review} />
        )}
      </>
    );
  } else if (modal.kind === "permissions") {
    title = "权限详情";
    content = (
      <>
        <h3>{modal.grant.caller.displayName}</h3>
        <p className="anpi-small">{modal.grant.caller.consumer}</p>
        <p>
          {identityLabel(modal.identity)}
          {modal.identity.handle ? ` · ${modal.identity.handle}` : ""}
        </p>
        <p className="anpi-small anpi-break">{modal.identity.reference.did}</p>
        <p>
          授权方式：{modeLabel(modal.grant.mode)}
          {modal.grant.mode === "permanent"
            ? "，直到你撤销"
            : "，仅本次操作有效"}
        </p>
        {modal.grant.mode === "once" && (
          <>
            <p className="anpi-break">
              本次操作：{modal.grant.operation?.summary}
            </p>
            <p>
              到期时间：
              {modal.grant.expiresAt
                ? new Date(modal.grant.expiresAt).toLocaleString()
                : "未设置"}
            </p>
          </>
        )}
        <Scope snapshot={modal.grant.snapshot} />
        <p className="anpi-small">
          不包含私钥导出、身份删除和设备恢复等管理操作。
        </p>
        <div className="anpi-footer">
          <Button
            variant="outline"
            onClick={() => {
              controller.closeModal();
            }}
          >
            关闭
          </Button>
        </div>
      </>
    );
  } else if (modal.kind === "revoke") {
    title = "撤销授权";
    content = (
      <>
        <h3>{modal.grant.caller.displayName}</h3>
        <p className="anpi-small">{modal.grant.caller.consumer}</p>
        <p>{identityLabel(modal.identity)}{modal.identity.handle ? ` · ${modal.identity.handle}` : ""}</p>
        <p className="anpi-small anpi-break">{modal.identity.reference.did}</p>
        <p>将撤销此插件的{modeLabel(modal.grant.mode)}。已发出的请求可能仍会完成，也不会注销远端登录。</p>
        <p className="anpi-small">撤销后不会自动再次弹窗；如需恢复，可在授权请求历史中重新申请。</p>
        <div className="anpi-footer">
          <Button disabled={view.pending} onClick={() => controller.closeModal()}>取消</Button>
          <Button variant="primary" disabled={view.pending} onClick={() => { void controller.revoke(); }}>确认撤销</Button>
        </div>
      </>
    );
  } else {
    title = "删除身份";
    content = (
      <>
        <p>
          将删除当前 DSH
          宿主上的此身份与密钥。此操作不会注销远端登录或撤销已发布的 DID。
        </p>
        <label htmlFor="anpi-delete-confirm">
          输入身份名称「{identityLabel(modal.identity)}」确认
        </label>
        <input
          id="anpi-delete-confirm"
          value={confirmation}
          onChange={(event) => {
            setConfirmation(event.target.value);
          }}
        />
        <div className="anpi-footer">
          <Button
            disabled={view.pending}
            onClick={() => {
              controller.closeModal();
            }}
          >
            取消
          </Button>
          <Button
            variant="primary"
            disabled={
              view.pending || confirmation !== identityLabel(modal.identity)
            }
            onClick={() => {
              void controller.deleteIdentity(confirmation);
            }}
          >
            删除身份
          </Button>
        </div>
      </>
    );
  }
  return (
    <Modal
      open
      title={title}
      closeLabel="稍后关闭"
      onClose={() => {
        controller.closeModal();
      }}
      className="anpi-modal"
      contentClassName="anpi-modal-content"
    >
      <div ref={root} className="anpi">
        {content}
        {view.pending && <p role="status">正在处理，请勿重复提交…</p>}
        {view.error && (
          <p role="alert" className="anpi-error">
            {view.error}
          </p>
        )}
      </div>
    </Modal>
  );
}
function AccessForm({
  controller,
  review,
}: {
  controller: IdentityController;
  review: RequestReview;
}): ReactNode {
  const request = review.request;
  const [mode, setMode] = useState<AuthorizationMode>("once");
  const [key, setKey] = useState(
    request.kind === "access" && request.identity
      ? identityKey(request.identity)
      : review.identities[0]
        ? identityKey(identityReference(review.identities[0]))
        : "",
  );
  if (request.kind !== "access") return null;
  const identity = review.identities.find(
    (i) => identityKey(identityReference(i)) === key,
  );
  const snapshot =
    review.snapshots?.find((item) => identityKey(item.identity) === key)
      ?.snapshot ??
    (request.identity && identityKey(request.identity) === key
      ? review.snapshot
      : undefined);
  const exact = isExactSnapshot(snapshot);
  const selectedMode = exact ? 'once' : mode;
  return (
    <>
      <label htmlFor="anpi-identity-choice">使用哪个身份</label>
      <select
        id="anpi-identity-choice"
        value={key}
        onChange={(event) => {
          setKey(event.target.value);
        }}
        disabled={request.identity !== undefined}
      >
        {review.identities.map((item) => (
          <option
            key={identityKey(identityReference(item))}
            value={identityKey(identityReference(item))}
          >
            {identityLabel(item)}
            {item.handle ? ` · ${item.handle}` : ""} · {item.reference.did}
          </option>
        ))}
      </select>
      {!identity && <p>没有兼容身份，请回到原插件申请创建身份。</p>}
      {exact && request.operation?.httpOrigin && <p className="anpi-break">目标网站：{request.operation.httpOrigin}</p>}
      {exact && review.operationPreview && <dl className="anpi-parameters" aria-label="本次操作范围">
        <dt>请求方法</dt><dd>{review.operationPreview.method}</dd>
        <dt>目标网址</dt><dd>{review.operationPreview.target}</dd>
        {review.operationPreview.parameters !== undefined && <>
          <dt>参数摘要</dt><dd><p className="anpi-small">敏感字段已隐藏；较长内容可能截断。此处仅供核对，不能修改请求。</p>
            <pre className="anpi-document" aria-label="参数摘要">{JSON.stringify(review.operationPreview.parameters, null, 2)}</pre></dd>
        </>}
        <dt>请求内容 SHA-256</dt><dd><code className="anpi-break">{review.operationPreview.bodyDigest}</code></dd>
      </dl>}
      {exact && !review.operationPreview && <p role="alert">当前操作摘要不可用，暂不能批准。请从原任务重新发起操作。</p>}
      <fieldset>
        <legend>授权方式</legend>
        <div className="anpi-mode">
          <label>
            <input
              type="radio"
              name="anpi-mode"
              checked={selectedMode === "once"}
              onChange={() => {
                setMode("once");
              }}
            />
            单次授权<small>仅本次操作有效</small>
          </label>
          {!exact && <label>
            <input
              type="radio"
              name="anpi-mode"
              checked={mode === "permanent"}
              onChange={() => {
                setMode("permanent");
              }}
            />
            永久授权<small>持续有效，直到你撤销</small>
          </label>}
        </div>
      </fieldset>
      {selectedMode === "permanent" ? (
        <p className="anpi-operation">持续授权：可读取公开身份、签名，并请求下列全部网站，直到你撤销。不仅限于当前操作。</p>
      ) : request.operation ? (
        <p className="anpi-operation">本次操作：{request.operation.summary}</p>
      ) : (
        selectedMode === "once" && (
          <p role="alert">
            原插件未提供明确操作，暂不能批准单次授权，请原插件补齐。
          </p>
        )
      )}
      {!exact && mode === "once" &&
        review.permanentIdentities?.some(
          (reference) => identityKey(reference) === key,
        ) && (
          <p className="anpi-small">
            此插件已有永久授权，仍然有效；本次选择单次授权不会撤销它。需要取消时，请在身份详情中撤销。
          </p>
        )}
      {review.unavailableReason && (
        <p role="alert">{review.unavailableReason}</p>
      )}
      {exact ? <div className="anpi-access-scope" role="note">
        <p>仅允许上方这一次请求。请求方法、目标网址和请求内容均已绑定；未明确批准前不会执行操作。</p>
        <p className="anpi-small">不会授予其他域名、其他请求、永久写入或通用签名权限。</p>
      </div> : <div className="anpi-access-scope">
        <p className="anpi-small">{FULL_PERMISSION_NOTICE}</p>
        <p className="anpi-small">{snapshot?.capabilities.includes('identity:sign') ? '签名可在外部使用，不受网站列表限制。' : '仅允许公开身份读取与精确 HTTP 请求认证，不提供设备断言或通用签名权限。'}</p>
        <details>
          <summary>全部使用权限 · 查看范围</summary>
          {snapshot ? (
            <>
              <p>
                {snapshot.capabilities
                  .map(
                    (capability) => capabilityNames[capability] ?? capability,
                  )
                  .join("、")}
              </p>
              <p className="anpi-small">
                签名用途：{snapshot.signingPurposes.join("、") || "无"}
              </p>
            </>
          ) : (
            <p>无法读取权限范围，暂不能授权。</p>
          )}
        </details>
        <p className="anpi-small anpi-break">
          网站：{snapshot?.httpOrigins.includes('*') ? '全部 HTTPS 域名（通配权限）' : snapshot?.httpOrigins.join("、") || "无"}
        </p>
      </div>}
      <DecisionActions
        controller={controller}
        disabled={
          !identity ||
          !snapshot ||
          Boolean(review.unavailableReason) ||
          (exact && !review.operationPreview) ||
          (selectedMode === "once" && !request.operation)
        }
        approve={() => {
          if (identity)
            void controller.decide({
              decision: "approve",
              identity: identityReference(identity),
              mode: selectedMode,
              ...(snapshot ? { reviewedSnapshot: snapshot } : {}),
            });
        }}
        label={exact ? '允许本次操作' : '允许授权'}
      />
    </>
  );
}
function DecisionActions({
  controller,
  disabled,
  approve,
  label,
}: {
  controller: IdentityController;
  disabled: boolean;
  approve: () => void;
  label: string;
}): ReactNode {
  const view = useSyncExternalStore(
    controller.subscribe,
    controller.getSnapshot,
  );
  return (
    <div className="anpi-footer">
      <Button
        disabled={view.pending}
        onClick={() => {
          controller.closeModal();
        }}
      >
        稍后
      </Button>
      <span className="anpi-spacer" />
      <Button
        variant="outline"
        disabled={view.pending}
        onClick={() => {
          void controller.decide({ decision: "deny" });
        }}
      >
        拒绝
      </Button>
      <Button
        variant="primary"
        disabled={disabled || view.pending}
        onClick={approve}
      >
        {label}
      </Button>
    </div>
  );
}
