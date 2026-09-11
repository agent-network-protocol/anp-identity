import React, { useEffect, useState } from 'react';
import contribution from './remote.js';
import { unwrapDemoResult } from './client-result.mjs';
export const inject = ['slots', 'remote', 'connection'];
const phases: Record<string, string> = { idle: '尚未开始', creating: '等待创建确认', publishing: '等待公开文档授权', ready: '准备发送', authorizing: '等待 HTTP 授权', sending: '正在发送', success: '验签成功', denied: '你已拒绝请求', error: '操作未完成' };
function Demo({ api }: any) {
  const [state, setState] = useState<any>({ phase: 'idle', events: [] });
  const [busy, setBusy] = useState(false);
  useEffect(() => { let active = true; const read = async () => { try { const next = unwrapDemoResult(await api.status()); if (active) setState(next); } catch { /* Connection recovery is handled by the host. */ } }; void read(); const timer = setInterval(read, 650); return () => { active = false; clearInterval(timer); }; }, [api]);
  const run = async (method: string) => { setBusy(true); try { setState(unwrapDemoResult(await api[method]())); } catch (error: any) { setState((previous: any) => ({ ...previous, error: error.message })); } finally { setBusy(false); } };
  const pending = ['creating', 'publishing', 'authorizing', 'sending'].includes(state.phase);
  return <section className="anp-demo"><style>{`.anp-demo{padding:4px 10px 24px;max-width:850px;color:inherit}.anp-demo h2{font-size:23px;margin:8px 0}.anp-demo p{line-height:1.65}.anp-demo .sub{opacity:.65;font-size:13px}.anp-demo .steps{display:flex;gap:8px;margin:20px 0}.anp-demo .steps span{border:1px solid #ffffff20;border-radius:10px;padding:12px;flex:1;font-size:13px}.anp-demo .actions{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0}.anp-demo button{border:1px solid #ffffff30;border-radius:9px;padding:10px 14px;background:#ffffff10;color:inherit;cursor:pointer}.anp-demo button.primary{background:#526bff;color:white;border:0}.anp-demo button:disabled{opacity:.4;cursor:default}.anp-demo .card{border:1px solid #ffffff20;border-radius:12px;padding:16px;margin-top:16px}.anp-demo .good{color:#6bd8ab}.anp-demo .error{color:#ffb5a8}.anp-demo code,.anp-demo pre{overflow-wrap:anywhere;white-space:pre-wrap;font-size:12px}.anp-demo pre{max-height:250px;overflow:auto;background:#0002;padding:12px}.anp-demo li{font-size:13px;line-height:1.7}.anp-demo .tag{font-size:12px;opacity:.7}`}</style>
    <span className="tag">ANP IDENTITY · LOCAL DEMO</span><h2>让身份签名，向 Server 证明是你</h2>
    <p className="sub">普通插件申请，你决定是否允许。私钥留在 Host，Server 只拿公钥验签。</p>
    <div className="steps"><span>① 插件申请创建身份</span><span>② 你确认使用权限</span><span>③ HTTPS 请求 · Server 验签</span></div>
    <div className="actions"><button className="primary" disabled={busy || pending} onClick={() => run('start')}>{state.phase === 'idle' ? '开始演示：申请创建身份' : '重新演示：创建新身份'}</button><button disabled={busy || !['ready', 'success'].includes(state.phase)} onClick={() => run('send')}>授权并发送签名请求</button></div>
    <p><strong className={state.phase === 'success' ? 'good' : ''}>{phases[state.phase]}</strong></p>
    {pending && <p className="sub">请在身份确认弹窗中处理；若暂时关闭，可到「身份 → 授权请求」继续。</p>}
    {state.identity && <div className="card"><span className="sub">本次演示身份</span><p><code>{state.identity}</code></p><span className="sub">POST {state.origin}/hello</span></div>}
    {state.error && <p role="alert" className="error">操作未完成：{state.error}。未自动重试；可以重新开始。</p>}
    {state.result && <div className="card"><h3 className={state.result.verified ? 'good' : 'error'}>{state.result.verified ? '✓ Server 验签通过' : 'Server 拒绝请求'} · HTTP {state.result.httpStatus}</h3><p>{state.result.message}</p><p className="sub">检查公钥、正文摘要、请求方法与地址、Ed25519 签名、时间和防重放。</p><details><summary>查看真实 HTTP 签名与服务端返回</summary><pre>{JSON.stringify(state.result, null, 2)}</pre></details><div className="actions"><button disabled={busy || state.phase !== 'success'} onClick={() => run('checks')}>试试篡改正文 / 签名 / 重放</button></div>{state.checks?.checks?.map((check: any) => <p key={check.name} className={check.rejected ? 'good' : 'error'}>{check.rejected ? '✓ 已拒绝' : '✕ 未拒绝'} {check.name} <code>{check.code}</code></p>)}</div>}
    <details className="card" open><summary>演示过程</summary><ol>{state.events.map((event: any, index: number) => <li key={index}><span className="sub">{event.time}</span>　{event.text}</li>)}</ol></details>
    <p className="sub">仅本地演示。Server 使用经授权提供的公开文档，不代表 DID 已发布或域名归属已验证。单次授权只允许当前操作；永久授权可复用直到撤销。</p>
  </section>;
}
export async function apply(ctx: any) {
  const unmount = await ctx.remote.$mount(contribution);
  const api = ctx.get('remote.anpHttpDemo');
  const dispose = ctx.slots.inject('settings.section', () => ctx.slots.register({ name: 'settings.section', id: 'anp-http-demo', label: '签名演示', order: 41, inject: () => ({ api }) }, Demo));
  return async () => { dispose(); await unmount(); };
}
