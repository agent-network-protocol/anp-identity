/** Host design tokens keep the plugin aligned with both DSH themes. */
export const styles = `
.anpi{container-type:inline-size}
.anpi .anpi-tabs{margin:16px 0 20px;gap:20px}
.anpi .anpi-columns{grid-template-columns:minmax(164px,30%) minmax(0,1fr);gap:24px}
.anpi .anpi-identities{padding:4px;border-radius:12px;background:var(--dsw-alias-bg-layer-2,#1e232a)}
.anpi .anpi-identities button{display:flex;align-items:center;gap:10px;padding:12px 8px;border-radius:8px;min-height:72px;transition:background-color .15s}
.anpi .anpi-identities button:hover{background:var(--dsw-alias-bg-layer-3,#222830)}
.anpi .anpi-identities button[aria-current=true]{background:var(--dsw-alias-bg-layer-3,#222830);border-left-color:var(--dsw-alias-label-primary,#eef0f5)}
.anpi-identity-label{min-width:0;display:block}
.anpi-identity-label strong{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;font-size:13px;font-weight:600;line-height:1.4;overflow-wrap:anywhere}
.anpi .anpi-identities small{font-size:12px;margin-top:4px}
.anpi .anpi-detail>h3{font-size:18px;line-height:1.4;overflow-wrap:anywhere;margin:2px 0 16px}
.anpi-fields{border:1px solid var(--dsw-alias-border-l2,#343b46);border-radius:10px;overflow:hidden;background:var(--dsw-alias-bg-layer-2,#1e232a)}
.anpi .anpi-fields .anpi-copy{margin:0;padding:12px 14px;border:0;border-radius:0;background:none;gap:8px;grid-template-columns:58px minmax(0,1fr) auto}
.anpi .anpi-fields .anpi-copy+.anpi-copy{border-top:1px solid var(--dsw-alias-border-l2,#343b46)}
.anpi-field-label{font-size:12px;color:var(--dsw-alias-label-secondary,#bec6d2)}
.anpi .anpi-fields .anpi-copy-did{grid-template-columns:minmax(0,1fr) auto;align-items:start}
.anpi-copy-did .anpi-field-value{grid-row:2;grid-column:1/-1;font:12px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;user-select:text}
.anpi-copy-did button{grid-column:2;grid-row:1}
.anpi .anpi-detail .anpi-section{padding-top:16px;margin-top:20px}
.anpi .anpi-detail .anpi-section h3{font-size:14px;font-weight:600;margin-bottom:8px}
.anpi .anpi-detail .anpi-section>p.anpi-muted{padding:8px 0;margin:0}
.anpi .anpi-detail .anpi-section>p.anpi-small{margin-top:10px;line-height:1.6}
@container(max-width:480px){.anpi .anpi-columns{grid-template-columns:1fr;gap:20px}.anpi .anpi-identities{display:block}.anpi .anpi-identities button{min-height:60px}.anpi-identity-label strong{-webkit-line-clamp:1}}
@media(prefers-reduced-motion:reduce){.anpi .anpi-identities button{transition:none}}
.anpi-access-scope{margin-top:12px}.anpi-access-scope summary{cursor:pointer}.anpi-access-scope p{margin:4px 0}.anpi-access-scope details{margin-top:8px}.anpi-modal .anpi-modal-content{max-height:calc(100dvh - 80px)}
.anpi{font:14px/1.6 system-ui,sans-serif;color:var(--dsw-alias-label-primary,#eef0f5);min-width:0}.anpi h2{font-size:24px;margin:0}.anpi h3{font-size:17px;margin:0 0 12px}.anpi p{margin:8px 0}.anpi-small,.anpi-muted,.anpi small,.anpi time{color:var(--dsw-alias-label-tertiary,#aab3c2);font-size:12px}.anpi-break{overflow-wrap:anywhere;min-width:0}.anpi-tabs{display:flex;gap:18px;border-bottom:1px solid var(--dsw-alias-border-l2,#343b46);margin:22px 0}.anpi-tabs button{padding:8px 3px;background:none;border:0;border-bottom:3px solid transparent;color:inherit;font:inherit;cursor:pointer}.anpi-tabs button[aria-selected=true]{border-bottom-color:var(--dsw-alias-brand-primary,#4a65ff)}.anpi-count{display:inline-flex;align-items:center;justify-content:center;background:var(--dsw-alias-bg-layer-3,#3a414c);border-radius:20px;min-width:23px;margin-left:8px}.anpi-columns{display:grid;grid-template-columns:minmax(170px,28%) minmax(0,1fr);gap:28px}.anpi-identities{border:1px solid var(--dsw-alias-border-l2,#343b46);border-radius:10px;overflow:hidden;align-self:start}.anpi-identities button{background:none;color:inherit;border:0;border-left:3px solid transparent;width:100%;padding:16px;text-align:left;cursor:pointer}.anpi-identities button[aria-current=true]{border-left-color:var(--dsw-alias-brand-primary,#4a65ff);background:color-mix(in srgb,var(--dsw-alias-brand-primary,#4a65ff) 17%,transparent)}.anpi-identities small{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.anpi-detail{min-width:0}.anpi-copy{display:grid;grid-template-columns:54px minmax(0,1fr) auto;align-items:center;gap:12px;border:1px solid var(--dsw-alias-border-l2,#343b46);background:var(--dsw-alias-bg-layer-3,#222830);border-radius:8px;padding:9px 12px;margin:8px 0}.anpi-section{border-top:1px solid var(--dsw-alias-border-l2,#343b46);padding-top:18px;margin-top:20px}.anpi-row{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:10px 0}.anpi-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.anpi-request-list{border:1px solid var(--dsw-alias-border-l2,#343b46);border-radius:10px;overflow:hidden}.anpi-request-list article{padding:18px;margin:0;border-bottom:1px solid var(--dsw-alias-border-l2,#343b46)}.anpi-request-list article:last-child{border:0}.anpi-request-action{display:flex;align-items:flex-end;flex-direction:column;gap:12px;flex-shrink:0}.anpi-document{padding:12px;background:var(--dsw-alias-bg-layer-1,#14181e);max-height:280px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}.anpi-error{color:var(--dsw-alias-state-error-primary,#ff9c99);overflow-wrap:anywhere}.anpi-modal{width:min(660px,calc(100vw - 32px));max-height:calc(100dvh - 32px)}.anpi-modal-content{overflow-y:auto;max-height:calc(100dvh - 160px)}.anpi-modal .anpi{padding:0 4px}.anpi-parameters{display:grid;grid-template-columns:90px minmax(0,1fr);gap:12px;padding:18px;background:var(--dsw-alias-bg-layer-3,#222830);border:1px solid var(--dsw-alias-border-l2,#343b46);border-radius:9px}.anpi dd{margin:0;overflow-wrap:anywhere}.anpi dt{color:var(--dsw-alias-label-tertiary,#aab3c2)}.anpi select,.anpi input:not([type=radio]){box-sizing:border-box;width:100%;font:inherit;color:inherit;background:var(--dsw-alias-bg-layer-1,#14181e);border:1px solid var(--dsw-alias-border-l2,#343b46);border-radius:8px;padding:12px;margin:8px 0}.anpi select{white-space:normal}.anpi fieldset{border:0;padding:0;margin:18px 0}.anpi legend{margin-bottom:10px;font-weight:600}.anpi-mode{display:flex;gap:24px}.anpi-mode label{flex:1;cursor:pointer}.anpi-mode input{margin-right:9px;accent-color:var(--dsw-alias-brand-primary,#4a65ff)}.anpi-mode small{display:block;padding-left:25px}.anpi-operation{padding:10px;background:var(--dsw-alias-bg-layer-3,#222830);border-radius:7px;overflow-wrap:anywhere}.anpi-footer{display:flex;gap:12px;align-items:center;justify-content:flex-end;margin-top:24px;position:sticky;bottom:0;background:var(--dsw-alias-bg-layer-2,#1e232a);padding:8px 0}.anpi-spacer{flex:1}.anpi button:focus-visible,.anpi input:focus-visible,.anpi select:focus-visible{outline:2px solid var(--dsw-alias-brand-primary,#4a65ff);outline-offset:3px}@media(max-width:720px){.anpi-columns{grid-template-columns:1fr;gap:18px}.anpi-identities{display:flex}.anpi-identities button{min-width:0}.anpi-row{align-items:flex-start;flex-wrap:wrap}.anpi-request-action{align-items:flex-start}.anpi-mode{gap:10px}.anpi-copy{gap:7px}.anpi-modal{width:calc(100vw - 20px)}}
`;
export function mountStyles(): () => void {
  const style = document.createElement("style");
  style.dataset.anpIdentity = "v7";
  style.textContent = styles;
  document.head.appendChild(style);
  return () => {
    style.remove();
  };
}
