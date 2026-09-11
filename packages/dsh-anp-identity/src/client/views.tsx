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
          <p className="anpi-break">
            网站：{snapshot.httpOrigins.join("、") || "无"}
          </p>
        </>
      ) : (
        <p>无法读取权限范围，暂不能授权。</p>
      )}
      <p className="anpi-small">{FULL_PERMISSION_NOTICE}</p>
      <p className="anpi-small">签名可在外部使用，不受网站列表限制。</p>
    </>
  );
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
      <h2>身份</h2>
      <p className="anpi-muted">管理此 DSH 中保存的身份</p>
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
                  <strong title={identityLabel(item)}>{identityLabel(item)}</strong>
                  <small title={item.reference.did}>{item.reference.did}</small>
                </span>
              </button>
            ))}
          </nav>
          {identity && (
            <div className="anpi-detail" key={view.selectedKey}>
              <h3>{identityLabel(identity)}</h3>
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
  const key =
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
  if (modal.kind === "result") {
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
    title = `允许${request.caller.displayName}${request.kind === "create" ? "创建" : "使用"}身份？`;
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
      <fieldset>
        <legend>授权方式</legend>
        <div className="anpi-mode">
          <label>
            <input
              type="radio"
              name="anpi-mode"
              checked={mode === "once"}
              onChange={() => {
                setMode("once");
              }}
            />
            单次授权<small>仅本次操作有效</small>
          </label>
          <label>
            <input
              type="radio"
              name="anpi-mode"
              checked={mode === "permanent"}
              onChange={() => {
                setMode("permanent");
              }}
            />
            永久授权<small>持续有效，直到你撤销</small>
          </label>
        </div>
      </fieldset>
      {mode === "permanent" ? (
        <p className="anpi-operation">持续授权：可读取公开身份、签名，并请求下列全部网站，直到你撤销。不仅限于当前操作。</p>
      ) : request.operation ? (
        <p className="anpi-operation">本次操作：{request.operation.summary}</p>
      ) : (
        mode === "once" && (
          <p role="alert">
            原插件未提供明确操作，暂不能批准单次授权，请原插件补齐。
          </p>
        )
      )}
      {mode === "once" &&
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
      <div className="anpi-access-scope">
        <p className="anpi-small">{FULL_PERMISSION_NOTICE}</p>
        <p className="anpi-small">签名可在外部使用，不受网站列表限制。</p>
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
          网站：{snapshot?.httpOrigins.join("、") || "无"}
        </p>
      </div>
      <DecisionActions
        controller={controller}
        disabled={
          !identity ||
          !snapshot ||
          Boolean(review.unavailableReason) ||
          (mode === "once" && !request.operation)
        }
        approve={() => {
          if (identity)
            void controller.decide({
              decision: "approve",
              identity: identityReference(identity),
              mode,
              ...(snapshot ? { reviewedSnapshot: snapshot } : {}),
            });
        }}
        label="允许授权"
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
