# ANP Identity 外部 HTTP 请求签名与 DSH 插件集成方案

- 状态：方案草案，尚未实施功能代码
- 日期：2026-08-30
- 适用仓库：`anp-identity`
- 适用范围：E1 Identity、Rust Host SPI、Node Host Provider、DeepSeek Harness/Cordis 插件

## 1. 结论摘要

`anp-identity` 已经具备为外部 HTTP 请求生成身份签名的能力，仓库中也已经存在较完整的 DSH/Cordis 插件：

```text
packages/dsh-anp-identity
```

因此，本任务不应重新创建第二套插件。推荐将后续工作定义为：

> 审核、加固、真实接入并发布现有 `@agent-network-protocol/dsh-anp-identity` 插件。

当前已经形成以下调用链：

```text
Rust Exact HTTP Signing
  → Node Host Provider
  → DSH/Cordis Identity Service
  → DSH consumer plugin
  → external HTTPS service
```

现有实现已经通过针对性 Rust 测试和 DSH 包自身的验证脚本，但仍有三个必须优先闭环的问题：

1. 普通 DSH consumer 可以通过当前的 `transport` callback 读取已签名 Request，和文档声明的“普通 consumer 不获得签名 Header patch”不完全一致。
2. 现有 DSH 测试主要确认签名 Header 被生成，尚缺少正式 verifier 对最终 HTTP Request 的端到端验签。
3. 顶层 GitHub Actions 尚未执行 `packages/dsh-anp-identity` 的 `npm run verify`。

在解决这些问题并完成真实 DSH 安装、重启和外部 HTTPS verifier 验收前，不宜将当前状态表述为生产级 DSH 集成已经完成。

## 2. 目标与非目标

### 2.1 目标

- 明确 `anp-identity` 外部 HTTP 请求签名的真实能力边界。
- 为 DSH 普通插件提供受 capability 和 origin policy 限制的认证 HTTP 请求能力。
- 为 AWiki IM Core 等可信 Host consumer 保留受控的精确 Header patch 能力。
- 保证普通 consumer、Browser、Remote、Agent Tool 和模型不会获得通用签名 Oracle。
- 使用正式 ANP verifier 验证最终发送的 HTTP Request。
- 建立 Rust、Node Provider、DSH、真实 DSH 部署和外部服务的分层验收。
- 将 DSH 插件构建、测试、公共 API 和打包检查加入仓库 CI。

### 2.2 非目标

- 不新增 K1、PlainLegacy 或其他非 E1 Identity profile。
- 不把 ANP Identity 变成通用 HTTP client、OAuth client 或 Bearer Token cache。
- 不在 Identity 插件中实现外部服务的 challenge/retry 业务状态机。
- 不向普通 DSH consumer 暴露私钥、Root Key、raw ECDH shared secret 或通用签名 Header patch。
- 不直接向模型暴露“任意 URL + 任意 KID + 任意 bytes”的签名工具。
- 不在第一阶段顺带实现 DID Registry、Resolver、发布服务、钱包 UI、备份系统或 Root Key rotation。

## 3. 现有实现盘点

### 3.1 Rust Host SPI

Rust 侧已经提供 `HttpRequestSigningPort::prepare_http_signature`。输入包括：

- `KeySelector`：显式 KID 或唯一默认候选；
- 完整 URL；
- HTTP method；
- headers；
- 可选 body；
- 可选 `nonce`、`created`、`expires`；
- 可选 `covered_components`。

输出包括：

- `binding_digest`；
- 实际使用的 `kid`；
- `header_patch`，其中包含 `Signature-Input`、`Signature`，有 body 时还包含 `Content-Digest`。

已有约束：

- body 最大 4 MiB；
- 拒绝调用方预置 `Authorization`、`Content-Digest`、`Signature-Input` 和 `Signature`；
- 拒绝 header value 中的 CR/LF；
- 拒绝大小写归一化后的重复 header；
- 只使用 active、managed、未擦除的密钥；
- 密钥必须被 DID Document 的 `authentication` relationship 授权；
- 允许 `request_signing` 和 `device_signing` 角色；
- 默认候选不是唯一一个时 fail closed。

Rust Host SPI 还提供独立的 Legacy DID-WBA Authorization Header 生成入口。它和 RFC 9421 风格的 HTTP Message Signature 是两种不同的认证方式，外部服务接入前必须明确选择哪一种。

### 3.2 Node Host Provider

Node Provider 已公开以下受 capability 控制的接口：

```ts
prepareHttpSignature(
  request: ExactHttpSigningRequest,
): Promise<PreparedHttpSignatureAttempt>
```

相关 capability 为：

```text
IDENTITY_HTTP_SIGNATURE
```

Node DTO 已覆盖：

- identity reference；
- KID；
- URL；
- method；
- headers；
- Buffer body；
- nonce；
- created；
- expires；
- covered components。

这使可信 Node Host 能调用 Rust 生成精确请求签名，而默认 Node Facade 不直接暴露 Header patch。

### 3.3 DSH/Cordis 插件

现有包：

```text
@agent-network-protocol/dsh-anp-identity
```

当前版本：

```text
0.1.0
```

现有 peer dependency：

```text
@agent-network-protocol/anp-identity ^0.2.0
@deepseek-ai/cordis ^4.0.1
```

现有 Node 基线：

```text
^22.19.0 || >=24.0.0
```

DSH 插件已经实现：

- `ctx.anpIdentity` Cordis Service；
- 独立 Native Provider 插件；
- 多 DID create/list/get/delete；
- consumer-scoped lease；
- capability 映射；
- consumer grant、label 和唯一 handle；
- purpose-scoped sign/verify；
- Origin Proof；
- DID Document Change Session；
- catalog intent、tombstone、generation/CAS 和跨进程锁；
- Store/catalog recovery；
- 精确 HTTPS origin allowlist；
- HTTP body 4 MiB 限制；
- 调用方认证 Header 拒绝；
- manual redirect；
- Host-only Provider lease；
- keyring、env、local-file 和 programmatic injected Root Key；
- 双语 README、安全边界文档、Cordis patch 和第三方插件示例。

### 3.4 当前验证结果

本方案形成前实际执行了以下检查：

```bash
cargo test -p anp-identity host::http_signing::tests
```

结果：

```text
3 passed; 0 failed
```

以及：

```bash
cd packages/dsh-anp-identity
npm run verify
```

结果：

- TypeScript source/test typecheck 通过；
- 公共 API snapshot 检查通过；
- 生成文件检查通过；
- 2 个测试文件通过；
- 12 个测试通过。

这些结果证明现有实现不是空壳，但尚未覆盖全仓测试、真实 DSH tarball 安装和外部 HTTPS verifier E2E。

## 4. 外部 HTTP 请求签名的能力边界

### 4.1 可以做到什么

ANP Identity 可以使用当前 Identity Store 中的授权 Ed25519 身份密钥，对给定 method、URL、部分 headers 和可选 body 生成 HTTP Message Signature Header。

典型输出包括：

```text
Signature-Input
Signature
Content-Digest    # 当请求包含 body 时
```

接收端可以根据 `keyid` 找到 DID Document 中的 verification method，并确认该密钥被 `authentication` relationship 授权后完成验签。

### 4.2 不能自动做到什么

“能够生成签名”不代表任意外部服务都能使用该认证方式。外部服务必须支持相同协议，并完成：

- 解析 `Signature-Input` 和 `Signature`；
- 解析或获取 DID Document；
- 找到 `keyid` 对应的 verification method；
- 检查 `authentication` relationship；
- 验证 Ed25519 signature；
- 验证 `Content-Digest`；
- 检查 `created`、`expires` 和 nonce/replay policy。

如果外部服务只支持 OAuth、Bearer Token、AWS SigV4、自定义 HMAC 或 mTLS，则需要单独的认证适配，不能假设 ANP HTTP Message Signature 可以直接替代。

### 4.3 默认签名不覆盖所有 Header

底层默认 covered components 主要包括：

```text
@method
@target-uri
@authority
content-digest    # 当 body 存在时追加
```

普通请求 Header 即使被作为输入传入，也不会自动全部进入 signature base。`binding_digest` 会绑定 Host 提供的归一化 headers 和 body digest，但它不是远端服务器能够独立验证的 HTTP Message Signature 字段。

因此必须在集成契约中明确：

- `content-type` 是否需要覆盖；
- 业务请求 ID 是否需要覆盖；
- 幂等键是否需要覆盖；
- 哪些 Header 会被 Fetch、反向代理或网络栈修改；
- 哪些 Header 必须在签名完成后保持不可变。

### 4.4 Rust Host SPI 与 DSH 的策略边界

Rust Host SPI 接收 Host 提供的精确请求数据，但不承担完整的外网访问策略。HTTPS-only、origin allowlist、redirect policy 和 transport ownership 应由 DSH Host 层负责。

这意味着：

- Rust 负责密钥选择、签名和密码学约束；
- Node Provider 负责 capability lease 和 FFI DTO；
- DSH Service 负责 consumer policy、origin policy、body limit 和网络发送；
- 业务插件负责业务请求 schema，不应取得通用签名能力。

## 5. 当前关键缺口

### 5.1 P0：普通 consumer 可以观察已签名 Request

当前公开 API 为：

```ts
identity.authenticatedHttp.dispatch(request, transport)
```

DSH 插件完成签名后调用：

```ts
return transport(authenticatedRequest(request, body, attempt.headerPatch))
```

`transport` 由普通 consumer 提供，因此 consumer 可以在 callback 中读取已经写入 Request 的 `Signature-Input`、`Signature` 和 `Content-Digest`。

这与文档中的“普通 consumer 永远拿不到 Header patch”不完全一致：consumer 虽然没有得到独立的 `headerPatch` DTO，但能够读取等价的签名 Header。

风险包括：

- 普通插件可以缓存并重放有效期内的精确签名请求；
- 普通插件可以把签名 Header 发送给其他代码路径；
- 公开 API 和安全文档形成错误的信任预期；
- 测试通过的原因反而证明 consumer 可以观察签名 Request。

推荐将普通 API 收敛为：

```ts
dispatch(request: Request): Promise<Response>
```

由 Host Service 持有并调用网络 transport。测试 transport 只能在 Host 初始化或 fixture 层注入，不由普通 lease consumer 每次提供。

如果产品明确把所有同进程插件都视为完全可信，可以保留当前 API，但必须修改安全文档，明确普通 consumer 能够观察签名 Request。推荐方案仍然是收回 transport，以维持更强且更清晰的边界。

### 5.2 P0：缺少正式 verifier E2E

现有 DSH 测试主要证明：

- 签名 Header 存在；
- manual redirect 被设置；
- 非法 origin 被拒绝；
- 调用方认证 Header 被拒绝；
- 超大 body 被拒绝；
- 重启后身份仍然可签名。

但尚未证明：

- 正式 ANP verifier 能验证最终 HTTP Request；
- method 被修改后验证失败；
- URL 或 query 被修改后验证失败；
- body 被修改后验证失败；
- 被覆盖 Header 被修改后验证失败；
- 未被覆盖 Header 的行为符合书面契约；
- 签名请求能够被真实外部 HTTPS 服务接受。

必须增加完整 sign → transport → verify 链路，而不是只断言 Header 存在。

### 5.3 P0：DSH verify 未进入顶层 CI

`packages/dsh-anp-identity/package.json` 已定义：

```text
npm run verify
```

但顶层 `.github/workflows/ci.yml` 当前只明确执行 Rust workspace 和 Node binding 的检查，没有执行 DSH 插件 verify。

这会导致：

- Rust/Node API 变化破坏 DSH 插件时，顶层 CI 可能仍然通过；
- 公共 TypeScript API snapshot 可能过期；
- Cordis 类型或运行时行为可能静默回归；
- 发布前才发现 DSH package 不可构建。

### 5.4 P1：尚无真实 DSH 安装闭环

Cordis fixture 通过不等于目标 DSH 部署已经验收。仍需验证：

- npm tarball 内容完整；
- native `.node` binary 可被目标平台加载；
- Service 和 Provider 插件装载顺序正确；
- Cordis fiber dispose 和 DSH shutdown 正确释放 lease；
- 目标 service account 可以访问 keyring；
- DSH restart 后 Store、DID 和 KID 保持连续；
- 真实外部 HTTPS verifier 接受最终请求。

### 5.5 P1：covered components 和网络栈变更策略未冻结

如果签名后 Fetch、代理或业务 transport 修改了被覆盖字段，远端验签会失败；如果重要业务 Header 没有被覆盖，远端可能接受语义被改变的请求。

必须先明确：

- Host 最终发送的 exact request 是什么；
- 签名发生在网络栈修改前还是修改后；
- 哪些 Header 可以由 transport 增加；
- 哪些 Header 必须由 Host 固定并纳入签名；
- redirect 是否由调用方处理，还是由 Host 对每个新 target 重新授权和签名。

## 6. 推荐目标架构

### 6.1 普通 DSH consumer

```text
DSH consumer plugin
  │
  │ acquireClient({
  │   consumer,
  │   capabilities: ['identity:http-auth'],
  │   httpOrigins,
  │ })
  ▼
ctx.anpIdentity
  │
  │ validate consumer/capability/grant/origin/body
  ▼
Host-owned authenticated HTTP dispatcher
  │
  │ exact request DTO
  ▼
Node Provider lease
  │ IDENTITY_HTTP_SIGNATURE
  ▼
Rust ANP Identity
  │ signed Header patch
  ▼
Host-owned network transport
  │
  ▼
External HTTPS service
  │
  ▼
Response returned to consumer
```

普通 consumer 只能提交 Request 并接收 Response，不能取得 Header patch 或已签名 Request。

### 6.2 可信 Host consumer

AWiki IM Core 等确实需要原生 bridge 的可信消费者可以使用：

```ts
ctx.anpIdentity.acquireProvider({
  consumer,
  capabilities: ['IDENTITY_HTTP_SIGNATURE'],
})
```

约束：

- consumer 必须同时出现在 `allowConsumers` 和 `allowProviderConsumers`；
- Host lease 必须有 TTL；
- Header patch 只能交给同一可信 native bridge；
- 不得通过 Remote、Browser、Agent Tool 或模型接口转发；
- 不得记录请求 body、签名 Header 或本地身份路径。

### 6.3 模型或 Agent Tool

不推荐为模型提供以下通用工具：

```text
sign_http_request(url, method, headers, body, kid)
```

推荐由业务 consumer 插件提供限定操作，例如：

```text
customer_api.get_profile
customer_api.submit_order
awiki.send_message
```

业务插件内部固定：

- endpoint；
- method；
- 请求 schema；
- 允许的 Header；
- 响应 schema；
- 审批和幂等规则。

然后在 Host 内部调用 `ctx.anpIdentity` 完成身份认证。模型获得的是业务能力，而不是通用身份签名能力。

## 7. 分阶段实施计划

### 阶段 0：冻结用途和协议契约

目标：明确签什么、谁来调用、谁来验证，避免实现与安全预期分叉。

任务：

1. 明确目标 consumer：普通 DSH 插件、可信 Host consumer，或二者都需要。
2. 明确外部认证协议：RFC 9421 风格 HTTP Message Signature、Legacy DID-WBA，或两套均支持。
3. 明确外部 verifier 如何解析 DID 和校验 `authentication` relationship。
4. 明确 covered components。
5. 明确 `created`、`expires`、nonce 和 replay policy。
6. 明确 401 challenge/retry 的责任模块。
7. 明确 redirect policy。
8. 明确目标 DSH、Cordis、Node 和平台版本。
9. 明确 Root Key provider，生产环境优先 keyring 或独立 Host 注入方案。

验收产物：

- 一份简短 ADR；
- 普通 client contract；
- Host Provider contract；
- 外部 verifier contract；
- 明确的非目标列表。

完成标准：

- 不存在“所有 Header 都被签名”之类未经实现支持的描述；
- 普通 consumer 与 Host consumer 的权限边界无歧义；
- 外部服务可以基于契约独立实现 verifier。

### 阶段 1：加固 DSH HTTP dispatcher

目标：普通 consumer 只能发送受控的认证请求，不能直接获得签名材料。

任务：

1. 将普通 client API 改为 Host-owned transport。
2. 将测试 transport 注入移动到 Service/Host fixture 层。
3. 保留 Host Provider 的 `prepareHttpSignature`。
4. 保持并复核精确 HTTPS origin allowlist。
5. 保持对 username、password、fragment 和非 HTTPS URL 的拒绝。
6. 保持调用方预置认证 Header 的拒绝。
7. 固化普通 consumer 的 covered components policy，不允许任意 caller 控制。
8. 明确无 body 与显式空 body 的不同语义。
9. 保持 4 MiB 限制，并在签名前拒绝超限 body。
10. 默认不自动 follow redirect；如果未来支持，必须逐跳重新授权和重新签名。
11. 确保错误不包含 URL、body、DID 私密状态、本地路径或 Provider 内部细节。

完成标准：

- 普通 `ManagedIdentityClient` 中不存在 Header patch API；
- 普通 consumer 无法通过 callback 观察已签名 Request；
- 非法 origin 在 Provider 调用和网络发送前失败；
- 可信 Host consumer 的受控 Header patch 能力不受影响；
- 公共 API snapshot 和双语文档同步更新。

### 阶段 2：补齐协议级测试

#### 2.1 Rust 测试

增加或确认以下用例：

- GET，无 body；
- POST，JSON body；
- POST，显式空 body；
- query string；
- 二进制 body；
- 固定 `created`、`expires`、nonce 的确定性向量；
- `request_signing` KID；
- `device_signing` KID；
- revoked key；
- erased key；
- external key；
- 未被 `authentication` relationship 授权的 key；
- 多个默认候选时 fail closed；
- body 恰好 4 MiB；
- body 为 4 MiB + 1；
- 重复 Header；
- Header CR/LF；
- 调用方预置认证 Header；
- 篡改 method 后验签失败；
- 篡改 URL 后验签失败；
- 篡改 query 后验签失败；
- 篡改 body 后验签失败；
- 篡改 `Content-Digest` 后验签失败；
- 篡改被覆盖业务 Header 后验签失败；
- 未被覆盖 Header 的行为被明确记录和测试。

#### 2.2 Node Provider 测试

增加或确认：

- 缺少 `IDENTITY_HTTP_SIGNATURE` capability 时拒绝；
- lease dispose 后拒绝；
- lease 超时后拒绝；
- identity reference DTO 映射正确；
- Buffer body 不被文本编码破坏；
- 零长度 Buffer 和 undefined body 不被混淆；
- nonce、created、expires 和 covered components 完整透传；
- Native error 映射为稳定 code；
- 错误中不泄露 URL、body 和 Store 路径。

#### 2.3 DSH Service 测试

增加或确认：

- consumer allowlist；
- capability allowlist；
- identity grant；
- exact origin allowlist；
- 非 HTTPS 拒绝；
- URL credentials 拒绝；
- URL fragment 拒绝；
- caller-managed auth Header 拒绝；
- 4 MiB 边界；
- manual redirect；
- redirect 不复用旧签名；
- Host-owned transport；
- transport error 传播规则；
- Provider incompatibility；
- key rotation 后 KID cache 刷新或明确 fail closed；
- identity deletion/tombstone 期间禁止签名；
- catalog corrupt 时授权 fail closed；
- DSH Service restart 后身份连续；
- 正式 ANP verifier 验证最终 Request。

完成标准：

- 至少一个测试使用正式 verifier 验证最终 HTTP Request；
- 至少覆盖 method、URL/query、body 和一个业务 Header 的 tamper test；
- 测试不再依赖普通 consumer 捕获已签名 Request。

### 阶段 3：真实 DSH 集成验收

目标：证明发布包能在目标 DSH 中装载和工作，而不是只在源码 fixture 中通过。

任务：

1. 构建 Node native binding。
2. 分别对 native package 和 DSH package 执行 `npm pack`。
3. 从 tarball 安装到隔离的真实 DSH 实例，避免只验证源码软链接。
4. 先加载 Identity Service，再加载 Native Provider。
5. 使用绝对 `stateRoot`。
6. 生产形态优先使用 keyring。
7. 配置最小 consumer allowlist 和 exact origin allowlist。
8. 检查 `ctx.anpIdentity.health()`。
9. 创建或打开 E1 DID。
10. 向测试 verifier 发送一个签名 GET 和一个签名 POST。
11. 重启 DSH 后重新打开同一 Store 和 DID。
12. 验证其他 consumer 不能越权使用身份。
13. 验证非法 origin 不产生网络流量。
14. 检查日志、catalog 和错误信息中没有敏感材料。

建议配置形态：

```yaml
- insert:
    - id: anp-identity
      name: '@agent-network-protocol/dsh-anp-identity'
      config:
        stateRoot: /var/lib/dsh/anp-identity
        allowConsumers:
          - example/http-client
        allowProviderConsumers: []
        httpAllowedOrigins:
          example/http-client:
            - https://api.example.com
        recoveryOnOpen: true

    - id: anp-identity-provider
      name: '@agent-network-protocol/dsh-anp-identity/provider'
      config:
        stateRoot: /var/lib/dsh/anp-identity
        rootKeyProvider: keyring
        rootKeyProviderId: anp-identity/dsh
        keyringFallbackToLocalFile: false
```

完成标准：

- 真实 DSH 加载成功；
- health 为 `ready`；
- 真实 verifier 接受签名 GET/POST；
- DSH restart 后 DID、KID 和 Store 连续；
- 非法 consumer/origin 在网络发送前失败；
- tarball 安装不依赖仓库相对路径。

### 阶段 4：CI、打包和发布闭环

目标：Rust、Node 或 DSH 任意一层变化时，CI 能及时发现跨层破坏。

建议在顶层 CI 中增加独立 DSH job，至少执行：

```bash
npm --prefix bindings/node ci
npm --prefix bindings/node run build
npm --prefix bindings/node test

cd packages/dsh-anp-identity
npm ci --legacy-peer-deps
npm run verify
npm pack --dry-run
```

进一步建议：

- 从实际 tarball 安装后运行最小 Cordis smoke test；
- 在目标 Linux 架构上运行 native load test；
- 如果声明 macOS/Windows 支持，则分别构建和加载对应 native artifact；
- 检查 package files 中包含 `lib/**`、README、BOUNDARY、Cordis patch、LICENSE 和 examples；
- 保持 public API snapshot freshness；
- 发布前运行全仓 Rust/Node/DSH 验证。

发布顺序：

1. 发布并验证 `@agent-network-protocol/anp-identity@0.2.x`；
2. 发布 `@agent-network-protocol/dsh-anp-identity@0.1.x`；
3. 在隔离 DSH 中从 registry 或 tarball 安装固定版本；
4. 完成真实外部 HTTPS verifier smoke；
5. 再更新正式 DSH profile。

完成标准：

- PR 修改任意跨层接口时，顶层 CI 会执行 DSH verify；
- `npm pack --dry-run` 通过；
- 真实 tarball 安装 smoke 通过；
- 发布版本与 peer dependency 匹配；
- 文档中的安装命令可以在干净环境复现。

## 8. 测试矩阵

| 层级 | 重点 | 必须证明的结果 |
| --- | --- | --- |
| Rust Host SPI | key policy、exact request、signature generation | 正确 KID、Header patch、body limit、tamper failure |
| ANP verifier | DID relationship、signature base、digest | 最终请求可验证，篡改后不可验证 |
| Node Provider | capability、DTO、async FFI | 未授权拒绝，参数无损透传，稳定错误码 |
| DSH Service | consumer/grant/origin/transport | 普通 consumer 不获得签名材料，非法请求发送前失败 |
| Catalog/lifecycle | restart、intent、tombstone、recovery | 重启连续，异常状态 fail closed |
| Package | build、types、exports、tarball | 干净安装可用，公共 API 与实现一致 |
| 真实 DSH | Cordis load、keyring、shutdown/restart | health ready、Store 连续、lease 正确释放 |
| 外部 HTTPS | 网络传输、server verifier | 签名 GET/POST 被接受，非法或篡改请求被拒绝 |

## 9. 安全检查清单

- [ ] 普通 client API 不返回 Header patch。
- [ ] 普通 consumer 不接收已签名 Request callback。
- [ ] Host Provider lease 需要显式 allowlist。
- [ ] HTTP signature capability 单独授权。
- [ ] origin 使用精确 HTTPS origin，不接受 wildcard。
- [ ] URL username/password 和 fragment 被拒绝。
- [ ] caller-managed Authorization/Signature Header 被拒绝。
- [ ] body 在签名前完成有界读取。
- [ ]无 body 与空 body 语义明确。
- [ ] redirect 不自动复用旧签名。
- [ ] KID 必须 active、managed、未擦除且 relationship authorized。
- [ ]默认 KID 多候选时 fail closed。
- [ ] covered components 有明确 Host policy。
- [ ] created/expires/nonce/replay policy 有服务端对应实现。
- [ ]日志不包含 body、Header patch、Root Key、私钥或 token。
- [ ] catalog 不包含 cryptographic secret。
- [ ]错误不包含请求 URL、body、本地路径或敏感 Provider detail。
- [ ] keyring 和 Store 权限符合部署要求。
- [ ] DSH shutdown/restart 会释放并重建 lease。

## 10. 最终验收标准

只有同时满足以下条件，才能宣称“ANP Identity 已正式支持在 DSH 中为外部 HTTP 请求签名”：

1. Rust 能生成并由正式 verifier 验证 HTTP Message Signature。
2. method、URL、query、body 和约定 covered Header 被篡改时验证失败。
3. 外部测试服务实际接受至少一个签名 GET 和一个签名 POST。
4. 普通 DSH consumer 不能读取 Header patch 或已签名 Request。
5. 普通 consumer 不能选择未授权 KID、origin 或 covered components。
6. Host-only consumer 只能通过 allowlist、capability 和 TTL lease 获取精确签名能力。
7. body limit、Header injection、非 HTTPS、credentials 和 redirect 均按契约处理。
8. key rotation、revocation、Store reopen 和 DSH restart 后行为正确。
9. catalog、错误和日志中没有私钥、Root Key、body、token 或其他敏感内容。
10. DSH package verify 已进入顶层 CI。
11. 从打包产物安装到真实 DSH 的 smoke/E2E 通过。
12. 中英文文档、安全边界和真实 API 一致。

## 11. 优先级建议

### P0

1. 冻结外部 verifier、covered components 和 replay 契约。
2. 修正普通 consumer 的 transport/已签名 Request 暴露边界。
3. 增加正式 sign-and-verify E2E 和 tamper tests。
4. 将 DSH `npm run verify` 加入顶层 CI。

### P1

1. 从 tarball 安装到真实 DSH。
2. 验证 keyring、shutdown/restart 和 Store 连续性。
3. 验证真实外部 HTTPS verifier。
4. 验证 key rotation 后的 KID cache 行为。

### P2

1. 只有在目标服务需要时再补 Legacy DID-WBA 完整链路。
2. 按正式发布范围扩展 native 多平台 artifact 验证。
3. 开发面向具体业务的 DSH consumer 插件，不开发通用模型签名工具。

## 12. 推荐的最小交付顺序

```text
协议 ADR
  → Host-owned transport
  → verifier E2E
  → DSH CI
  → tarball install smoke
  → real DSH restart test
  → external HTTPS verifier test
  → release
```

这条顺序优先解决安全边界和协议正确性，再处理发布工程，不需要重写现有 Rust、Node Provider 或 DSH Service 架构。
