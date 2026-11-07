# 面向 DeepSeek Harness 的 ANP Identity

`@agent-network-protocol/dsh-anp-identity` 为 DSH 应用提供共享的多 DID 身份 Store。应用不需要各自实现私钥托管、DID Document 生命周期、崩溃恢复和请求签名。

普通插件通过 `bindIdentityClient(ctx)` 申请创建身份和使用授权；`ctx.anpIdentity` 的旧 lease 接口保留给可信 Host 集成。私钥操作由 ANP Identity 原生模块完成；私钥在磁盘上加密保存。DSH catalog 只记录 label、handle 和 consumer grant 等非秘密元数据。

## 它解决什么问题

一个 DSH 安装中可能同时存在多个插件和多个 DID。这个插件统一解决：

- DID 私钥由谁保管，以及某个签名目的应该使用哪类密钥；
- DID Document 更新如何在进程崩溃或发布结果不确定时恢复；
- 多个插件如何共用身份，而不让任一普通插件取得私钥；
- HTTP 请求如何完成身份认证，同时不把可复用 Header patch 交给调用方；
- 多 DID、通用 handle、consumer grant 和删除保护如何保持一致。

ANP Identity Store 是身份与加密密钥的真值。插件增加事务化的 catalog：创建前写 intent，删除前写 tombstone；跨进程修改使用文件锁、generation 检查和原子 rename。异常重启后流程会继续完成，未知身份只会成为无授权的 `Unclaimed`，不会猜测所有者。当前发布扩展将 catalog 升级为 v4，升级和回滚必须遵循 [V7-MANAGEMENT.md](./V7-MANAGEMENT.md) 的停写与一致性要求。

## 主要能力

- 多 DID 创建、列举、打开、删除和恢复；
- 按 purpose 约束的 Ed25519 签名与验签；
- Origin Proof 签名；
- 事务化 DID Document Change Session；
- consumer-scoped lease、grant、label 和唯一 handle；
- 有上限的 HTTP 认证 dispatcher：只允许配置的精确 HTTPS origin，body 最大 4 MiB，拒绝调用方预置认证 Header，并强制 manual redirect；
- 独立的 Host Provider lease，供 AWiki IM Core 等可信原生消费者使用。sealed ECDH、sealed 导入导出、enrollment、Root Transfer 和精确 Header patch 只在这个 Host 面存在。

## 它不解决什么

- 它不是 DID Registry、Resolver、发布服务、备份系统或钱包 UI；
- 它不实现 AWiki 消息、Bearer Token、challenge 重试或 P5 Root Transfer；这些属于 `dsh-awiki` 与 AWiki IM Core；
- 它不向 Browser、Remote、Agent Tool 或模型暴露 raw ECDH shared secret、Root Key、导入私钥和通用签名工具；
- consumer 名称是同进程策略与诊断边界，可防误用，但不是针对同一 Node.js 进程内恶意代码的沙箱。

完整边界见 [BOUNDARY.md](./BOUNDARY.md)。

本轮源码候选还提供显式启用的 fresh 协议身份注册：`./protocol-bootstrap` 发起真实创建审批，现有 manager 的非秘密 `registrationBootstrap` 配置继续 User Service 邮箱/Turnstile 确认、Registry 验证及加密 Host 凭据保管。它要求独立 `dsh-identity/1106` 产品准入和匹配的 native API v2 候选；registry 版本号相同不代表已含这些方法。[发布与 fresh 设置](PUBLICATION.md#fresh-host-registration-bootstrap)说明分两阶段配置真实 Host；“已发布”不自动表示 MCP/PAP 已获使用许可。

协议身份创建（`parameters.usage: 'protocol'`）默认声明完整的私聊、群聊及端到端加密协议，E1 和 Web 都保留供后续消息插件使用的设备签名与加密协商密钥。创建身份不会自动连接消息插件或向它授权，也不会修改既有身份的文档。注册服务需要接受完整协议清单；显式开启 identity-only 模式的服务会拒绝该清单。具体协议列表见 [PUBLICATION.md](./PUBLICATION.md)。

## 安装与配置

```bash
pnpm add @agent-network-protocol/dsh-anp-identity
```

本包会安装精确兼容的 ANP Identity wrapper，由 wrapper 自动选择当前平台的预编译原生包；
用户不需要 Rust 或源码 checkout。Cordis 中先装载 Service，再装载 Provider：

随包发布的 DSH layer 默认向 `@awiki/dsh-plugin` 开放 client 和 Host Provider，确保文档中的
双插件安装无需额外本地 patch。其他部署可通过
`DSH_ANP_IDENTITY_ALLOW_CONSUMERS` 与
`DSH_ANP_IDENTITY_ALLOW_PROVIDER_CONSUMERS` JSON 数组完整替换默认值。

```yaml
- insert:
    - id: anp-identity
      name: '@agent-network-protocol/dsh-anp-identity'
      config:
        stateRoot: /var/lib/dsh/anp-identity
        allowConsumers: ['example/identity-client', '@awiki/dsh-plugin']
        allowProviderConsumers: ['@awiki/dsh-plugin']
        httpAllowedOrigins:
          example/identity-client: ['https://api.example.com']

    - id: anp-identity-provider
      name: '@agent-network-protocol/dsh-anp-identity/provider'
      config:
        stateRoot: /var/lib/dsh/anp-identity
        rootKeyProvider: keyring
        rootKeyProviderId: anp-identity/dsh
```

keyring 的 `rootKeyProviderId` 格式为 `service/account`；env 模式填写环境变量名；injected 模式填写 key id，并且只能通过可信 Host 代码以 Buffer 注入，不能写入 Loader YAML。`local-file` 必须显式启用；如果 Store 与 Root Key 文件被一起复制，攻击者可以离线解密 Store。

`local-file` 与 OS keyring 都是已实现的本地方式。采用文件保管的 Host 可选择 `rootKeyProvider: local-file`（bundle 对应 `DSH_ANP_IDENTITY_ROOT_KEY_PROVIDER=local-file`），不要求使用 OS keyring。管理 broker master 直接复用 DSH 既有原子 credential record，broker 与协议状态保持加密本地文件。

## 其他 DSH 插件如何使用

普通插件由 Host 加入 `userConsumers`，通过 `bindIdentityClient(ctx)` 提交请求，等待创建确认，再单独申请使用授权。创建不会发布 DID 文档、注册 Handle 或自动授予使用权。支持单次授权和持续到撤销的永久授权；当前默认授予全部普通使用权限，暂不支持逐项选择。

完整 API 与边界见 [管理说明](./V7-MANAGEMENT.md)；可运行示例见 [HTTP 签名 demo](../../demo/dsh-http/README.md)。设置页包含 Handle/DID、授权请求、权限详情和撤销入口。

### 既有可信 Host 集成

以下旧 lease 示例仅适用于明确配置的可信 Host 集成，不适用于普通 user-mode 插件。

调用插件声明 `inject = ['anpIdentity']`，申请最小 capability，并让 lease 随自己的 Cordis fiber 释放：

```ts
const lease = await ctx.anpIdentity.acquireClient({
  consumer: 'example/identity-client',
  capabilities: ['identity:read', 'identity:create', 'identity:sign'],
})

const identity = await lease.create({
  label: 'Example agent',
  handle: 'example.agent',
  identity: {
    profile: 'e1',
    domain: 'agents.example.com',
    pathSegments: ['agents', 'example'],
    managedKeys: [
      { fragment: 'root', role: 'root_control' },
      { fragment: 'request', role: 'request_signing' },
    ],
  },
})

const snapshot = await identity.publicIdentity()
await identity.sign({
  purpose: 'authentication',
  kid: `${snapshot.reference.did}#request`,
  payload: Buffer.from('canonical application bytes'),
})
```

HTTP 认证需要申请 `identity:http-auth`，由 Host 为该 consumer 配置精确 origin，然后调用 `identity.authenticatedHttp.dispatch(request, transport)`。普通 consumer 永远拿不到 Header patch。

## 模块协作

| 模块 | 职责 |
| --- | --- |
| `ctx.anpIdentity` | 公共多 DID Facade、client lease、catalog、grant、handle 和 HTTP dispatch |
| `./provider` | 打开原生 Store，并按 Cordis 生命周期注册唯一 Provider |
| `./provider-api` | 提供给 AWiki IM Core 等外部原生消费者的版本化 Host-only 契约 |
| `@agent-network-protocol/anp-identity` | 加密密钥托管、DID Document、签名、恢复和 sealed secret handoff |
| `dsh-awiki` | AWiki 账户、消息、Bearer Token/challenge 状态和应用工作流 |

移动端不依赖这个 DSH 包，可直接链接 ANP Identity Rust crate，同时复用相同的 Facade/Host SPI 语义。

## 恢复语义

- Store 有身份、catalog/journal 没有记录：重建为无 grant 的 `Unclaimed`；
- catalog 有记录、Store 没有身份：删除 dangling 条目；
- create intent 未完成：在能够唯一识别 Store 身份时继续提交；
- deletion tombstone 未完成：可在瞬时原生失败后继续删除；如果删除响应丢失，只有在确认
  精确的原生身份已经不存在后才移除 tombstone；
- catalog 损坏：grant 与 handle fail closed。显式执行 `recover()` 后，按 Store 重建为 `Unclaimed`，不会伪造授权。

Host Provider 删除属于显式的本地破坏性操作。它会先丢弃未发布的本地 Document 或
Enrollment 状态，再删除完整身份 namespace；该操作不会撤销或修改远端 DID。

`recover()` 会获取 Store 级独占锁并执行全量恢复，不应作为轮询 API。

## 开发验证

```bash
npm install --legacy-peer-deps
npm run verify
```

HTTP 签名功能 E2E 还需要 `dsh` CLI、Node `^22.19.0` 或 `>=24.0.0`、
`pnpm`、`uv`、OpenSSL，以及工作区约定的相邻 ANP checkout：

```bash
npm run test:functional
```

该命令会构建 debug native binding，将 native package、DSH 插件和测试
consumer 打包并安装到临时的真实 DSH profile，再向使用 ANP Python verifier
的独立 HTTPS 进程发送签名 GET 和 POST；篡改后的 POST 必须被拒绝。运行结束
后会删除临时 DSH profile、Store、证书和 tarball。

许可证：Apache-2.0。


## 公共客户端身份基础

新增能力和安全边界见 [PUBLICATION.md](./PUBLICATION.md)。公共身份插件可以独立加载，
通过可信 Host 注册的 User Service 管理通道和已有 DID 发布驱动，准备并发布 CIMD/JWKS。
缺少真实回调或授权通道时保持待配置，不要求消息或邮件插件，不默认发起第三方登录。
现有管理页展示发布状态、CIMD 和失败重试；普通插件的 OAuth 签名必须同时满足精确
`oauthAllowedAudiences`、用户 grant、已发布记录和有效密钥。断言不通过 Browser/Remote 返回。

协议身份通过显式 `usage: 'protocol'` 创建审批，使用本地 E1/Web 设备密钥、按能力投影的 ES256 发布，以及目标绑定的机器/PAP lease。真实 User Service 管理通道、加密凭据 broker、catalog v4 迁移与验证边界见 [发布与管理契约](./PUBLICATION.md)。

可信 Host 发布 driver 同时提供 typed、设备绑定的 PAP callback 注册与一次领取。V2 PAP account 可独立声明严格 RFC 8252 loopback redirect；V1 与受保护公开获取 URL 保持 HTTPS 规则。这些 callback 能力不向 Remote 或模型工具开放。
