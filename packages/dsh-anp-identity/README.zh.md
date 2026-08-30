# 面向 DeepSeek Harness 的 ANP Identity

`@agent-network-protocol/dsh-anp-identity` 为 DSH 应用提供共享的多 DID 身份 Store。应用不需要各自实现私钥托管、DID Document 生命周期、崩溃恢复和请求签名。

普通插件通过 `ctx.anpIdentity` 使用精简的 TypeScript Facade。私钥操作由 ANP Identity 原生模块完成；私钥在磁盘上加密保存。DSH catalog 只记录 label、handle 和 consumer grant 等非秘密元数据。

## 它解决什么问题

一个 DSH 安装中可能同时存在多个插件和多个 DID。这个插件统一解决：

- DID 私钥由谁保管，以及某个签名目的应该使用哪类密钥；
- DID Document 更新如何在进程崩溃或发布结果不确定时恢复；
- 多个插件如何共用身份，而不让任一普通插件取得私钥；
- HTTP 请求如何完成身份认证，同时不把可复用 Header patch 交给调用方；
- 多 DID、通用 handle、consumer grant 和删除保护如何保持一致。

ANP Identity Store 是身份与加密密钥的真值。插件增加事务化的 `catalog-v1`：创建前写 intent，删除前写 tombstone；跨进程修改使用文件锁、generation 检查和原子 rename。异常重启后流程会继续完成，未知身份只会成为无授权的 `Unclaimed`，不会猜测所有者。

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

## 其他 DSH 插件如何使用

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
- deletion tombstone 未完成：继续删除；
- catalog 损坏：grant 与 handle fail closed。显式执行 `recover()` 后，按 Store 重建为 `Unclaimed`，不会伪造授权。

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
