# DSH 外部 HTTP 请求签名功能闭环计划

- 状态：已完成
- 日期：2026-08-30
- 优先级：P0
- 适用仓库：`anp-identity`

## 1. 目标

本计划只完成一件事：

> 打通真实 DSH → `dsh-anp-identity` → Node Provider → Rust 签名 → HTTPS verifier 的完整功能链路。

完成后，应能证明现有插件可以在真实 DSH 中为外部 HTTP 请求生成身份签名，并且最终发送的 GET 和 POST 请求能够被服务端正确验签。

## 2. 本阶段固定选择

- 使用现有 `@agent-network-protocol/dsh-anp-identity` 插件，不创建第二套插件。
- 只使用 E1 Identity。
- 只使用现有 HTTP Message Signature 流程，不接入 Legacy DID-WBA。
- 继续使用现有 `authenticatedHttp.dispatch(request, transport)` API，不调整 transport 所有权。
- 使用 `request_signing` 身份密钥。
- 使用当前默认 covered components；POST body 继续通过 `Content-Digest` 绑定。
- verifier 使用 ANP 已有正式验签接口。
- DID Document 在测试环境中预先提供给 verifier，不在本阶段实现远程 DID Resolver。

## 3. 不在本阶段处理

- 普通 consumer 与同进程恶意插件之间的安全隔离。
- Host-owned transport 改造。
- 更细粒度的 path、method 或业务操作授权。
- keyring 和生产 Root Key 部署。
- challenge/retry、Bearer Token 和业务鉴权状态机。
- DSH 重启恢复、密钥轮换和并发 consumer。
- Legacy DID-WBA。
- 多平台 native artifact。
- 顶层 CI、正式发布和生产环境接入。
- Browser、Remote、Agent Tool 或模型接口。

## 4. 功能链路

```text
真实 DSH consumer
  → ctx.anpIdentity.acquireClient
  → identity.authenticatedHttp.dispatch
  → Node Provider.prepareHttpSignature
  → Rust HttpRequestSigningPort
  → transport 发送真实 HTTPS 请求
  → ANP verifier 验证最终 Request
  → 返回 2xx Response
```

## 5. 实施步骤

### 步骤 1：准备可安装产物

1. 构建现有 Node native binding。
2. 分别对 Node binding 和 DSH 插件执行 `npm pack`。
3. 在隔离目录中从 tarball 安装，不使用 workspace 软链接或源码直接引用。

验证结果：DSH 插件和 native binding 都能从打包产物正常加载。

### 步骤 2：准备最小 HTTPS verifier

1. 启动一个独立 HTTPS 测试服务。
2. 为服务配置测试 Identity 的 DID Document。
3. 使用 ANP verifier 验证最终收到的 method、URL、headers 和 body。
4. 验签成功返回 2xx，验签失败返回明确的 4xx。

验证结果：服务端不是只检查 Header 是否存在，而是实际执行密码学验签和 `Content-Digest` 校验。

### 步骤 3：在真实 DSH 中执行请求

1. 加载 Identity Service 和 Native Provider。
2. 获取包含 `identity:http-auth` capability 的 client lease。
3. 创建或打开一个包含 `request_signing` key 的 E1 Identity。
4. 将 verifier 的 HTTPS origin 配置到 consumer allowlist。
5. 发送一个无 body 的签名 GET 请求。
6. 发送一个 JSON body 的签名 POST 请求。
7. transport 使用真实网络发送请求，并把 Response 返回 consumer。

验证结果：GET 和 POST 都被 verifier 接受并返回 2xx。

### 步骤 4：确认验签不是假阳性

增加一个最小负向用例：修改已签名 POST 的 body 后发送，verifier 必须拒绝。

本阶段不扩展完整篡改矩阵；method、URL、query 和更多 Header 的覆盖留给后续协议测试。

## 6. 验收标准

以下条件全部满足后，P0 完成：

1. Node binding 和 DSH 插件均从 tarball 安装成功。
2. 插件在真实 DSH/Cordis 环境中成功加载。
3. E1 Identity 能通过现有链路完成请求签名。
4. 一个真实 HTTPS GET 请求通过 ANP verifier 验签。
5. 一个带 JSON body 的真实 HTTPS POST 请求通过验签和 `Content-Digest` 校验。
6. 篡改 POST body 后，verifier 明确拒绝请求。
7. consumer 能收到 verifier 返回的正常 HTTP Response。
8. 整个流程不依赖 mock transport、仅检查 Header 的断言或仓库内软链接。

## 7. 建议交付物

- 一个可重复执行的 DSH 功能 E2E。
- 一个最小 HTTPS verifier fixture。
- tarball 安装和运行脚本。
- 一份简短运行记录，包含使用版本、执行命令和通过结果。

## 8. 后续工作

P0 通过后，再分别规划：

1. 安全边界和 Host-owned transport。
2. 完整协议测试与互操作验证。
3. DSH restart、keyring 和生产部署。
4. 顶层 CI、跨平台构建和正式发布。

## 9. 实施结果

执行命令：

```bash
cd packages/dsh-anp-identity
npm run test:functional
```

该命令使用临时 `DSH_HOME`，构建 debug Node native binding，将 native binding、DSH 插件和测试 consumer 分别打包为 tarball，再通过真实 `dsh` CLI 安装并启动独立 HTTPS verifier。

2026-08-30 验收结果：

- 运行版本：Node `24.19.0`、DSH `0.1.0-rc.6`、ANP `1.0.0`、ANP Identity `0.2.0`、DSH 插件 `0.1.0`；
- tarball 安装和真实 DSH profile 加载成功；
- 签名 GET 通过 ANP verifier，返回 HTTP 200；
- 带 JSON body 和 `Content-Digest` 的签名 POST 通过，返回 HTTP 200；
- 使用原签名发送篡改 body 时，verifier 因 `Content-Digest verification failed` 返回 HTTP 401；
- consumer 收到并解析了全部真实 HTTPS Response。
