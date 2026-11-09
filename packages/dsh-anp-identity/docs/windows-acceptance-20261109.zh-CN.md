# DSH 共享身份 Windows 验收报告

执行日期：2026-11-09 至 2026-11-10，Asia/Shanghai。验收范围为 Identity、ANP、PAP 和共享身份 MCP；Service Agent 仅作隔离联调服务，不包含移动端项目。

## 结论

**业务验收尚未通过，阻塞在身份注册后的设备认证与发布。** Windows 注册初始化问题已修复并在实际桌面候选包复测：沿用同一个请求，短信请求被服务端接受。用户提交验证码后，服务端已能返回匹配的 DID 文档，但本地仍为 `registration_uncertain`，身份详情为“尚未发布”，没有确认的 CIMD。

新增的只读设备核对在真实桌面上返回 **HTTP 401**。匿名设备查询同样返回 HTTP 401、JSON-RPC `-32000`，错误内容提及 Bearer、Token 和 Authorization。当前客户端的设备管理契约使用 HTTP Message Signatures，明确不回退到保存的 Bearer。独立 SDK 验证了隔离生成身份的同类请求签名。

因此，服务端认证契约兼容性是当前主要排查方向；**尚不能仅凭 401 将问题最终归责给服务端**，仍需结合部署版本与请求日志确认。没有修改线上服务、重发注册、清除不确定记录，或把已有 awiki.me 身份改绑到 awiki.info。

## 版本与隔离

| 项目 | 实际使用的版本或来源 |
| --- | --- |
| Windows 桌面 | DSH NEXT 2.0.22-next，Host 0.2.2-rc.1，内置 Node 24.21.0 |
| 原版注册基线 | Identity 0.1.16、ANP 0.1.4、PAP 0.1.4，来自 npm |
| 桌面 Identity 候选 | 0.1.16 加本地恢复补丁与只读诊断；保留原 0.1.16 controller；逐文件核对哈希 |
| Identity 源码测试 | `21b8facb87576ff0eec4f47a30ebe8a90c944d94` 加修复，工作区包版本 0.1.14；受影响编译模块与实际 0.1.16 基线核对相同后移植 |
| MCP 候选宿主 | `AgentConnect/dsh-harness-identity` 的 `194aaf492eca057539b15c1d8a7523e0dc7d7397`，在 Windows 构建并运行完整匹配的源码 Host |
| 身份服务 | 新的专用测试流程固定为 `https://awiki.info` |
| 隔离服务 | 已有本机 Service Agent、专用 PostgreSQL 容器和数据卷；仅本机访问 |

测试使用独立数据目录。原始个人目录、已有身份及 awiki.me 流程均保留。测试目录 ACL 已核对为当前用户、SYSTEM 和 Administrators。没有复制个人模型凭据，也没有导出私钥。

## 逐步验收

| 步骤 | 操作与预期 | 实际结果 | 判定及证据 |
| --- | --- | --- | --- |
| 环境与插件 | 核对实际包、配置、网络和权限 | 三个 npm 插件安装完成；注册服务在真实界面显示 awiki.info；原版 MCP 没有 `/domain` 入口 | 环境检查完成；不能代替业务成功。`baseline.json` |
| 原版注册 | 用户在身份管理创建并确认；应进入验证 | 0.1.16 显示注册不可用；状态目录返回 Windows 模式 `0666`，尚无执行目录 | 客户端 Windows 权限误判。`registration-stock-failure.json` |
| 修复后验证 | 实际加载候选包，沿用原请求 | 补丁文件哈希匹配；短信请求受理；未重复创建身份 | 本地阻塞已解除。`identity-deployment.json`、`registration-candidate-state.json` |
| 注册及发布 | 用户输入验证码；应确认注册并发布 DID/CIMD | DID 公共文档 HTTP 200 且 id 匹配；本地 `registerStarted=true`、`registered=false`；没有保存的管理凭据密文；尚未发布 | 阻塞，不能认定发布成功。`publication-after-owner-confirmation.json`、`publication-remote-check.json` |
| 只读定位 | 使用原本地设备签名查询 `device_registry_get` | 实际桌面返回 HTTP 401；状态仍不确定；未写凭据或重发注册 | 认证契约兼容性待服务端日志确认。`registration-inspection-product.json`、`registry-unauthenticated-baseline.json` |
| 三协议读取 | 同一已发布身份完成发现、认证、读取 | 前置发布条件未满足 | **未执行业务验收**。公开元数据探测不计为认证读取 |
| 隔离写入及跨协议读回 | 仅隔离服务写入并读回 | 本机健康、元数据与未认证拒绝检查符合预期；正式域名连接器拒绝 localhost/开发证书 | **未执行写入与读回**；未放宽正式网络或 TLS 校验。`service-start.log`、隔离服务 `health.json` |
| Matchall | 能力发现、草稿、结果查询；不发布真实需求 | 前置条件未满足；此前公开元数据探测存在超时/重定向 | **业务流程未执行**；不能以 fixture 的 scope 测试替代真实匹配结果 |

文章中的真实外站发帖、真实需求发布均明确**未执行**。本次也没有在外站执行业务写入。

## 失败归因及处理记录

| 问题 | 归因与处理 | 复测或剩余限制 |
| --- | --- | --- |
| Windows 私有目录/文件模式误判 | Identity 客户端缺陷：Windows 不以合成 POSIX 位判断 ACL；Unix 检查保留；凭据文件拒绝符号链接及非普通文件 | 原版失败后，实际候选进入短信验证；不代表任意 Windows ACL 已被审计 |
| 已删除身份遗留未启动注册流程 | 既有 Identity 缺陷纳入修复：仅有可信删除账本且无执行目录时，在锁与 CAS 下归档；保留私有原记录 | 回归覆盖并发、过期版本、已有执行状态、无删除证据、不可用 Provider；没有删除真实身份来制造用例 |
| 注册不确定缺少进一步证据 | 增加固定设备清单的只读检查，每个 controller 最多一次；只返回闭合结果、HTTP 状态及数字 RPC 错误 | 核对成功也不自动完成注册或发布；不修改未知结果 |
| Native 测试绑定缺失 | 本机测试依赖：恢复精确 0.2.6 Windows 绑定并校验 SHA-256，未提交二进制 | 完整插件测试可运行 |
| OpenSSL 不在 PATH | 本机测试环境：仅为 PAP 测试进程补充 Git for Windows OpenSSL 路径 | 本地真实 HTTPS fixture 通过；未修改系统 PATH |
| POSIX 权限断言在 Windows 失败 | 测试可移植性：只限定 POSIX 模式断言的平台，保留持久化与 CAS 检查 | Identity 与 PAP 相关测试通过 |
| Node `--import` 使用盘符路径 | PAP 测试缺陷：改用文件 URL | 跨进程冷却检查通过，签名和网络调用均保持为零 |
| 将 MCP 包直接叠加现有桌面 | 集成方式不兼容：出现重复注册及管理状态读取异常；旧锁文件还保留了可选 peer 包 | 保存失败包树和锁文件后，以干净依赖恢复 Identity；匹配的完整源码 Host 加载 MCP 成功。未认定为 MCP 业务已通过 |
| 旧 0.1.14 候选与 ANP 0.1.4 peer 约束冲突 | 候选版本组合错误，npm 拒绝安装 | 使用实际 0.1.16 基线；未用 force 绕过约束 |
| GitHub 连接器拒绝写入新 fork | 工具权限限制，返回 HTTP 403；Git fetch 也曾网络失败 | 使用本机既有 Git 凭据的 GitHub API 提交 PR；未保存或输出凭据 |
| 设备管理 HTTP 401 | 已确认远端拒绝，最终责任尚待服务端请求日志确认 | 不更改线上配置，不以 Bearer 回退掩盖契约差异；交接见英文诊断记录 |

## 回归证据

- Identity：构建、公共 API 快照、类型检查、生成物检查通过。最终完整测试 **362 通过、19 跳过**，共 40 个文件通过、11 个跳过。一次新增权限测试最初错误地从 root Service proxy 调用管理方法，正确被拒绝；改为真实 manager-bound proxy 后完整重跑通过，原失败日志保留。
- 新增只读检查相关测试最初为 **29 通过**；另有 **79 通过、1 跳过**的注册/界面回归。完整最终结果以上一条为准，不累加为额外覆盖率。
- ANP：源码回归 **14 通过**。
- PAP：`test:p22` 类型检查及 **49 项测试通过**，包括本地 HTTPS 和新 Node 进程冷却验证。
- MCP：domain、once、consent 三文件 **37 项测试通过**；完整源码产物构建 **8 个 gate 全部通过**。
- 匹配的源码 Host 在 Windows 实际启动，真实 Loader 中 Identity/ANP/PAP/MCP 条目处于运行状态，四类工具均已注册；记录了 MCP 模块真实路径和 SHA-256。**未执行业务工具，不能算业务验收成功**。`source-host-loaded.json`
- 原生签名经独立 `@awiki/anp-typescript-sdk@0.9.4` 验证通过，使用临时生成身份，不接触用户私钥，不请求远端。`native-signature-verification.json`

Linux 专属及需外部服务的跳过测试没有被改记为成功。共享 awiki-harness 规则目录在工作区缺失，采用仓库自身说明、测试和当前用户约束。依赖中缺失 sourcemap 的既有警告仍存在，不影响已完成的测试结果。

## 交付与后续

- [Identity 修复及诊断 PR #18](https://github.com/agent-network-protocol/anp-identity/pull/18)：保留草稿，待真实发布及后续协议验收。
- [PAP Windows 测试修复 PR #3](https://github.com/AgentConnect/dsh-pap/pull/3)：只改测试和验证文档。
- 原始失败、候选包、逐文件哈希、脱敏状态及回归日志保存在本地验收目录；PR 不上传身份目录或认证材料。
- 服务端维护者需核对 awiki.info 当前设备管理端点的 HTTP Message Signatures 支持情况，并关联本次注册及随后 401 请求的日志。仅能确认 DID 可读取，不应要求重新注册来猜测结果。
- 服务端结果确认后，仍须通过现有可信管理流程恢复本次注册；不能手工将 journal 改成成功。之后依次验证 CIMD/JWKS、同一身份的三协议读取、隔离服务写入/读回，以及 Matchall 只读流程。

尚无证据支持“所有问题已修复”或“四项业务能力全部通过”。本次代码修复不发布 npm 包，不修改线上服务，不合并 PR。
