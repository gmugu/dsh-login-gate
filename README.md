# dsh-login-gate

DeepSeek Harness（DSH）Web GUI 的登录门禁插件——给整个 Web 界面加一道密码登录墙。

DSH 自带的 webserver 不提供任何鉴权：只要端口可达，任何人都能打开你的 Web GUI。
本插件在组合层把**全部 HTTP 路由、SPA fallback 和 WebSocket upgrade** 包上一层会话校验：
未登录的页面访问跳转登录页，API 请求返回 401；插件停用时完整还原，无残留。

## 特性

- HMAC-SHA256 签名的过期时间戳会话（HttpOnly、SameSite=Strict Cookie）
- 异步 scrypt 密码哈希（新密码 N=2^16，旧低成本哈希登录成功后自动升级），不阻塞事件循环
- 按 IP 的登录失败限速（15 分钟窗口内 5 次失败封禁 15 分钟）
- 首次访问进入「设置访问密码」首次运行流程——密码在浏览器侧设置，本机只存哈希
- 「登录门禁」设置卡片：会话时长（在线改，即时生效）、修改/重置密码、退出登录
- 会话时长（`ttlHours`）与反代开关（`trustProxy`）为 volatile 配置字段：卡片与侧栏「插件」面板 → dsh-login-gate → login-gate 的配置表单是同一份数据的两个入口，均持久化到 profile、无需重启
- 修改密码自动轮换签名 secret，其他已登录会话立即失效
- 局域网设置页修复（`trustLanSettings`）：非 localhost 访问时「模型 / 通用设置 / 插件配置」默认照常可用，见[局域网访问](#局域网访问)

> 版本要求：v1.6.x 适配 dsh **0.1.7** 起（settings 服务重构为 Config 表单投影）；dsh 0.1.5 请用 v1.5.x。

## 安装

一条命令（插件以 bundle 形式**自带接线**，`dsh` 会自动把它列入 profile 组合层，无需手动改任何配置）：

```sh
dsh plugin --profile web add github:gmugu/dsh-login-gate
```

重启 `dsh web`，首次访问设置访问密码（至少 8 位）。

离线/内网机器用 tarball 同理：

```sh
dsh plugin --profile web add /path/to/dsh-login-gate-x.y.z.tgz
```

<details>
<summary>原理（点开）</summary>

本包根目录带 `cordis.patch.yml` 并在 `package.json` 声明 `dsh.bundle.patch`。
`dsh plugin add`（内部即 pnpm add）完成后，dsh 会把声明了 `dsh.bundle` 的依赖自动
追加进 profile 的 `dsh.profile.bundles` 层列表；loader 组合时应用包内 patch，
把 `- { id: login-gate, name: dsh-login-gate }` 插入组合——接线随包自带。

</details>

> **从旧版（手动接线）升级的用户**：若你的 profile `cordis.patch.yml` 里曾手动添加过
> `- id: login-gate` 的 insert 条目，请删除它，避免与包内接线重复挂载。
> 装了 [dsh-market](https://github.com/dsh-market/dsh-market) 插件市场的机器，待本插件
> 上架精选目录后也可在 设置 → 插件市场 一键安装。

## 卸载

```sh
dsh plugin --profile web remove dsh-login-gate
```

重启 `dsh web`。与安装同理，dsh 会自动把它从 profile 组合层移除，无需手动清理接线。

- **旧版手动接线用户**：请同时删除 profile `cordis.patch.yml` 里手动的 `- id: login-gate` insert 条目，否则 loader 找不到已卸载的包。
- **残留数据**（重装时想沿用原密码就保留）：
  - 凭据文件 `$DSH_HOME/storages/login-gate.json`（密码哈希 + 签名 secret）
  - profile 配置里 `login-gate` 条目的 `config`（会话时长等；dsh 0.1.5 及更早存于 `$DSH_HOME/settings.yaml` 的段会在 0.1.7 首次启动时自动迁入 profile）

  需要彻底清理时手动删除即可。
- ⚠️ 卸载后 Web GUI 恢复为**无鉴权**状态——端口可达即等于可访问，请确认网络环境可接受。

## 首次运行与密码找回

- **首次访问**：出现「设置访问密码」页；仅 scrypt 哈希落盘于
  `$DSH_HOME/storages/login-gate.json`（权限 `0600`）。
- **忘记密码**：停止 dsh，删除该凭据文件后重启，即回到首次设置流程。
- **日常管理**：登录后打开 设置 → 登录门禁。

## 局域网访问

从局域网地址（如 `http://192.168.2.128:3080`）访问时，dsh 默认把所有非
localhost 页面视为不可信，浏览器端拒绝加载宿主设置文档——「设置 → 模型」报
`加载提供商目录失败：settings are unavailable in this browser`，通用设置与
插件配置表单同样不可用。这是 dsh 客户端的设计行为，与网络或登录门无关。

本插件默认修复它：向首页注入 `__DSH_TRANSPORT__.ownsHost = true`（dsh 桌面端
使用的同一信任通道），理由是能打开这个页面的访问者都已通过密码认证。插件的
配置表单开关 `trustLanSettings` 可关闭该行为（改动在插件重挂载后、下次加载
页面时生效）。

两点边界：

- **用域名/主机名访问**（而非 IP 字面量）时，dsh 的 Host/Origin 403 信任栅栏
  仍然生效，`/api` 请求会被拒；需按 dsh 文档用 `--trusted-host` 声明该域名。
  本插件不放宽这道栅栏。
- **经反向代理访问**建议同时开启 `trustProxy: true`，登录限速才能按真实来源
  IP（`X-Forwarded-For`）而非代理地址计算。

## 配置参考

`cordis.patch.yml` 插入项可传 `config:`（全部可选）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `ttlHours` | 12 | 会话时长（小时）；volatile 字段，装好后可在「登录门禁」卡片或插件配置表单在线改 |
| `cookieName` | `__dsh_gate` | 会话 Cookie 名 |
| `credentialsFile` | `$DSH_HOME/storages/login-gate.json` | 凭据文件路径 |
| `resetPassword` | `false` | 启动即清除已存密码，回到首次设置 |
| `trustProxy` | `false` | 位于反向代理后时置 `true`，按 `X-Forwarded-For` 取客户端 IP；volatile，可在线改 |
| `disableBrowserTokenAuth` | `true` | 中和 dsh 内建浏览器令牌鉴权（/api 的 401 与首页令牌交换）；登录门已覆盖身份职责，Host/Origin 信任栅栏（403）始终保留 |
| `trustLanSettings` | `true` | 信任本门禁保护下的非 localhost 页面，向首页注入 dsh 桌面端同款信任标记（`__DSH_TRANSPORT__.ownsHost`），使「模型 / 通用设置 / 插件配置」在局域网地址下照常工作；置 `false` 恢复 dsh 原行为 |

示例：

```yaml
- insert:
    - id: login-gate
      name: dsh-login-gate
      config:
        ttlHours: 24
        trustProxy: true
```

## 安全设计

- 密码只以 scrypt 哈希存储（随机 salt、异步计算、内存上限 128 MiB），明文永不落盘
- 会话令牌为 HMAC-SHA256 签名的过期时间戳，比较使用 `timingSafeEqual`
- 登录失败统一延迟响应并按来源 IP 限速
- `/__auth/reset-password`、`/__auth/change-password` 均需有效会话才能调用
- 门禁对宿主 webserver 的注册方法打补丁实现全量包网，teardown 时逐项还原
- 局域网设置页修复只放宽浏览器端的页面信任判定，不触碰 dsh 的 Host/Origin 403 栅栏；设置文档仅对已通过密码认证的页面开放

## 开发

- 架构说明与开发流程见 [CONTRIBUTING.md](CONTRIBUTING.md)
- 本仓库主要由 AI 代理协作开发，代理约定见 [AGENTS.md](AGENTS.md)
- 无构建步骤：`lib/` 即运行时代码；快速验证 `node --check lib/*.js`
- 运行时依赖（cordis / schemastery）由 DSH 宿主提供

## 许可

[MIT](LICENSE) © gmugu。基于上游 dsh-login-gate v1.4.5（MIT）二次开发，上游基线见仓库首次提交。
