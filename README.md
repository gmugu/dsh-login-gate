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
- 「登录门禁」设置卡片：会话时长、修改/重置密码、退出登录，改动在线生效
- 修改密码自动轮换签名 secret，其他已登录会话立即失效

## 安装

背景：DSH 把「安装」分成两件事——**装依赖**（pnpm 管）与**接进组合**（`cordis.patch.yml` 管）。
两种方式装完依赖后都需手动接线（就两行），见「通用收尾」。

### 方式一：从本仓库安装（git 依赖）

```sh
dsh plugin --profile web add github:gmugu/dsh-login-gate
```

### 方式二：tarball（离线/内网）

从 [Releases](https://github.com/gmugu/dsh-login-gate/releases) 下载 tarball 后安装：

```sh
dsh plugin --profile web add /path/to/dsh-login-gate-x.y.z.tgz
```

### 通用收尾（两种方式都需要）

编辑 `$DSH_HOME/profiles/web/cordis.patch.yml`（`$DSH_HOME` 默认 `~/.dsh`；若已存在
`insert:` 列表则把两行并入其中）：

```yaml
- insert:
    - id: login-gate
      name: dsh-login-gate
```

重启 `dsh web`，首次访问设置访问密码（至少 8 位）。

> 装了 [dsh-market](https://github.com/dsh-market/dsh-market) 插件市场的机器，待本插件
> 上架精选目录后可在 设置 → 插件市场 一键安装（依赖+接线全自动）。

## 首次运行与密码找回

- **首次访问**：出现「设置访问密码」页；仅 scrypt 哈希落盘于
  `$DSH_HOME/storages/login-gate.json`（权限 `0600`）。
- **忘记密码**：停止 dsh，删除该凭据文件后重启，即回到首次设置流程。
- **日常管理**：登录后打开 设置 → 登录门禁。

## 配置参考

`cordis.patch.yml` 插入项可传 `config:`（全部可选）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `ttlHours` | 12 | 会话时长（小时）；设置卡片里的在线值会覆盖它 |
| `cookieName` | `__dsh_gate` | 会话 Cookie 名 |
| `credentialsFile` | `$DSH_HOME/storages/login-gate.json` | 凭据文件路径 |
| `resetPassword` | `false` | 启动即清除已存密码，回到首次设置 |
| `trustProxy` | `false` | 位于反向代理后时置 `true`，按 `X-Forwarded-For` 取客户端 IP |

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

## 开发

- 架构说明与开发流程见 [CONTRIBUTING.md](CONTRIBUTING.md)
- 本仓库主要由 AI 代理协作开发，代理约定见 [AGENTS.md](AGENTS.md)
- 无构建步骤：`lib/` 即运行时代码；快速验证 `node --check lib/*.js`
- 运行时依赖（cordis / schemastery）由 DSH 宿主提供

## 许可

[MIT](LICENSE) © gmugu。基于上游 dsh-login-gate v1.4.5（MIT）二次开发，上游基线见仓库首次提交。
