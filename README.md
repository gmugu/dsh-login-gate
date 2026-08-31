# dsh-login-gate（二次开发工程）

DeepSeek Harness（DSH）Web GUI 的 Cookie 会话登录门禁插件。

**基线**：`v1.4.5`，自本地插件安装目录 `/vol1/1000/dsh/home/plugins/dsh-login-gate`
原样导入（见 git 首个提交 `3ddc3cf`，与原文件字节一致）。本工程在其之上做二次开发。

## 功能概述

- HMAC-SHA256 签名的过期时间戳会话（HttpOnly、SameSite=Strict Cookie）
- 异步 scrypt 密码哈希（新密码 N=2^16，旧哈希登录成功后自动升级），永不阻塞事件循环
- 按 IP 的登录失败限速（15 分钟窗口，5 次失败封 15 分钟）
- 首次访问无凭据文件时进入「设置访问密码」首次运行流程，浏览器侧选密码、只落盘哈希
- `login-gate` 设置命名空间（会话时长 / trust-proxy），Web 设置卡片可在线改
- 鉴权保护的 `/__auth/reset-password`、`/__auth/change-password` 端点 + 设置卡片 UI

## 目录结构

```
├── lib/
│   ├── index.js    # Host 半：全部服务端逻辑（无构建步骤，纯 ESM JS）
│   └── client.js   # Client 半：浏览器设置卡片（window.__ModuleLoader__.load 包装）
├── package.json    # dsh 插件清单（exports + dsh.client 平台与 inject 声明）
└── README.md
```

没有构建步骤：`lib/` 下的 JS 就是运行时代码，直接被 DSH 加载。

## 架构要点（改代码前先读）

### Host 半（`lib/index.js`）

导出 `name = "login-gate"`、`inject = ["webServer"]`、`Config`、`apply`。

1. **等待组合就绪**：轮询直到 `webServer` 出现 SPA fallback 且至少一条 upgrade 路由
   （超时 30s 后强行安装），确保包装的是最终 handler。
2. **注册豁免路由**：`/__auth/login`、`/__auth/logout`（另有两个 *不* 豁免的
   reset/change 端点，本身受会话保护）。
3. **包网**：包装已注册的全部路由 handler、fallback、upgrade handler，并打补丁
   `register/registerUpgrade/registerFallback`，使后续注册的路由同样被门禁；
   teardown 时全部还原。
4. **设置命名空间**：`settings` 服务挂载时注册 `login-gate` 命名空间，
   `ttlHours`/`trustProxy` 可在线生效（持久化在 `$DSH_HOME/settings.yaml`）。
5. **凭据文件**：默认 `$DSH_HOME/storages/login-gate.json`（salt + scrypt 哈希 +
   HMAC secret，`0o600`）。删除该文件即回到首次设置流程。

### Client 半（`lib/client.js`）

`window.__ModuleLoader__.load({ id, factory })` 模块格式，`require("react")` 取 React，
注入 `slots`/`connection`/`remote`/`settingsScope`，在 `settings.section` 插槽注册
「登录门禁」设置卡片（会话时长、改密、重置、退出登录）。样式通过带
`data-plugin="dsh-login-gate"` 属性的 `<style>` 注入。

## 开发工作流

### 1. 开发依赖（编辑器智能提示用）

`node_modules/` 已从原插件安装目录原样复制（cordis 4.0.1 / schemastery / cosmokit，
与上游 lockfile 一致，不入库），开箱即有智能提示。如需重建：

```sh
npm install --ignore-scripts --cache /tmp/.npm-cache   # 本机默认缓存目录不可写时指定可写缓存
```

`devDependencies` 与运行时 peerDependencies 相同（cordis / schemastery）。
运行时由 DSH 宿主提供这些包，`node_modules/` 不参与运行、不入库。

### 2. 改代码

直接编辑 `lib/index.js` / `lib/client.js`。快速语法检查：

```sh
node --check lib/index.js
node --check lib/client.js
# Host 半加载冒烟（不调用 apply，无副作用）：
node -e 'await import("./lib/index.js").then(m => console.log(Object.keys(m)))'
```

### 3. 让运行中的 DSH 用上改动（改完需重启，二选一）

**方式 A（推荐）：把 profile 的 link 指向本工程**

编辑 `/vol1/1000/dsh/home/profiles/web/package.json`：

```json
"dsh-login-gate": "link:/vol1/1000/dsh/projects/dsh-login-gate"
```

然后重装并重启：

```sh
dsh plugin --profile web install   # 等价于在 profile 目录跑 pnpm install
# 按你的部署方式重启 dsh web
```

此后本工程的每次改动 `git commit` 后重启即生效，原 `/vol1/1000/dsh/home/plugins/dsh-login-gate`
目录保持原样，可随时回退 link。

**方式 B：同步到原安装目录（保持 profile 不动）**

```sh
rsync -a --delete --exclude node_modules --exclude .git --exclude README.md \
  /vol1/1000/dsh/projects/dsh-login-gate/ \
  /vol1/1000/dsh/home/plugins/dsh-login-gate/
# 重启 dsh web
```

### 4. 本地测试注意

- 开发期想重走首次设置流程：删除 `$DSH_HOME/storages/login-gate.json`
  （或在插入项传 `config.resetPassword: true`）。
- 现网 `settings.yaml` 中已有 `login-gate.ttlHours: 720`，会覆盖 Config 默认值。
- **本 GUI 本身就在这个插件保护之下**：改坏 host 半且已启用方式 A/B 同步时，
  重启后可能锁在门外——兜底是删除/改名凭据文件回到首次设置，或从 profile 的
  `cordis.patch.yml` 暂时移除 `- id: login-gate` 插入项再重启。

## 入口配置（cordis.patch.yml 插入项）

当前 web profile 仅 `insert { id: login-gate, name: dsh-login-gate }`，全走默认：

| 字段 | 默认 | 说明 |
|---|---|---|
| `ttlHours` | 12 | 会话时长（小时），被设置命名空间在线值覆盖 |
| `cookieName` | `__dsh_gate` | 会话 Cookie 名 |
| `credentialsFile` | `$DSH_HOME/storages/login-gate.json` | 凭据文件路径 |
| `resetPassword` | `false` | 启动即删除已存密码，回到首次设置 |
| `trustProxy` | `false` | 信任 `X-Forwarded-For`（反代后开启） |

## 若要改名分叉（新插件身份）

1. `package.json` 的 `name`；
2. `lib/client.js`：`id: "dsh-login-gate"`、`NS`（设置命名空间）、`data-plugin` 样式属性、CSS 前缀；
3. `lib/index.js`：`name`（插件名）、设置命名空间字符串 `"login-gate"`（两处）、路由路径可按需改；
4. profile `cordis.patch.yml` 的插入项 `id`/`name`；
5. 避免与原插件同时启用（两个门禁会互相包对方的路由）。

