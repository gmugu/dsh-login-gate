# 开发指南（CONTRIBUTING.md）

面向在本仓库改代码的人与 AI 代理。使用者文档见 `README.md`；AI 代理的提交约定见 `AGENTS.md`。

> 下文用 `$DSH_HOME` 表示 DSH 主目录（默认 `~/.dsh`），用 `$REPO` 表示本仓库的绝对路径。

## 仓库结构

```
├── lib/
│   ├── index.js    # Host 半：全部服务端逻辑（纯 ESM JS，无构建步骤）
│   └── client.js   # Client 半：浏览器设置卡片（window.__ModuleLoader__.load 包装）
├── package.json    # dsh 插件清单（exports、dsh.client、files 发布范围、仓库元数据）
├── AGENTS.md       # AI 代理约定（提交规则、公开仓库卫生）
├── CONTRIBUTING.md # 本文件
├── README.md       # 面向使用者的文档（随 npm pack 进包，勿写本机绝对路径）
└── LICENSE         # MIT
```

## 架构要点

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
   `ttlHours`/`trustProxy` 在线生效（持久化在 `$DSH_HOME/settings.yaml`）。
5. **凭据文件**：默认 `$DSH_HOME/storages/login-gate.json`（salt + scrypt 哈希 +
   HMAC secret，`0600`）。删除该文件即回到首次设置流程。

### Client 半（`lib/client.js`）

`window.__ModuleLoader__.load({ id, factory })` 模块格式，`require("react")` 取 React，
注入 `slots`/`connection`/`remote`/`settingsScope`，在 `settings.section` 插槽注册
「登录门禁」设置卡片。样式通过带 `data-plugin="dsh-login-gate"` 属性的 `<style>` 注入。

## 发布新版本（GitHub）

1. bump `package.json` 的 `version`（有代码改动就必须 bump，接收方才能区分版本）；
2. 按约定经用户确认后提交、推送；
3. 打 tag：`git tag vX.Y.Z && git push origin vX.Y.Z`；
4. 打包：`npm pack --cache /tmp/.npm-cache`，产物 `dsh-login-gate-X.Y.Z.tgz`
   （`files` 字段限定只含 `lib`、`README.md`、`LICENSE`）；
5. 在 GitHub Releases 挂上 tarball，接收方按 `README.md` 的 tarball 方式安装。

（后续若发布到 npm 并提交至 awesome-dsh-plugin 精选列表，用户可经 dsh-market 一键安装。）

## 改名分叉（新插件身份）

1. `package.json` 的 `name` 与仓库元数据；
2. `lib/client.js`：`id: "dsh-login-gate"`、`NS`（设置命名空间）、`data-plugin` 样式属性、CSS 前缀；
3. `lib/index.js`：`name`（插件名）、设置命名空间字符串 `"login-gate"`（两处）、路由路径可按需改；
4. profile `cordis.patch.yml` 插入项的 `id`/`name`；
5. 避免与原插件同时启用（两个门禁会互相包对方的路由）。
