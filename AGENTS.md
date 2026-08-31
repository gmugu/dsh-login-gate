# AGENTS.md — AI 代码代理约定

本仓库主要由 AI 代理协作开发（vibe-coding）。任何代理在本目录工作前，先读完本文件。

## Git 提交约定（用户要求，必须遵守）

- **不要自动 `git commit`。** 任何改动一律留在工作区。
- 只有用户测试验证（改动需重启 dsh web 生效）并明确确认"可以提交"之后，才执行 commit。
- 用户未确认前，宁可保持脏工作区，也不提交。
- 提交信息与现有历史风格一致：英文祈使句主题行 + 可选正文。

## 项目要点

- 无构建步骤：`lib/index.js`（host 半）与 `lib/client.js`（client 半）就是运行时代码，直接被 DSH 加载。
- 验证手段：`node --check lib/*.js`；host 半可 `node -e 'await import("./lib/index.js")'` 冒烟（无副作用）；最终以用户在浏览器中的实测为准。
- 开发工作流、架构说明、打包与发布流程见 `CONTRIBUTING.md`；面向使用者的文档是 `README.md`。
- 改动 `lib/` 代码后，发布前必须 bump `package.json` 的 `version`。

## 公开仓库卫生

本仓库发布在 GitHub（https://github.com/gmugu/dsh-login-gate）：

- 不得提交：密钥/凭据/令牌、`$DSH_HOME` 下的私人文档、tarball 产物（`.gitignore` 已覆盖）。
- `README.md` 会随 `npm pack` 进入发布包：**勿写入本机绝对路径或私有部署细节**（此类内容放 `CONTRIBUTING.md`）。
- 上游凭据文件 `$DSH_HOME/storages/login-gate.json` 含密码哈希与签名 secret，绝不允许进入仓库。
