window.__ModuleLoader__.load({
	id: "dsh-login-gate",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
		var react = require("react");
		var h = react.createElement;

		var CSS = `.lgc-section{max-width:560px;display:flex;flex-direction:column;gap:2px}
.lgc-section-title{margin:0 0 2px;font-size:18px;font-weight:600;color:var(--dsw-alias-label-primary,#e6e8ec);line-height:1.4}
.lgc-section-desc{margin:0 0 10px;color:var(--dsw-alias-label-tertiary,#9aa3af);font-size:13px;line-height:1.5}
.lgc-field{display:flex;flex-direction:column;gap:7px;padding:12px 0}
.lgc-field+.lgc-field{border-top:1px solid var(--dsw-alias-border-l2,#2c313a)}
.lgc-label{color:var(--dsw-alias-label-primary,#c2c8d0);font-size:13px;font-weight:500;line-height:1.5}
.lgc-row{display:flex;gap:8px}
.lgc-input{border:1px solid var(--dsw-alias-border-l2,#333945);background:var(--dsw-alias-bg-layer-3,#16181d);height:34px;font:inherit;color:var(--dsw-alias-label-primary,#e6e8ec);border-radius:8px;padding:0 12px;font-size:13px;line-height:1.5;box-sizing:border-box}
.lgc-row .lgc-input{flex:1;min-width:0}
.lgc-input:focus-visible{border-color:var(--dsw-alias-brand-primary,#4f8ef7);outline:none}
.lgc-input::placeholder{color:var(--dsw-alias-label-tertiary,#6b7280)}
.lgc-btn{appearance:none;font:inherit;cursor:pointer;border:1px solid #0000;border-radius:8px;padding:6px 14px;font-size:13px;line-height:1.5;background:#3567f6;color:#fff;align-self:flex-start}
.lgc-btn:hover{background:#2c58dd}
[data-ds-dark-theme] .lgc-btn{background:#000;color:#fff}
[data-ds-dark-theme] .lgc-btn:hover{background:#1f2127}
.lgc-btn-danger{appearance:none;font:inherit;cursor:pointer;border:1px solid #5c2b33;border-radius:8px;padding:6px 14px;font-size:13px;line-height:1.5;background:#3a1d22;color:#ff9aa4;align-self:flex-start}
.lgc-btn-danger:hover{background:#4a2228}
.lgc-btn-ghost{appearance:none;font:inherit;cursor:pointer;border:1px solid var(--dsw-alias-border-l2,#333945);border-radius:8px;padding:6px 14px;font-size:13px;line-height:1.5;background:transparent;color:var(--dsw-alias-label-secondary,#c2c8d0);align-self:flex-start}
.lgc-btn-ghost:hover{border-color:var(--dsw-alias-brand-primary,#4f8ef7);color:var(--dsw-alias-label-primary,#e6e8ec)}
.lgc-hint{color:var(--dsw-alias-label-tertiary,#6b7280);margin:0;font-size:12px;line-height:1.5}
.lgc-msg{margin:4px 0 0;font-size:12px;line-height:1.5}
.lgc-msg-ok{color:#7bd88f}
.lgc-msg-err{color:#ff9aa4}`;
		if (typeof document !== "undefined" && document.querySelector('style[data-plugin="dsh-login-gate"]') === null) {
			var tag = document.createElement("style");
			tag.setAttribute("data-plugin", "dsh-login-gate");
			tag.textContent = CSS;
			document.head.appendChild(tag);
		}

		var NS = "login-gate";
		var inject = ["slots", "connection", "remote", "settingsScope"];

		function postJson(path, fields) {
			return fetch(path, {
				method: "POST",
				credentials: "same-origin",
				headers: { "content-type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams(fields || {}).toString()
			}).then(function (res) {
				return res.json().catch(function () {
					return { ok: false, error: "HTTP " + res.status };
				});
			});
		}

		/**
		 * Top-level Settings section for the login gate (a sidebar peer of
		 * General / Models / Plugins / Agent presets). Owns the session TTL,
		 * password change/reset, and logout — all backed by the host's
		 * `login-gate` settings namespace and its auth-gated routes.
		 */
		function LoginGateSection(props) {
			var scope = props.scope;
			var snapState = react.useState(function () { return scope.getSnapshot(); });
			var snap = snapState[0];
			var setSnap = snapState[1];
			react.useEffect(function () {
				return scope.subscribe(function () { setSnap(scope.getSnapshot()); });
			}, [scope]);

			var msgState = react.useState(null);
			var msg = msgState[0];
			var setMsg = msgState[1];

			var ready = snap.status === "ready";
			var ttlValue = ready && snap.value ? snap.value.ttlHours : void 0;

			var ttlState = react.useState(typeof ttlValue === "number" ? String(ttlValue) : "");
			var ttl = ttlState[0];
			var setTtl = ttlState[1];
			react.useEffect(function () {
				setTtl(typeof ttlValue === "number" ? String(ttlValue) : "");
			}, [ttlValue]);

			var oldState = react.useState("");
			var newState = react.useState("");
			var confirmState = react.useState("");

			function saveTtl() {
				var n = Number(String(ttl).trim());
				if (!Number.isFinite(n) || n < 1) {
					setMsg({ kind: "err", text: "会话时长必须是 ≥1 的数字。" });
					return;
				}
				setMsg(null);
				scope.set("ttlHours", Math.floor(n)).then(function () {
					setMsg({ kind: "ok", text: "会话时长已保存，即时生效。" });
				}, function () {
					setMsg({ kind: "err", text: "保存失败，请重试。" });
				});
			}

			function doReset() {
				if (!window.confirm("确定要重置访问密码吗？重置后你需要重新设置一个密码，当前会话会退出。")) return;
				setMsg(null);
				postJson("/__auth/reset-password", {}).then(function (r) {
					if (r.ok) setMsg({ kind: "ok", text: "密码已重置。请刷新页面重新设置访问密码。" });
					else setMsg({ kind: "err", text: r.error || "重置失败。" });
				});
			}

			function doChange() {
				var o = oldState[0];
				var n = newState[0];
				var c = confirmState[0];
				if (n !== c) {
					setMsg({ kind: "err", text: "两次输入的新密码不一致。" });
					return;
				}
				if (n.length < 8) {
					setMsg({ kind: "err", text: "新密码至少 8 位。" });
					return;
				}
				setMsg(null);
				postJson("/__auth/change-password", { oldPassword: o, newPassword: n, confirm: c }).then(function (r) {
					if (r.ok) {
						setMsg({ kind: "ok", text: "密码已修改，其他会话已失效。" });
						oldState[1]("");
						newState[1]("");
						confirmState[1]("");
					} else {
						setMsg({ kind: "err", text: r.error || "修改失败。" });
					}
				});
			}

			return h("div", { className: "lgc-section" },
				h("h2", { className: "lgc-section-title" }, "登录门禁"),
				h("p", { className: "lgc-section-desc" }, "访问密码与会话时长"),
				!ready ? h("p", { className: "lgc-hint" }, "正在读取设置…") : null,
				ready ? h("div", { className: "lgc-field" },
					h("label", { className: "lgc-label" }, "会话时长（小时）"),
					h("div", { className: "lgc-row" },
						h("input", { className: "lgc-input", type: "number", min: 1, value: ttl, onChange: function (e) { setTtl(e.target.value); } }),
						h("button", { type: "button", className: "lgc-btn", onClick: saveTtl }, "保存")
					),
					h("p", { className: "lgc-hint" }, "登录会话的有效时长，改动即时生效。")
				) : null,
				ready ? h("div", { className: "lgc-field" },
					h("label", { className: "lgc-label" }, "修改密码"),
					h("input", { className: "lgc-input", type: "password", autoComplete: "current-password", placeholder: "当前密码", value: oldState[0], onChange: function (e) { oldState[1](e.target.value); } }),
					h("input", { className: "lgc-input", type: "password", autoComplete: "new-password", placeholder: "新密码（至少 8 位）", value: newState[0], onChange: function (e) { newState[1](e.target.value); } }),
					h("input", { className: "lgc-input", type: "password", autoComplete: "new-password", placeholder: "确认新密码", value: confirmState[0], onChange: function (e) { confirmState[1](e.target.value); } }),
					h("button", { type: "button", className: "lgc-btn", onClick: doChange }, "修改密码"),
					h("p", { className: "lgc-hint" }, "修改后其它已登录会话会立即失效。")
				) : null,
				ready ? h("div", { className: "lgc-field" },
					h("label", { className: "lgc-label" }, "重置密码"),
					h("button", { type: "button", className: "lgc-btn-danger", onClick: doReset }, "重置密码"),
					h("p", { className: "lgc-hint" }, "删除已保存的密码，下次访问重新进入首次设置。")
				) : null,
				ready ? h("div", { className: "lgc-field" },
					h("label", { className: "lgc-label" }, "退出登录"),
					h("button", { type: "button", className: "lgc-btn-ghost", onClick: function () { window.location.assign("/__auth/logout"); } }, "退出登录"),
					h("p", { className: "lgc-hint" }, "结束当前会话，返回登录页。")
				) : null,
				msg ? h("p", { className: "lgc-msg " + (msg.kind === "ok" ? "lgc-msg-ok" : "lgc-msg-err") }, msg.text) : null
			);
		}

		function apply(ctx) {
			var scope = ctx.settingsScope.bind({ namespace: NS });
			ctx.slots.inject("settings.section", function () {
				return ctx.slots.register({
					name: "settings.section",
					id: "login-gate",
					order: 30,
					label: function () { return "登录门禁"; },
					inject: function () { return { scope: scope }; }
				}, LoginGateSection);
			});
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
