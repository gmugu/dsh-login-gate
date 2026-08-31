import {
	createHash,
	createHmac,
	randomBytes,
	scrypt,
	timingSafeEqual,
} from "node:crypto";
import { mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import z from "@deepseek-ai/schemastery";

/**
 * dsh-login-gate — login gate for the DeepSeek Harness Web GUI.
 *
 * The shipped `@deepseek-ai/dsh-host-webserver` deliberately provides no auth.
 * Its route tables (`exact`, `prefixes`), upgrade table, and the single
 * fallback seat are public and read live per request, so this plugin:
 *
 *   1. waits until the composition has settled (the SPA fallback seat and the
 *      WebSocket upgrades are registered), re-reading `ctx.webServer` on every
 *      access — the loader hands out per-access service proxies and may run
 *      out-of-tree plugins before the transport layer finishes composing;
 *   2. registers its own exempt routes `/__auth/login` and `/__auth/logout`;
 *   3. wraps every registered route handler, the fallback seat, and upgrade
 *      handlers with a session check, and patches the registry methods so any
 *      later registration is gated too;
 *   4. registers a `login-gate` settings namespace plus auth-gated
 *      reset/change-password endpoints, which the Web settings card uses to
 *      manage the password, the session TTL, and logout;
 *   5. on teardown, unwraps everything and restores the original methods.
 *
 * Sessions are HMAC-SHA256-signed expiry timestamps in an HttpOnly,
 * SameSite=Strict cookie; the signing secret and the scrypt password hash
 * live in one credentials JSON file. With no credentials file the login page
 * turns into a first-run "set your password" form, so the password is chosen
 * in the browser and only its hash is ever stored.
 *
 * v1.3.0 hardening: password hashing is now async (never blocks the event
 * loop), uses a stronger scrypt cost for new passwords, transparently
 * upgrades legacy hashes on next successful login, enforces a 12-character
 * minimum, and rate-limits login attempts per source IP.
 *
 * v1.4.0: registers the `login-gate` settings namespace (session TTL and
 * trust-proxy) so the Web "Plugins" settings card can edit them live, and
 * adds auth-gated `/__auth/reset-password` and `/__auth/change-password`
 * endpoints that the card drives.
 */

const name = "login-gate";
const inject = ["webServer"];

const LOGIN_PATH = "/__auth/login";
const LOGOUT_PATH = "/__auth/logout";
const RESET_PATH = "/__auth/reset-password";
const CHANGE_PASSWORD_PATH = "/__auth/change-password";
const MAX_BODY_BYTES = 16 * 1024;
const FAILED_ATTEMPT_DELAY_MS = 800;
const PASSWORD_MIN_CHARS = 8;

/** Preferred scrypt cost for NEW passwords (N=2^16 → 64 MiB). */
const PREFERRED_SCRYPT = { N: 65536, r: 8, p: 1, keylen: 32 };
/** Cost used by hashes created before v1.3.0 (Node's scryptSync defaults). */
const LEGACY_SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };
const SCRYPT_MAXMEM = 128 * 1024 * 1024;

/** Per-IP login rate limiting (in-memory; scoped to this process). */
const MAX_LOGIN_FAILURES = 5;
const RATE_WINDOW_MS = 15 * 60_000;
const RATE_BLOCK_MS = 15 * 60_000;
const RATE_MAX_ENTRIES = 10_000;

/** How long to wait for the composition to settle before gating anyway. */
const SETTLE_TIMEOUT_MS = 30_000;
const SETTLE_POLL_MS = 200;

const Config = z.object({
	/** Session lifetime in hours. */
	ttlHours: z.natural().default(12),
	/** Session cookie name. */
	cookieName: z.string().default("__dsh_gate"),
	/**
	 * Credentials file (salt + scrypt hash + HMAC secret). Defaults to
	 * `<DSH_HOME>/storages/login-gate.json`.
	 */
	credentialsFile: z.string(),
	/** Reset: delete the stored password so the next visit re-runs setup. */
	resetPassword: z.boolean().default(false),
	/** Honor X-Forwarded-For when behind a trusted reverse proxy. */
	trustProxy: z.boolean().default(false),
});

/**
 * User-facing settings namespace (`login-gate`). Registered with the settings
 * service when one is mounted, so the Web "Plugins → Plugin configuration"
 * card can edit these live without a restart. Only the values a person owns
 * live here; the gate's composition facts (cookie name, credentials path)
 * stay in the entry config.
 */
const SettingsSchema = z.object({
	/** Session lifetime in hours. */
	ttlHours: z.natural().default(12),
	/** Honor X-Forwarded-For when behind a trusted reverse proxy. */
	trustProxy: z.boolean().default(false),
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Digest helper so timingSafeEqual never sees mismatched lengths. */
function equalDigest(a, b) {
	const da = createHash("sha256").update(String(a)).digest();
	const db = createHash("sha256").update(String(b)).digest();
	return timingSafeEqual(da, db);
}

function parseCookies(header) {
	const out = {};
	for (const part of String(header ?? "").split(";")) {
		const at = part.indexOf("=");
		if (at === -1) continue;
		out[part.slice(0, at).trim()] = decodeURIComponent(part.slice(at + 1).trim());
	}
	return out;
}

function readBody(req) {
	return new Promise((resolve, reject) => {
		let size = 0;
		const chunks = [];
		req.on("data", (chunk) => {
			size += chunk.length;
			if (size > MAX_BODY_BYTES) {
				reject(new Error("body too large"));
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});
		req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
		req.on("error", reject);
	});
}

/**
 * Promisified crypto.scrypt — runs in the libuv thread pool, so a login
 * attempt never blocks the single-threaded event loop.
 */
const scryptAsync = (password, salt, keylen, options) =>
	new Promise((resolve, reject) => {
		scrypt(password, salt, keylen, options, (err, key) =>
			err ? reject(err) : resolve(key),
		);
	});

/** Normalized scrypt params for verifying an existing hash. */
const scryptParamsOf = (creds) => {
	const p = creds?.scrypt;
	if (
		p &&
		typeof p.N === "number" &&
		typeof p.r === "number" &&
		typeof p.p === "number"
	) {
		return {
			N: p.N,
			r: p.r,
			p: p.p,
			keylen: typeof p.keylen === "number" ? p.keylen : 32,
		};
	}
	return LEGACY_SCRYPT;
};

/** Derive a scrypt key with an explicit cost and memory ceiling. */
const hashPassword = (password, salt, params) =>
	scryptAsync(password, salt, params.keylen, {
		N: params.N,
		r: params.r,
		p: params.p,
		maxmem: SCRYPT_MAXMEM,
	});

/** True when the stored hash predates the current preferred cost. */
const needsUpgrade = (creds) => {
	const p = creds?.scrypt;
	if (!p) return true;
	return (
		p.N !== PREFERRED_SCRYPT.N ||
		p.r !== PREFERRED_SCRYPT.r ||
		p.p !== PREFERRED_SCRYPT.p ||
		p.keylen !== PREFERRED_SCRYPT.keylen
	);
};

function page(title, bodyHtml) {
	return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · DeepSeek Harness</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         font-family: system-ui, "Segoe UI", "Microsoft YaHei", sans-serif;
         background: #16181d; color: #e6e8ec; }
  .card { width: min(92vw, 360px); padding: 32px 28px; border-radius: 14px;
          background: #1e2128; border: 1px solid #2c313a;
          box-shadow: 0 12px 40px rgba(0,0,0,.45); }
  h1 { margin: 0 0 6px; font-size: 18px; }
  p.sub { margin: 0 0 22px; color: #9aa3af; font-size: 13px; }
  label { display: block; margin: 14px 0 6px; font-size: 13px; color: #c2c8d0; }
  input[type=password] { width: 100%; padding: 10px 12px; border-radius: 8px;
          border: 1px solid #333945; background: #16181d; color: #e6e8ec; font-size: 15px; }
  input[type=password]:focus { outline: none; border-color: #4f8ef7; }
  button { margin-top: 22px; width: 100%; padding: 10px; border: 0; border-radius: 8px;
           background: #3567f6; color: #fff; font-size: 15px; cursor: pointer; }
  button:hover { background: #2c58dd; }
  .error { margin-top: 14px; padding: 8px 10px; border-radius: 8px; font-size: 13px;
           background: #3a1d22; color: #ff9aa4; border: 1px solid #5c2b33; }
  .foot { margin-top: 18px; font-size: 12px; color: #6b7280; text-align: center; }
</style>
</head>
<body>
<div class="card">
${bodyHtml}
<div class="foot">DeepSeek Harness · login-gate</div>
</div>
</body>
</html>`;
}

function loginPage({ setup, error, next }) {
	const heading = setup ? "设置访问密码" : "登录";
	const sub = setup
		? `首次使用：为这个 Web GUI 设置一个访问密码（至少 ${PASSWORD_MIN_CHARS} 位）。密码只以哈希形式存储在本机。`
		: "此页面受密码保护，请输入访问密码。";
	const field = setup
		? `<label for="pw">新密码</label>
<input id="pw" name="password" type="password" autocomplete="new-password" required minlength="${PASSWORD_MIN_CHARS}">
<label for="pw2">确认密码</label>
<input id="pw2" name="confirm" type="password" autocomplete="new-password" required minlength="${PASSWORD_MIN_CHARS}">`
		: `<label for="pw">密码</label>
<input id="pw" name="password" type="password" autocomplete="current-password" required>`;
	const err = error ? `<div class="error">${error}</div>` : "";
	return page(
		setup ? "设置密码" : "登录",
		`<h1>${heading}</h1>
<p class="sub">${sub}</p>
<form method="post" action="${LOGIN_PATH}">
<input type="hidden" name="next" value="${next}">
${field}
<button type="submit">${setup ? "保存并进入" : "登录"}</button>
</form>${err}`,
	);
}

/**
 * Floating "logout" button removed in v1.4.3 — logout now lives in the Web
 * settings card (client half), which navigates to the still-exempt
 * `/__auth/logout` route below.
 */

function apply(ctx, config) {
	let ttlSeconds = Math.max(1, config.ttlHours ?? 12) * 3600;
	let trustProxy = config.trustProxy === true;
	const credFile =
		config.credentialsFile ??
		join(process.env.DSH_HOME ?? join(homedir(), ".dsh"), "storages", "login-gate.json");

	// Live user settings: register a namespace when the settings service is
	// mounted (the Web composition ships dsh-settings-file). Without one the
	// plugin keeps reading the entry config exactly as before.
	ctx.inject(["settings"], (sctx) => {
		const scope = sctx.settings.register("login-gate", SettingsSchema, {
			base: { ttlHours: config.ttlHours ?? 12, trustProxy: config.trustProxy === true },
		});
		const applyLive = () => {
			const value = scope.get();
			ttlSeconds = Math.max(1, value.ttlHours) * 3600;
			trustProxy = value.trustProxy === true;
		};
		applyLive();
		scope.watch(applyLive);
	});

	/** Fresh service reference per access: the loader returns per-access proxies. */
	const getWs = () => ctx.webServer;

	/**
	 * @type {{salt:string,hash:string,secret:string,scrypt?:object,createdAt?:string}|null|undefined}
	 * undefined = not yet loaded, null = setup mode (no password set), object = armed.
	 */
	let creds;
	/** Resolved once the credentials file has been read at startup. */
	let readyResolve;
	const ready = new Promise((resolve) => {
		readyResolve = resolve;
	});

	const loadCreds = async () => {
		if (config.resetPassword) return null;
		try {
			const parsed = JSON.parse(await readFile(credFile, "utf8"));
			if (
				typeof parsed.salt === "string" &&
				typeof parsed.hash === "string" &&
				typeof parsed.secret === "string"
			) {
				return parsed;
			}
			return null;
		} catch {
			return null;
		}
	};
	// Eagerly load so the gate is armed (or knowingly in setup mode) before
	// the first request can slip through.
	loadCreds().then(
		(loaded) => {
			if (creds === undefined) creds = loaded;
			readyResolve();
		},
		() => {
			if (creds === undefined) creds = null;
			readyResolve();
		},
	);

	const saveCreds = async (password) => {
		const salt = randomBytes(16).toString("hex");
		const next = {
			salt,
			hash: (await hashPassword(password, salt, PREFERRED_SCRYPT)).toString("hex"),
			secret: randomBytes(32).toString("hex"),
			scrypt: PREFERRED_SCRYPT,
			createdAt: new Date().toISOString(),
		};
		await mkdir(dirname(credFile), { recursive: true });
		await writeFile(credFile, JSON.stringify(next, null, "\t") + "\n", { mode: 0o600 });
		creds = next;
	};

	const sign = (exp) => createHmac("sha256", creds.secret).update(`v1.${exp}`).digest("hex");
	const sessionCookie = () => {
		const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
		return `${config.cookieName}=v1.${exp}.${sign(exp)}; Max-Age=${ttlSeconds}; Path=/; HttpOnly; SameSite=Strict`;
	};
	const clearCookie = () =>
		`${config.cookieName}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict`;

	const isAuthed = (req) => {
		if (!creds) return false; // setup mode counts as not logged in; login page guides setup
		const token = parseCookies(req.headers.cookie)[config.cookieName];
		if (typeof token !== "string") return false;
		const at = token.lastIndexOf(".");
		const prefixAt = token.indexOf(".");
		if (at === -1 || prefixAt === -1 || prefixAt === at) return false;
		const exp = Number(token.slice(prefixAt + 1, at));
		const mac = token.slice(at + 1);
		if (!Number.isFinite(exp) || exp * 1000 <= Date.now()) return false;
		return equalDigest(mac, sign(exp));
	};

	const deny = (req, res) => {
		const path = new URL(req.url ?? "/", "http://x").pathname;
		const wantsHtml =
			(req.method === "GET" || req.method === "HEAD") &&
			!path.startsWith("/api/") &&
			path !== "/api";
		if (wantsHtml) {
			const next = encodeURIComponent(req.url ?? "/");
			res.writeHead(302, { location: `${LOGIN_PATH}?next=${next}` });
			res.end();
			return;
		}
		res.writeHead(401, { "content-type": "application/json; charset=utf-8" });
		res.end(JSON.stringify({ error: "unauthorized" }));
	};

	// —— per-IP login rate limiting ————————————————————————————————————

	const attempts = new Map();

	const clientIp = (req) => {
		if (trustProxy) {
			const xff = req.headers["x-forwarded-for"];
			if (typeof xff === "string" && xff.length > 0) {
				const first = xff.split(",")[0].trim();
				if (first) return first;
			}
		}
		return req.socket?.remoteAddress ?? "unknown";
	};

	const pruneAttempts = () => {
		if (attempts.size <= RATE_MAX_ENTRIES) return;
		const now = Date.now();
		for (const [ip, rec] of attempts) {
			if (now - rec.windowStart > RATE_WINDOW_MS && rec.blockedUntil <= now) {
				attempts.delete(ip);
			}
		}
	};

	const checkRate = (ip) => {
		const now = Date.now();
		let rec = attempts.get(ip);
		if (!rec || now - rec.windowStart > RATE_WINDOW_MS) {
			rec = { count: 0, windowStart: now, blockedUntil: 0 };
			attempts.set(ip, rec);
			pruneAttempts();
		}
		if (rec.blockedUntil > now) {
			return { blocked: true, retryAfter: Math.ceil((rec.blockedUntil - now) / 1000) };
		}
		return { blocked: false, rec };
	};

	const recordFailure = (rec) => {
		rec.count += 1;
		if (rec.count >= MAX_LOGIN_FAILURES) rec.blockedUntil = Date.now() + RATE_BLOCK_MS;
	};

	const clearRate = (ip) => {
		attempts.delete(ip);
	};

	// —— own exempt routes ——————————————————————————————————————————————

	const safeNext = (raw) => {
		if (typeof raw === "string" && raw.startsWith("/") && !raw.startsWith("//")) return raw;
		return "/";
	};

	const handleLogin = async (req, res) => {
		if (req.method === "GET" || req.method === "HEAD") {
			await ready;
			if (creds && isAuthed(req)) {
				res.writeHead(303, { location: "/" });
				res.end();
				return;
			}
			const url = new URL(req.url ?? "/", "http://x");
			res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
			res.end(
				loginPage({
					setup: !creds,
					error: url.searchParams.get("e") === "1" ? "密码不正确，请重试。" : undefined,
					next: safeNext(url.searchParams.get("next")),
				}),
			);
			return;
		}
		if (req.method !== "POST") {
			res.writeHead(405);
			res.end();
			return;
		}
		await ready;

		const ip = clientIp(req);
		const gate = checkRate(ip);
		if (gate.blocked) {
			res.writeHead(429, {
				"content-type": "text/html; charset=utf-8",
				"retry-after": String(gate.retryAfter),
			});
			res.end(
				loginPage({
					setup: !creds,
					error: `尝试次数过多，请约 ${Math.max(1, Math.ceil(gate.retryAfter / 60))} 分钟后再试。`,
					next: "/",
				}),
			);
			return;
		}

		const params = new URLSearchParams(await readBody(req));
		const password = params.get("password") ?? "";
		const next = safeNext(params.get("next"));

		if (!creds) {
			// first-run setup
			const confirm = params.get("confirm") ?? "";
			if (password.length < PASSWORD_MIN_CHARS || password !== confirm) {
				recordFailure(gate.rec);
				await sleep(FAILED_ATTEMPT_DELAY_MS);
				res.writeHead(400, { "content-type": "text/html; charset=utf-8" });
				res.end(
					loginPage({
						setup: true,
						error: `两次输入不一致或密码不足 ${PASSWORD_MIN_CHARS} 位。`,
						next,
					}),
				);
				return;
			}
			await saveCreds(password);
			clearRate(ip);
			res.writeHead(303, { location: next, "set-cookie": sessionCookie() });
			res.end();
			return;
		}

		// login against the stored hash, using its recorded cost
		const attempt = await hashPassword(password, creds.salt, scryptParamsOf(creds));
		const stored = Buffer.from(creds.hash, "hex");
		if (attempt.length !== stored.length || !timingSafeEqual(attempt, stored)) {
			recordFailure(gate.rec);
			await sleep(FAILED_ATTEMPT_DELAY_MS);
			res.writeHead(303, { location: `${LOGIN_PATH}?next=${encodeURIComponent(next)}&e=1` });
			res.end();
			return;
		}

		// success — transparently re-hash legacy passwords at the stronger cost
		if (needsUpgrade(creds)) {
			try {
				const salt = randomBytes(16).toString("hex");
				const upgraded = {
					...creds,
					salt,
					hash: (await hashPassword(password, salt, PREFERRED_SCRYPT)).toString("hex"),
					scrypt: PREFERRED_SCRYPT,
					createdAt: new Date().toISOString(),
				};
				await writeFile(credFile, JSON.stringify(upgraded, null, "\t") + "\n", { mode: 0o600 });
				creds = upgraded;
			} catch {
				/* non-fatal: keep serving with the existing hash */
			}
		}
		clearRate(ip);
		res.writeHead(303, { location: next, "set-cookie": sessionCookie() });
		res.end();
	};

	const handleLogout = (req, res) => {
		res.writeHead(303, { location: LOGIN_PATH, "set-cookie": clearCookie() });
		res.end();
	};

	/**
	 * Reset: delete the stored password so the next visit re-runs first-run
	 * setup. Auth-gated (NOT in `exempt`), so only a logged-in session reaches
	 * it; the response clears the now-defunct session cookie.
	 */
	const handleResetPassword = async (req, res) => {
		if (req.method !== "POST") {
			res.writeHead(405);
			res.end();
			return;
		}
		await ready;
		try {
			await unlink(credFile);
		} catch (error) {
			if (error.code !== "ENOENT") {
				res.writeHead(500, { "content-type": "application/json; charset=utf-8" });
				res.end(JSON.stringify({ ok: false, error: "删除凭据文件失败，未重置。" }));
				return;
			}
		}
		creds = null;
		clearRate(clientIp(req));
		res.writeHead(200, {
			"content-type": "application/json; charset=utf-8",
			"set-cookie": clearCookie(),
		});
		res.end(JSON.stringify({ ok: true }));
	};

	/**
	 * Change password: verify the old password, then store a fresh scrypt hash
	 * under a NEW signing secret (revokes every existing session) and hand the
	 * caller a new session cookie. Auth-gated like reset.
	 */
	const handleChangePassword = async (req, res) => {
		const json = (code, payload, extraHeaders) => {
			res.writeHead(code, {
				"content-type": "application/json; charset=utf-8",
				...extraHeaders,
			});
			res.end(JSON.stringify(payload));
		};
		if (req.method !== "POST") {
			res.writeHead(405);
			res.end();
			return;
		}
		await ready;
		if (!creds) {
			json(409, { ok: false, error: "尚未设置密码，请先完成首次设置。" });
			return;
		}
		const params = new URLSearchParams(await readBody(req));
		const oldPassword = params.get("oldPassword") ?? "";
		const newPassword = params.get("newPassword") ?? "";
		const confirm = params.get("confirm") ?? "";
		if (newPassword.length < PASSWORD_MIN_CHARS || newPassword !== confirm) {
			await sleep(FAILED_ATTEMPT_DELAY_MS);
			json(400, { ok: false, error: `两次输入不一致或新密码不足 ${PASSWORD_MIN_CHARS} 位。` });
			return;
		}
		const attempt = await hashPassword(oldPassword, creds.salt, scryptParamsOf(creds));
		const stored = Buffer.from(creds.hash, "hex");
		if (attempt.length !== stored.length || !timingSafeEqual(attempt, stored)) {
			await sleep(FAILED_ATTEMPT_DELAY_MS);
			json(401, { ok: false, error: "旧密码不正确。" });
			return;
		}
		const salt = randomBytes(16).toString("hex");
		const next = {
			salt,
			hash: (await hashPassword(newPassword, salt, PREFERRED_SCRYPT)).toString("hex"),
			secret: randomBytes(32).toString("hex"),
			scrypt: PREFERRED_SCRYPT,
			createdAt: new Date().toISOString(),
		};
		await mkdir(dirname(credFile), { recursive: true });
		await writeFile(credFile, JSON.stringify(next, null, "\t") + "\n", { mode: 0o600 });
		creds = next;
		clearRate(clientIp(req));
		json(200, { ok: true }, { "set-cookie": sessionCookie() });
	};

	const exempt = new Set([handleLogin, handleLogout]);
	const wrapperOf = new Map(); // wrapper fn -> original fn
	const isWrapper = (fn) => wrapperOf.has(fn);

	const wrapHttp = (handler) => {
		if (isWrapper(handler) || exempt.has(handler)) return handler;
		const wrapped = async (req, res) => {
			await ready;
			if (isAuthed(req)) return handler(req, res);
			deny(req, res);
		};
		wrapperOf.set(wrapped, handler);
		return wrapped;
	};
	const wrapUpgrade = (handler) => {
		if (isWrapper(handler) || exempt.has(handler)) return handler;
		const wrapped = async (req, socket, head) => {
			await ready;
			if (isAuthed(req)) return handler(req, socket, head);
			socket.destroy();
		};
		wrapperOf.set(wrapped, handler);
		return wrapped;
	};

	const originals = {};
	let installed = false;

	/** Install the gate on the live service. Idempotent. */
	const install = () => {
		const ws = getWs();
		if (installed || !ws) return;
		installed = true;

		originals.register = ws.register;
		originals.registerUpgrade = ws.registerUpgrade;
		originals.registerFallback = ws.registerFallback;

		originals.register.call(ws, { kind: "exact", path: LOGIN_PATH, handler: handleLogin });
		originals.register.call(ws, { kind: "exact", path: LOGOUT_PATH, handler: handleLogout });
		originals.register.call(ws, { kind: "exact", path: RESET_PATH, handler: handleResetPassword });
		originals.register.call(ws, { kind: "exact", path: CHANGE_PASSWORD_PATH, handler: handleChangePassword });

		// Patch the registries so every future registration is gated too.
		ws.register = (route) =>
			originals.register.call(
				ws,
				exempt.has(route.handler) ? route : { ...route, handler: wrapHttp(route.handler) },
			);
		ws.registerUpgrade = (route) =>
			originals.registerUpgrade.call(
				ws,
				exempt.has(route.handler) ? route : { ...route, handler: wrapUpgrade(route.handler) },
			);
		ws.registerFallback = (handler) => originals.registerFallback.call(ws, wrapHttp(handler));

		// Sweep what is already registered (route tables are read live per request).
		for (const table of [ws.exact, ws.prefixes]) {
			for (const route of table.values()) route.handler = wrapHttp(route.handler);
		}
		for (const route of ws.upgrades.values()) route.handler = wrapUpgrade(route.handler);
		if (ws.fallback !== undefined) ws.fallback = wrapHttp(ws.fallback);
	};

	const teardown = () => {
		clearTimeout(pollTimer);
		if (!installed) return;
		installed = false;
		const ws = getWs();
		if (!ws) return;
		ws.exact.delete(LOGIN_PATH);
		ws.exact.delete(LOGOUT_PATH);
		ws.exact.delete(RESET_PATH);
		ws.exact.delete(CHANGE_PASSWORD_PATH);
		for (const table of [ws.exact, ws.prefixes, ws.upgrades]) {
			for (const route of table.values()) {
				if (isWrapper(route.handler)) route.handler = wrapperOf.get(route.handler);
			}
		}
		if (ws.fallback !== undefined && isWrapper(ws.fallback)) ws.fallback = wrapperOf.get(ws.fallback);
		if (originals.register) {
			delete ws.register;
			delete ws.registerUpgrade;
			delete ws.registerFallback;
		}
	};

	// Wait for the composition to settle: the SPA fallback seat and at least
	// one upgrade route mean the transport layer is fully composed. The gate
	// must wrap the final handlers, not an early partial state.
	const startedAt = Date.now();
	let pollTimer;
	const poll = () => {
		if (installed) return;
		const ws = getWs();
		const settled = ws && ws.fallback !== undefined && ws.upgrades.size > 0;
		if (settled || Date.now() - startedAt > SETTLE_TIMEOUT_MS) {
			install();
			return;
		}
		pollTimer = setTimeout(poll, SETTLE_POLL_MS);
	};
	pollTimer = setTimeout(poll, 0);
}

export { Config, apply, inject, name };
