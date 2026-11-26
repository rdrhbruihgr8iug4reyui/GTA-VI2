/* GTA VI 查询站 · Vercel 后端（Node）
 * 覆盖原 server.py 的全部接口：验证码、注册、登录、重置、资料、收藏同步、BUG 反馈。
 * 数据库用 Neon Postgres（DATABASE_URL），发信用 163 SMTP（SMTP_* 环境变量）。
 */
const crypto = require("crypto");
const { Pool } = require("pg");
const nodemailer = require("nodemailer");

const DB_URL = (process.env.DATABASE_URL || "").trim();
const BUG_TO = (process.env.BUG_TO || process.env.SMTP_TO || "").trim() || "2335774797@qq.com";
const ADMIN_PW = (process.env.ADMIN_PASSWORD || "gta6-ec43bb").trim();
const REGISTER_OPEN = String(process.env.AUTH_REGISTER_OPEN || "1").toLowerCase() !== "0";
const CODE_TTL = parseInt(process.env.CODE_TTL || "300", 10);
const CODE_GAP = parseInt(process.env.CODE_GAP || "60", 10);

const USERNAME_RE = /^[\u4e00-\u9fa5A-Za-z0-9_]{2,16}$/;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/;
const PAGES = { home: "首页", map: "地图", eggs: "彩蛋", chars: "角色", news: "资讯", me: "个人中心" };
const RESERVED = new Set(["admin", "root", "system", "rockstar", "gta6", "gta", "staff", "moderator", "官方", "站长"]);

let pool = null;
function db() {
  if (!DB_URL) throw new Error("缺少 DATABASE_URL");
  if (!pool) {
    pool = new Pool({
      connectionString: DB_URL,
      ssl: { rejectUnauthorized: false },
      max: 3,
      connectionTimeoutMillis: 10000,
      idleTimeoutMillis: 20000,
    });
  }
  return pool;
}

let schemaReady = null;
function ensureSchema() {
  if (!schemaReady) {
    schemaReady = (async () => {
      const p = db();
      await p.query(`CREATE TABLE IF NOT EXISTS users(
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        pass_hash TEXT NOT NULL,
        pass_salt TEXT NOT NULL,
        bio TEXT NOT NULL DEFAULT '',
        avatar TEXT NOT NULL DEFAULT '',
        banner TEXT NOT NULL DEFAULT '',
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL,
        last_login TEXT NOT NULL
      )`);
      await p.query(`CREATE TABLE IF NOT EXISTS sessions(
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        ua TEXT, ip TEXT
      )`);
      await p.query(`CREATE TABLE IF NOT EXISTS codes(
        email TEXT NOT NULL,
        purpose TEXT NOT NULL,
        code TEXT NOT NULL,
        exp DOUBLE PRECISION NOT NULL,
        tries INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        PRIMARY KEY(email, purpose)
      )`);
      await p.query(`CREATE TABLE IF NOT EXISTS profiles(
        user_id INTEGER PRIMARY KEY,
        data TEXT NOT NULL DEFAULT '{}',
        updated_at TEXT
      )`);
      await p.query(`CREATE TABLE IF NOT EXISTS bugs(
        id SERIAL PRIMARY KEY,
        created_at TEXT NOT NULL,
        page_key TEXT, page TEXT,
        device TEXT, "desc" TEXT,
        ip TEXT, ua TEXT, referer TEXT,
        mail_status TEXT
      )`);
      await p.query(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`);
    })().catch((e) => { schemaReady = null; throw e; });
  }
  return schemaReady;
}

/* ---------------- 工具 ---------------- */
function nowStr() {
  const d = new Date(Date.now() + 8 * 3600 * 1000);
  return d.toISOString().replace("T", " ").slice(0, 19);
}
function clean(v, limit) {
  if (typeof v !== "string") return "";
  return v.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "").trim().slice(0, limit);
}
function send(res, status, body, extra) {
  const headers = Object.assign({
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Cache-Control": "no-store",
  }, extra || {});
  res.writeHead(status, headers);
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}
const ok = (res, obj, status) => send(res, status || 200, Object.assign({ ok: true }, obj || {}));
const fail = (res, status, error) => send(res, status, { ok: false, error });

async function readJson(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") { try { return JSON.parse(req.body); } catch (e) { return null; } }
  return new Promise((resolve) => {
    let raw = "";
    let done = false;
    req.on("data", (c) => {
      raw += c;
      if (raw.length > 128 * 1024) { done = true; resolve(null); req.destroy(); }
    });
    req.on("end", () => { if (!done) { try { resolve(JSON.parse(raw || "{}")); } catch (e) { resolve(null); } } });
    req.on("error", () => resolve(null));
  });
}

function ipOf(req) {
  const xf = (req.headers["x-forwarded-for"] || "").split(",")[0].trim();
  return xf || req.socket && req.socket.remoteAddress || "unknown";
}

/* 极简内存限流（单个实例内有效，够挡脚本） */
const rl = new Map();
function rateOk(key, gap, limit, window) {
  const now = Date.now();
  const arr = (rl.get(key) || []).filter((t) => t > now - window * 1000);
  if (gap && arr.length && now - arr[arr.length - 1] < gap * 1000) { rl.set(key, arr); return false; }
  if (limit && arr.length >= limit) { rl.set(key, arr); return false; }
  arr.push(now);
  rl.set(key, arr);
  return true;
}

/* ---------------- 密码 / 会话 ---------------- */
function hashPassword(password, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, "hex") : crypto.randomBytes(16);
  const dk = crypto.pbkdf2Sync(password, salt, 120000, 32, "sha256");
  return { hash: dk.toString("hex"), salt: salt.toString("hex") };
}
function verifyPassword(password, saltHex, wantHex) {
  try {
    const dk = crypto.pbkdf2Sync(password, Buffer.from(saltHex, "hex"), 120000, 32, "sha256");
    return crypto.timingSafeEqual(Buffer.from(dk.toString("hex")), Buffer.from(wantHex));
  } catch (e) { return false; }
}
async function makeSession(userId, ua, ip) {
  const token = crypto.randomBytes(32).toString("base64url");
  await db().query("INSERT INTO sessions(token_hash,user_id,created_at,ua,ip) VALUES($1,$2,$3,$4,$5)",
    [crypto.createHash("sha256").update(token).digest("hex"), userId, nowStr(), clean(ua, 300), ip]);
  return token;
}
async function userByToken(token) {
  if (!token) return null;
  const r = await db().query("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1",
    [crypto.createHash("sha256").update(token).digest("hex")]);
  return r.rows[0] || null;
}
async function readProfile(userId) {
  const r = await db().query("SELECT data FROM profiles WHERE user_id=$1", [userId]);
  if (!r.rows.length) return {};
  try { return JSON.parse(r.rows[0].data || "{}"); } catch (e) { return {}; }
}
function profileStats(data) {
  try {
    const favs = data.favs || {};
    const prog = data.eggProgress || {};
    return {
      favNews: (favs.news || []).length,
      favEggs: (favs.eggs || []).length,
      eggDone: Object.values(prog).filter(Boolean).length,
      history: (data.history || []).length,
    };
  } catch (e) { return { favNews: 0, favEggs: 0, eggDone: 0, history: 0 }; }
}
function publicUser(row, data) {
  const d = { id: row.id, username: row.username, bio: row.bio, avatar: row.avatar, banner: row.banner, role: row.role, created_at: row.created_at };
  if (data !== undefined) d.stats = profileStats(data);
  return d;
}

/* ---------------- 邮件 ---------------- */
function mailCfg() {
  return {
    host: process.env.SMTP_HOST || "smtp.163.com",
    port: parseInt(process.env.SMTP_PORT || "465", 10),
    secure: String(process.env.SMTP_SSL || "1").toLowerCase() !== "0",
    user: process.env.SMTP_USER || "",
    pass: process.env.SMTP_PASS || "",
    fromName: process.env.SMTP_FROM || "GTA VI 查询站",
  };
}
async function sendMail(to, subject, text) {
  const c = mailCfg();
  if (!c.user || !c.pass) return "no-password";
  try {
    const t = nodemailer.createTransport({
      host: c.host, port: c.port, secure: c.secure,
      auth: { user: c.user, pass: c.pass },
      connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000,
    });
    await t.sendMail({
      from: `"${c.fromName}" <${c.user}>`,
      to, subject,
      text,
    });
    return "sent";
  } catch (e) {
    console.error("mail failed:", e && e.message);
    return "failed: " + String(e && e.message || e).slice(0, 120);
  }
}

/* ---------------- 验证码 ---------------- */
async function issueCode(email, purpose) {
  email = (email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 254) return { status: 400, body: { ok: false, error: "邮箱格式不对" } };
  if (!["register", "reset"].includes(purpose)) return { status: 400, body: { ok: false, error: "验证码用途不对" } };
  if (purpose === "register" && !REGISTER_OPEN) return { status: 403, body: { ok: false, error: "现在暂停注册" } };

  const p = db();
  const ex = await p.query("SELECT 1 FROM users WHERE email=$1", [email]);
  if (purpose === "register" && ex.rows.length) return { status: 409, body: { ok: false, error: "这个邮箱已经注册过了，直接登录吧" } };
  if (purpose === "reset" && !ex.rows.length) return { status: 404, body: { ok: false, error: "这个邮箱还没有注册" } };

  const old = await p.query("SELECT created_at FROM codes WHERE email=$1 AND purpose=$2", [email, purpose]);
  if (old.rows.length) {
    const last = Date.parse(old.rows[0].created_at.replace(" ", "T") + "+08:00") || 0;
    const now = Date.now();
    if (now - last < CODE_GAP * 1000) {
      const wait = Math.floor((CODE_GAP * 1000 - (now - last)) / 1000) + 1;
      return { status: 429, body: { ok: false, error: `发送太频繁，${wait} 秒后再试`, wait } };
    }
  }

  const code = String(100000 + crypto.randomInt(900000));
  const status = await sendMail(email, "GTA VI 查询站 · 验证码",
    `你正在${purpose === "register" ? "注册账号" : "重置密码"}。\n\n验证码：${code}\n\n${Math.max(1, Math.floor(CODE_TTL / 60))} 分钟内有效。如果这不是你本人的操作，忽略这封邮件即可。\n\n—— GTA VI 查询站`);
  if (!["sent", "no-password"].includes(status)) {
    return { status: 502, body: { ok: false, error: "邮件发送失败，请稍后再试或换个邮箱" } };
  }
  const exp = (Date.now() / 1000) + CODE_TTL;
  await p.query(
    `INSERT INTO codes(email,purpose,code,exp,tries,created_at) VALUES($1,$2,$3,$4,0,$5)
     ON CONFLICT(email,purpose) DO UPDATE SET code=excluded.code, exp=excluded.exp, tries=0, created_at=excluded.created_at`,
    [email, purpose, code, exp, nowStr()]);
  return { status: 200, body: { ok: true, sent: status === "sent", ttl: CODE_TTL } };
}

/* ---------------- 路由 ---------------- */
module.exports = async (req, res) => {
  const u = new URL(req.url, "http://local");
  let path = u.pathname;
  if ((path === "/api/index" || path === "/api" || path === "/api/index.js") && u.searchParams.get("p")) {
    path = u.searchParams.get("p");
  }
  const method = (req.method || "GET").toUpperCase();

  if (method === "OPTIONS") return send(res, 204, "", {});
  try {
    await ensureSchema();

    if (path === "/api/health" || path === "/health") return ok(res, { time: nowStr(), auth: true });

    /* --- 账户 --- */
    if (path === "/api/auth/code" && method === "POST") {
      const b = await readJson(req);
      if (!b) return fail(res, 400, "请求格式不对");
      if (!rateOk("code:" + ipOf(req), 8, 30, 3600)) return fail(res, 429, "操作太频繁，稍后再试");
      const r = await issueCode(clean(b.email, 254).toLowerCase(), b.purpose === "reset" ? "reset" : "register");
      return send(res, r.status, r.body);
    }

    if (path === "/api/auth/register" && method === "POST") {
      const b = await readJson(req);
      if (!b) return fail(res, 400, "请求格式不对");
      if (!REGISTER_OPEN) return fail(res, 403, "现在暂停注册");
      const ip = ipOf(req);
      if (!rateOk("reg:" + ip, 5, 12, 3600)) return fail(res, 429, "注册太频繁，稍后再试");

      const username = clean(b.username, 24);
      const email = clean(b.email, 254).toLowerCase();
      const code = clean(b.code, 12);
      const password = typeof b.password === "string" ? b.password : "";

      if (!USERNAME_RE.test(username)) return fail(res, 400, "用户名需 2–16 位，只能用中文、字母、数字或下划线");
      if (RESERVED.has(username.toLowerCase())) return fail(res, 400, "这个用户名不可用");
      if (!EMAIL_RE.test(email)) return fail(res, 400, "邮箱格式不对");
      if (password.length < 8 || password.length > 72) return fail(res, 400, "密码长度需在 8–72 位之间");
      if (!/^\d{6}$/.test(code)) return fail(res, 400, "验证码是 6 位数字");

      const p = db();
      const dup = await p.query("SELECT username,email FROM users WHERE username=$1 OR email=$2", [username, email]);
      if (dup.rows.length) return fail(res, 409, "用户名或邮箱已被使用");

      const cr = await p.query("SELECT * FROM codes WHERE email=$1 AND purpose='register'", [email]);
      const row = cr.rows[0];
      if (!row || row.exp < Date.now() / 1000) return fail(res, 400, "验证码已过期，请重新获取");
      if (row.tries >= 5) return fail(res, 429, "验证码错误次数过多，请重新获取");
      if (String(row.code).length !== code.length || !crypto.timingSafeEqual(Buffer.from(String(row.code)), Buffer.from(code))) {
        await p.query("UPDATE codes SET tries=tries+1 WHERE email=$1 AND purpose='register'", [email]);
        return fail(res, 400, "验证码不正确");
      }

      const { hash, salt } = hashPassword(password);
      const now = nowStr();
      const ins = await p.query(
        `INSERT INTO users(username,email,pass_hash,pass_salt,bio,avatar,banner,role,created_at,last_login)
         VALUES($1,$2,$3,$4,'','','','user',$5,$5) RETURNING id, username, email, created_at`,
        [username, email, hash, salt, now]);
      const user = ins.rows[0];
      await p.query(`INSERT INTO profiles(user_id,data,updated_at) VALUES($1,'{}',$2)
        ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`, [user.id, now]);
      await p.query("DELETE FROM codes WHERE email=$1 AND purpose='register'", [email]);

      const token = await makeSession(user.id, req.headers["user-agent"] || "", ip);
      return ok(res, { token, user: { id: user.id, username, email, bio: "", avatar: "", banner: "", role: "user", created_at: now } });
    }

    if (path === "/api/auth/login" && method === "POST") {
      const b = await readJson(req);
      if (!b) return fail(res, 400, "请求格式不对");
      const account = clean(b.account, 254);
      const password = typeof b.password === "string" ? b.password : "";
      const ip = ipOf(req);
      if (!rateOk("login:" + ip, 0, 60, 600)) return fail(res, 429, "尝试太频繁，稍后再试");
      if (!account || !password) return fail(res, 400, "请输入账号和密码");

      const p = db();
      const r = await p.query("SELECT * FROM users WHERE username=$1 OR email=$2", [account, account.toLowerCase()]);
      const row = r.rows[0];
      if (!row || !verifyPassword(password, row.pass_salt, row.pass_hash)) return fail(res, 401, "账号或密码不正确");

      await p.query("UPDATE users SET last_login=$1 WHERE id=$2", [nowStr(), row.id]);
      const token = await makeSession(row.id, req.headers["user-agent"] || "", ip);
      return ok(res, { token, user: { id: row.id, username: row.username, email: row.email, bio: row.bio, avatar: row.avatar, banner: row.banner, role: row.role, created_at: row.created_at } });
    }

    if (path === "/api/auth/logout" && method === "POST") {
      const token = bearer(req);
      if (token) {
        await db().query("DELETE FROM sessions WHERE token_hash=$1", [crypto.createHash("sha256").update(token).digest("hex")]);
      }
      return ok(res, {});
    }

    if (path === "/api/auth/reset" && method === "POST") {
      const b = await readJson(req);
      if (!b) return fail(res, 400, "请求格式不对");
      const email = clean(b.email, 254).toLowerCase();
      const code = clean(b.code, 12);
      const password = typeof b.password === "string" ? b.password : "";
      if (!EMAIL_RE.test(email)) return fail(res, 400, "邮箱格式不对");
      if (password.length < 8 || password.length > 72) return fail(res, 400, "密码长度需在 8–72 位之间");

      const p = db();
      const ur = await p.query("SELECT * FROM users WHERE email=$1", [email]);
      const user = ur.rows[0];
      if (!user) return fail(res, 404, "这个邮箱还没有注册");
      const cr = await p.query("SELECT * FROM codes WHERE email=$1 AND purpose='reset'", [email]);
      const row = cr.rows[0];
      if (!row || row.exp < Date.now() / 1000) return fail(res, 400, "验证码已过期，请重新获取");
      if (row.tries >= 5 || String(row.code).length !== code.length || !crypto.timingSafeEqual(Buffer.from(String(row.code)), Buffer.from(code))) {
        await p.query("UPDATE codes SET tries=tries+1 WHERE email=$1 AND purpose='reset'", [email]);
        return fail(res, 400, "验证码不正确");
      }
      const { hash, salt } = hashPassword(password);
      await p.query("UPDATE users SET pass_hash=$1, pass_salt=$2 WHERE id=$3", [hash, salt, user.id]);
      await p.query("DELETE FROM codes WHERE email=$1 AND purpose='reset'", [email]);
      await p.query("DELETE FROM sessions WHERE user_id=$1", [user.id]);
      return ok(res, {});
    }

    if (path === "/api/auth/password" && method === "POST") {
      const row = await userByToken(bearer(req));
      if (!row) return fail(res, 401, "未登录");
      const b = await readJson(req);
      if (!b) return fail(res, 400, "请求格式不对");
      const oldPw = typeof b.old === "string" ? b.old : "";
      const newPw = typeof b.new === "string" ? b.new : "";
      if (newPw.length < 8 || newPw.length > 72) return fail(res, 400, "新密码长度需在 8–72 位之间");
      if (!verifyPassword(oldPw, row.pass_salt, row.pass_hash)) return fail(res, 400, "当前密码不正确");
      const { hash, salt } = hashPassword(newPw);
      await db().query("UPDATE users SET pass_hash=$1, pass_salt=$2 WHERE id=$3", [hash, salt, row.id]);
      return ok(res, {});
    }

    /* --- 个人资料 --- */
    if (path === "/api/me" && method === "GET") {
      const row = await userByToken(bearer(req));
      if (!row) return fail(res, 401, "未登录");
      return ok(res, { user: publicUser(row, await readProfile(row.id)) });
    }

    if (path === "/api/me" && method === "PATCH") {
      const row = await userByToken(bearer(req));
      if (!row) return fail(res, 401, "未登录");
      const b = await readJson(req);
      if (!b) return fail(res, 400, "请求格式不对");
      const bio = clean(b.bio, 120);
      const avatar = clean(b.avatar, 2000);
      const banner = clean(b.banner, 2000);
      await db().query("UPDATE users SET bio=$1, avatar=$2, banner=$3 WHERE id=$4", [bio, avatar, banner, row.id]);
      return ok(res, { user: { id: row.id, username: row.username, email: row.email, bio, avatar, banner, role: row.role, created_at: row.created_at } });
    }

    if (path === "/api/me/data" && method === "GET") {
      const row = await userByToken(bearer(req));
      if (!row) return fail(res, 401, "未登录");
      const data = await readProfile(row.id);
      return ok(res, { data, stats: profileStats(data) });
    }

    if (path === "/api/me/data" && method === "POST") {
      const row = await userByToken(bearer(req));
      if (!row) return fail(res, 401, "未登录");
      const b = await readJson(req);
      if (!b || typeof b.data !== "object" || b.data === null) return fail(res, 400, "数据格式不对");
      const raw = JSON.stringify(b.data);
      if (raw.length > 96 * 1024) return fail(res, 413, "数据太大了");
      await db().query(`INSERT INTO profiles(user_id,data,updated_at) VALUES($1,$2,$3)
        ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`, [row.id, raw, nowStr()]);
      return ok(res, { stats: profileStats(b.data) });
    }

    if (path.startsWith("/api/u/") && method === "GET") {
      const name = decodeURIComponent(path.slice(7)).trim();
      if (!name) return fail(res, 404, "用户不存在");
      const r = await db().query("SELECT * FROM users WHERE username=$1", [name]);
      const row = r.rows[0];
      if (!row) return fail(res, 404, "用户不存在");
      return ok(res, { user: publicUser(row, await readProfile(row.id)) });
    }

    /* --- BUG 反馈 --- */
    if (path === "/api/bug" && method === "POST") {
      const b = await readJson(req);
      if (!b) return fail(res, 400, "请求格式不对");
      if (String(b.hp || "").trim()) return ok(res, { id: 0, mail: "ignored" });

      const desc = clean(b.desc, 600);
      if (desc.length < 4) return fail(res, 400, "问题描述太短（至少 4 个字）");
      const pageKey = clean(b.page_key, 12) || "home";
      const page = PAGES[pageKey] || clean(b.page, 24) || "首页";
      const device = clean(b.device, 80);
      const ip = ipOf(req);
      const ua = clean(req.headers["user-agent"] || "", 300);
      const referer = clean(b.href || req.headers["referer"] || "", 300);

      if (!rateOk("bug:" + ip, 30, 20, 86400)) return fail(res, 429, "提交太频繁，稍后再试");

      const p = db();
      const ins = await p.query(
        `INSERT INTO bugs(created_at,page_key,page,device,"desc",ip,ua,referer,mail_status)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending') RETURNING id`,
        [nowStr(), pageKey, page, device, desc, ip, ua, referer]);
      const id = ins.rows[0].id;

      const body = [
        "页面：" + page + "（" + pageKey + "）",
        "设备 / 浏览器：" + (device || "未填写"),
        "时间：" + nowStr(),
        "",
        desc,
        "",
        "User-Agent：" + (ua || "-"),
        "来源页：" + (referer || "-"),
        "",
        "—— 由查询站后端自动发送",
      ].join("\n");
      const status = await sendMail(BUG_TO, "[BUG反馈] " + page + " · #" + id, body);
      await p.query("UPDATE bugs SET mail_status=$1 WHERE id=$2", [status, id]);
      return ok(res, { id, mail: "邮件将发往 " + BUG_TO });
    }

    if (path === "/api/bug" && method === "GET") {
      if (clean(req.headers["x-admin-key"], 64) !== ADMIN_PW && clean(u.searchParams.get("key"), 64) !== ADMIN_PW) {
        return fail(res, 401, "需要站长密码");
      }
      const r = await db().query("SELECT * FROM bugs ORDER BY id DESC LIMIT 200");
      return ok(res, { list: r.rows });
    }

    return fail(res, 404, "not found");
  } catch (e) {
    console.error("api error:", e);
    return fail(res, 500, "服务器出错：" + String(e && e.message || e).slice(0, 120));
  }
};

function bearer(req) {
  const h = req.headers["authorization"] || "";
  return h.toLowerCase().startsWith("bearer ") ? h.slice(7).trim() : "";
}
