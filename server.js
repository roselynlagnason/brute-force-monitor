// Vigilix backend.
// - records the real IP / ISP / location of every visit and login attempt (SQLite)
// - enforces rate limiting + lockouts on the server, supports admin IP blocking
// - sends alerts (Discord / Telegram / webhook), serves the admin API and the built React app
// Run: npm run server   (Node 22.13+ required for the built-in node:sqlite)
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const ROOT = path.dirname(fileURLToPath(import.meta.url));

// ---- tiny .env loader (no dependency); real environment variables win ----
try {
  for (const line of fs.readFileSync(path.join(ROOT, ".env"), "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/i);
    if (m && !line.trim().startsWith("#") && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
} catch { /* no .env file */ }

const env = process.env;
const PORT = Number(env.PORT) || 3001;
const DATA_DIR = path.resolve(env.DATA_DIR || path.join(ROOT, "data"));
// Set TRUST_PROXY=1 ONLY behind a reverse proxy (nginx, Render, Railway, Cloudflare...) that sets X-Forwarded-For.
const TRUST_PROXY = env.TRUST_PROXY === "1";
const ADMIN_USER = env.ADMIN_USER || "admin";
const ADMIN_PASS_HASH = env.ADMIN_PASS_HASH || "";
const ADMIN_PASS = env.ADMIN_PASS || "Admin123!";
const ADMIN_IDLE_MS = (Number(env.ADMIN_IDLE_MIN) || 15) * 60_000;
const MAX_FAILS = Number(env.MAX_FAILS) || 5;                    // failures allowed per window
const WINDOW_MS = (Number(env.LOCK_WINDOW_SEC) || 60) * 1000;    // lockout window
const ALERT_THRESHOLD = Number(env.ALERT_THRESHOLD) || 10;       // failures from one IP that raise an alert
const ALERT_WINDOW_MS = (Number(env.ALERT_WINDOW_MIN) || 5) * 60_000;
const ALERT_COOLDOWN_MS = 30 * 60_000;
const DISTRIBUTED_WINDOW_MS = 10 * 60_000;

if (!ADMIN_PASS_HASH && !env.ADMIN_PASS) console.warn("[warn] Using the default admin password. Set ADMIN_PASS_HASH in .env (see README).");

// ---- database ----
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, "loginguard.db"));
db.exec(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, time TEXT NOT NULL, kind TEXT NOT NULL, username TEXT, result TEXT, reason TEXT, risk TEXT, source TEXT, geo TEXT);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(time);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source, time);
CREATE TABLE IF NOT EXISTS blocked(ip TEXT PRIMARY KEY, reason TEXT, time TEXT);
CREATE TABLE IF NOT EXISTS notes(ip TEXT PRIMARY KEY, status TEXT, note TEXT, updated TEXT);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, ip TEXT, message TEXT, sent TEXT);
`);

const q = {
  insert: db.prepare("INSERT INTO events(id,time,kind,username,result,reason,risk,source,geo) VALUES(?,?,?,?,?,?,?,?,?)"),
  setRisk: db.prepare("UPDATE events SET risk=? WHERE id=?"),
  failsIp: db.prepare("SELECT COUNT(*) c, MIN(time) oldest FROM events WHERE kind='user' AND result='Failed' AND source=? AND time>?"),
  failsUser: db.prepare("SELECT COUNT(*) c, MIN(time) oldest FROM events WHERE kind='user' AND result='Failed' AND username=? AND time>?"),
  adminFailsIp: db.prepare("SELECT COUNT(*) c, MIN(time) oldest FROM events WHERE kind='admin' AND result='Failed' AND source=? AND time>?"),
  allFailsIp: db.prepare("SELECT COUNT(*) c FROM events WHERE result='Failed' AND source=? AND time>?"),
  distinctUsers: db.prepare("SELECT COUNT(DISTINCT username) c FROM events WHERE kind='user' AND source=? AND time>?"),
  blockedGet: db.prepare("SELECT * FROM blocked WHERE ip=?"),
  alertRecent: db.prepare("SELECT id FROM alerts WHERE ip=? AND time>?"),
  alertInsert: db.prepare("INSERT INTO alerts(time,ip,message,sent) VALUES(?,?,?,?)"),
  geoLatest: db.prepare("SELECT geo FROM events WHERE source=? AND geo IS NOT NULL AND geo!='{}' ORDER BY time DESC LIMIT 1")
};

// one-time import of the old events.json from the previous version
try {
  const old = JSON.parse(fs.readFileSync(path.join(ROOT, "events.json"), "utf8"));
  if (!db.prepare("SELECT COUNT(*) c FROM events").get().c && Array.isArray(old) && old.length) {
    db.exec("BEGIN");
    for (const e of old) {
      const { id, time, username, result, reason, risk, source, ...geo } = e;
      try { q.insert.run(String(id), time, result === "Visit" ? "visit" : "user", username, result, reason || "", risk || "Normal", source || "", JSON.stringify(geo)); } catch { /* skip dup */ }
    }
    db.exec("COMMIT");
    fs.renameSync(path.join(ROOT, "events.json"), path.join(ROOT, "events.json.imported"));
    console.log(`Imported ${old.length} events from events.json`);
  }
} catch { /* nothing to import */ }

// ---- helpers ----
const sinceIso = (ms) => new Date(Date.now() - ms).toISOString();
const str = (v, max = 200) => String(v ?? "").slice(0, max);
const rowToEvent = (r) => ({ id: r.id, time: r.time, kind: r.kind, username: r.username, result: r.result, reason: r.reason, risk: r.risk, source: r.source, ...JSON.parse(r.geo || "{}") });

function clientIp(req) {
  let ip = req.socket.remoteAddress || "";
  if (TRUST_PROXY && req.headers["x-forwarded-for"]) ip = String(req.headers["x-forwarded-for"]).split(",")[0].trim();
  return ip.replace(/^::ffff:/, "");
}
function isPrivate(ip) {
  return ip === "::1" || ip === "127.0.0.1" || /^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) || /^f[cd]/i.test(ip) || /^fe80/i.test(ip);
}

const geoCache = new Map();
async function lookupGeo(ip) {
  if (isPrivate(ip)) return { isp: "Local / private network", location: "—" };
  if (geoCache.has(ip)) return geoCache.get(ip);
  try {
    const fields = "status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,proxy,hosting,mobile";
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`, { signal: AbortSignal.timeout(3000) });
    const d = await res.json();
    if (d.status === "success") {
      const host = d.reverse || "";
      const info = {
        isp: d.isp || d.org || "Unknown", org: d.org || "", asn: (d.as || "").split(" ")[0],
        domain: host.split(".").slice(-2).join("."), hostname: host,
        country: d.country || "", region: d.regionName || "", city: d.city || "", postal: d.zip || "", timezone: d.timezone || "",
        location: [d.city, d.regionName, d.country].filter(Boolean).join(", "),
        lat: d.lat, lon: d.lon, proxy: !!d.proxy, hosting: !!d.hosting, mobile: !!d.mobile
      };
      geoCache.set(ip, info);
      return info;
    }
  } catch { /* lookup is best effort */ }
  return { isp: "Unknown", location: "Unknown" };
}

async function record({ kind, username, result, reason, risk = "Normal", ip }) {
  const geo = await lookupGeo(ip);
  const id = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  q.insert.run(id, new Date().toISOString(), kind, str(username) || "(empty)", result, reason, risk, ip, JSON.stringify(geo));
  return { id, geo };
}

// ---- alerts ----
const channels = () => ({
  discord: !!env.DISCORD_WEBHOOK_URL,
  telegram: !!(env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID),
  webhook: !!env.ALERT_WEBHOOK_URL
});
async function post(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(5000) });
  if (!r.ok) throw new Error(String(r.status));
}
async function sendAlert(message) {
  const sent = [];
  const jobs = [];
  if (env.DISCORD_WEBHOOK_URL) jobs.push(post(env.DISCORD_WEBHOOK_URL, { content: message }).then(() => sent.push("Discord")));
  if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) jobs.push(post(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, { chat_id: env.TELEGRAM_CHAT_ID, text: message }).then(() => sent.push("Telegram")));
  if (env.ALERT_WEBHOOK_URL) jobs.push(post(env.ALERT_WEBHOOK_URL, { text: message }).then(() => sent.push("Webhook")));
  await Promise.allSettled(jobs);
  return sent;
}
async function maybeAlert(ip, geo) {
  const fails = q.allFailsIp.get(ip, sinceIso(ALERT_WINDOW_MS)).c;
  if (fails < ALERT_THRESHOLD || q.alertRecent.get(ip, sinceIso(ALERT_COOLDOWN_MS))) return;
  const where = [geo.city, geo.country].filter(Boolean).join(", ") || "unknown location";
  const message = `Vigilix alert: ${ip} (${geo.isp || "unknown ISP"}, ${where}) made ${fails} failed logins in the last ${Math.round(ALERT_WINDOW_MS / 60000)} minutes.`;
  q.alertInsert.run(new Date().toISOString(), ip, message, "");   // reserve first so concurrent attempts don't double-alert
  const sent = await sendAlert(message);
  db.prepare("UPDATE alerts SET sent=? WHERE id=(SELECT MAX(id) FROM alerts WHERE ip=?)").run(sent.join(", ") || "dashboard only", ip);
}

// ---- admin auth ----
function checkPassword(pass) {
  if (ADMIN_PASS_HASH) {
    const [, salt, hash] = ADMIN_PASS_HASH.split("$");
    if (!salt || !hash) return false;
    const calc = crypto.scryptSync(pass, salt, 64), exp = Buffer.from(hash, "hex");
    return exp.length === calc.length && crypto.timingSafeEqual(calc, exp);
  }
  const a = crypto.createHash("sha256").update(pass).digest(), b = crypto.createHash("sha256").update(ADMIN_PASS).digest();
  return crypto.timingSafeEqual(a, b);
}
const sessions = new Map();   // token -> last activity (ms)
// Background polling (X-Poll: 1) must not keep a session alive, otherwise it would never go idle.
function isAdmin(req) {
  const token = (req.headers.authorization || "").replace(/^Bearer /, "");
  const last = sessions.get(token);
  if (!last) return false;
  if (Date.now() - last > ADMIN_IDLE_MS) { sessions.delete(token); return false; }
  if (req.headers["x-poll"] !== "1") sessions.set(token, Date.now());
  return true;
}

// ---- http plumbing ----
function readBody(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", c => { body += c; if (body.length > 20_000) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(body || "{}")); } catch { resolve({}); } });
  });
}
const send = (res, status, data) => { res.writeHead(status, { "Content-Type": "application/json", "X-Content-Type-Options": "nosniff" }); res.end(JSON.stringify(data)); };
const validIp = (ip) => /^[0-9a-f:.]{2,45}$/i.test(ip || "");
const retryAfter = (oldest) => Math.max(1, Math.ceil((Date.parse(oldest) + WINDOW_MS - Date.now()) / 1000));

const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".json": "application/json", ".woff2": "font/woff2" };
function serveStatic(req, res, pathname) {
  const dist = path.join(ROOT, "dist");
  if (!fs.existsSync(dist)) return send(res, 404, { error: "Not found. Run `npm run build` to serve the app from this server, or use `npm run dev`." });
  let file = path.join(dist, path.normalize(decodeURIComponent(pathname)));
  if (!file.startsWith(dist) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(dist, "index.html");
  res.writeHead(200, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream", "X-Content-Type-Options": "nosniff" });
  fs.createReadStream(file).pipe(res);
}

// ---- admin stats ----
function rangeWhere(url) {
  const from = url.searchParams.get("from"), to = url.searchParams.get("to");
  const where = [], args = [];
  if (from) { where.push("time>=?"); args.push(from); }
  if (to) { where.push("time<=?"); args.push(to); }
  return { sql: where.length ? "WHERE " + where.join(" AND ") : "", args };
}
function buildStats(url) {
  const { sql, args } = rangeWhere(url);
  const rows = db.prepare(`SELECT time,kind,result,username,source,risk FROM events ${sql} ORDER BY time DESC LIMIT 100000`).all(...args);
  const tz = Number(url.searchParams.get("tz")) || 0;               // Date.getTimezoneOffset() from the browser
  const totals = { attempts: 0, failed: 0, suspicious: 0, visits: 0, adminSignins: 0, uniqueIps: 0 };
  const ips = new Set(), users = new Map(), perIp = new Map();
  for (const r of rows) {
    ips.add(r.source);
    if (r.kind === "visit") totals.visits++;
    if (r.kind === "admin" && r.result === "Success") totals.adminSignins++;
    if (r.risk === "Suspicious") totals.suspicious++;
    const bad = r.result === "Failed" || r.result === "Blocked";
    if (bad) totals.failed++;
    if (r.kind === "user") {
      totals.attempts++;
      const u = users.get(r.username) || { username: r.username, count: 0, failed: 0 };
      u.count++; if (bad) u.failed++; users.set(r.username, u);
    }
    const p = perIp.get(r.source) || { ip: r.source, total: 0, failed: 0, usernames: new Set(), last: r.time };
    p.total++; if (bad) p.failed++;
    if (r.kind === "user") p.usernames.add(r.username);
    perIp.set(r.source, p);
  }
  totals.uniqueIps = ips.size;

  // timeline buckets (hourly for <= 48h ranges, otherwise daily), shifted into the viewer's timezone
  const now = Date.now();
  const fromMs = url.searchParams.get("from") ? Date.parse(url.searchParams.get("from")) : (rows.length ? Date.parse(rows[rows.length - 1].time) : now - 86_400_000);
  const toMs = url.searchParams.get("to") ? Date.parse(url.searchParams.get("to")) : now;
  const hourly = toMs - fromMs <= 48 * 3_600_000;
  const step = hourly ? 3_600_000 : 86_400_000;
  const key = (ms) => Math.floor((ms - tz * 60_000) / step) * step;
  const first = Math.max(key(fromMs), key(toMs) - 119 * step);
  const buckets = new Map();
  for (let t = first; t <= key(toMs); t += step) buckets.set(t, { t, failed: 0, blocked: 0, visits: 0 });
  for (const r of rows) {
    const b = buckets.get(key(Date.parse(r.time)));
    if (!b) continue;
    if (r.result === "Failed") b.failed++; else if (r.result === "Blocked") b.blocked++; else if (r.kind === "visit") b.visits++;
  }

  const topIps = [...perIp.values()].sort((a, b) => b.failed - a.failed || b.total - a.total).slice(0, 10).map(p => {
    const g = q.geoLatest.get(p.ip);
    const geo = g ? JSON.parse(g.geo) : {};
    return { ip: p.ip, total: p.total, failed: p.failed, distinctUsernames: p.usernames.size, last: p.last, isp: geo.isp, location: geo.location, proxy: !!geo.proxy, hosting: !!geo.hosting, spraying: p.usernames.size >= 5 && p.failed >= 5 };
  });
  return { totals, bucket: hourly ? "hour" : "day", timeline: [...buckets.values()], topUsernames: [...users.values()].sort((a, b) => b.count - a.count).slice(0, 8), topIps };
}

function ipDetail(ip) {
  const rows = db.prepare("SELECT * FROM events WHERE source=? ORDER BY time DESC LIMIT 200").all(ip);
  const total = db.prepare("SELECT COUNT(*) c, MIN(time) first, MAX(time) last FROM events WHERE source=?").get(ip);
  const usernames = db.prepare("SELECT username, COUNT(*) count, SUM(result='Failed') failed FROM events WHERE source=? AND kind='user' GROUP BY username ORDER BY count DESC LIMIT 20").all(ip);
  const g = q.geoLatest.get(ip);
  const note = db.prepare("SELECT status,note,updated FROM notes WHERE ip=?").get(ip);
  const failedTotal = db.prepare("SELECT COUNT(*) c FROM events WHERE source=? AND result='Failed'").get(ip).c;
  const distinct = usernames.length;
  return {
    ip, total: total.c, first: total.first, last: total.last, failed: failedTotal,
    geo: g ? JSON.parse(g.geo) : {}, events: rows.map(rowToEvent), usernames,
    blocked: q.blockedGet.get(ip) || null, note: note || null,
    patterns: { spraying: distinct >= 5 && failedTotal >= 5, targeted: usernames.some(u => u.failed >= 10) }
  };
}

// ---- server ----
http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const { pathname } = url;
  try {
    // PUBLIC: page visit
    if (req.method === "POST" && pathname === "/api/visit") {
      await record({ kind: "visit", username: "(visitor)", result: "Visit", reason: "Opened login page", ip: clientIp(req) });
      return send(res, 204, {});
    }

    // PUBLIC: login attempt. The server decides the outcome (it is a monitor: no account ever signs in).
    if (req.method === "POST" && pathname === "/api/login") {
      const b = await readBody(req);
      const ip = clientIp(req);
      const username = str(b.username).trim().toLowerCase();

      if (q.blockedGet.get(ip)) {
        await record({ kind: "user", username, result: "Blocked", reason: "IP blocked by administrator", risk: "Suspicious", ip });
        return send(res, 403, { message: "Access from your network has been blocked by the administrator." });
      }
      const byIp = q.failsIp.get(ip, sinceIso(WINDOW_MS)), byUser = q.failsUser.get(username, sinceIso(WINDOW_MS));
      if (byIp.c >= MAX_FAILS || byUser.c >= MAX_FAILS) {
        await record({ kind: "user", username, result: "Blocked", reason: byIp.c >= MAX_FAILS ? "Rate limit exceeded (IP)" : "Rate limit exceeded (username)", risk: "Suspicious", ip });
        const wait = retryAfter(byIp.c >= MAX_FAILS ? byIp.oldest : byUser.oldest);
        return send(res, 429, { message: `Too many failed attempts. Try again in ${wait} seconds.`, retryAfter: wait });
      }
      const { id, geo } = await record({ kind: "user", username, result: "Failed", reason: "Invalid credentials", ip });
      const recentFails = q.failsIp.get(ip, sinceIso(WINDOW_MS)).c;
      const spray = q.distinctUsers.get(ip, sinceIso(DISTRIBUTED_WINDOW_MS)).c >= 4;
      if (recentFails >= 3 || spray) q.setRisk.run("Suspicious", id);
      maybeAlert(ip, geo).catch(() => {});
      return send(res, 401, { message: "Incorrect username or password. Please try again." });
    }

    // ADMIN: sign in (rate limited, audited)
    if (req.method === "POST" && pathname === "/api/admin/login") {
      const b = await readBody(req);
      const ip = clientIp(req);
      const prior = q.adminFailsIp.get(ip, sinceIso(15 * 60_000));
      if (prior.c >= 5) {
        await record({ kind: "admin", username: str(b.username), result: "Blocked", reason: "Admin login rate limit", risk: "Suspicious", ip });
        return send(res, 429, { error: "Too many failed admin sign-ins. Try again in 15 minutes." });
      }
      if (str(b.username).trim() === ADMIN_USER && checkPassword(str(b.password, 500))) {
        const token = crypto.randomBytes(24).toString("hex");
        sessions.set(token, Date.now());
        await record({ kind: "admin", username: ADMIN_USER, result: "Success", reason: "Admin signed in", ip });
        return send(res, 200, { token, idleMinutes: ADMIN_IDLE_MS / 60000 });
      }
      const { geo } = await record({ kind: "admin", username: str(b.username), result: "Failed", reason: "Invalid admin credentials", risk: "Suspicious", ip });
      maybeAlert(ip, geo).catch(() => {});
      return send(res, 401, { error: "Invalid admin credentials. This attempt has been recorded." });
    }

    if (pathname.startsWith("/api/admin/")) {
      if (!isAdmin(req)) return send(res, 401, { error: "Unauthorized" });
      const m = req.method;

      if (m === "POST" && pathname === "/api/admin/ping") return send(res, 200, {});
      if (m === "POST" && pathname === "/api/admin/logout") { sessions.delete((req.headers.authorization || "").replace(/^Bearer /, "")); return send(res, 200, {}); }

      if (m === "GET" && pathname === "/api/admin/events") {
        const { sql, args } = rangeWhere(url);
        const limit = Math.min(Number(url.searchParams.get("limit")) || 5000, 20000);
        return send(res, 200, db.prepare(`SELECT * FROM events ${sql} ORDER BY time DESC LIMIT ${limit}`).all(...args).map(rowToEvent));
      }
      if (m === "DELETE" && pathname === "/api/admin/events") { db.exec("DELETE FROM events"); return send(res, 200, {}); }

      if (m === "GET" && pathname === "/api/admin/stats") return send(res, 200, buildStats(url));

      if (m === "GET" && pathname === "/api/admin/ip") {
        const ip = url.searchParams.get("ip");
        return validIp(ip) ? send(res, 200, ipDetail(ip)) : send(res, 400, { error: "Bad IP" });
      }

      if (m === "GET" && pathname === "/api/admin/meta") {
        const notes = {};
        for (const n of db.prepare("SELECT * FROM notes").all()) notes[n.ip] = { status: n.status, note: n.note, updated: n.updated };
        return send(res, 200, {
          blocked: db.prepare("SELECT * FROM blocked ORDER BY time DESC").all(), notes,
          alerts: db.prepare("SELECT * FROM alerts ORDER BY id DESC LIMIT 50").all(),
          channels: channels(),
          config: { maxFails: MAX_FAILS, windowSec: WINDOW_MS / 1000, alertThreshold: ALERT_THRESHOLD, alertWindowMin: ALERT_WINDOW_MS / 60000, idleMin: ADMIN_IDLE_MS / 60000 }
        });
      }

      if (m === "POST" && pathname === "/api/admin/block") {
        const b = await readBody(req);
        if (!validIp(b.ip)) return send(res, 400, { error: "Bad IP" });
        db.prepare("INSERT OR REPLACE INTO blocked(ip,reason,time) VALUES(?,?,?)").run(b.ip, str(b.reason, 300), new Date().toISOString());
        return send(res, 200, {});
      }
      if (m === "DELETE" && pathname === "/api/admin/block") {
        const ip = url.searchParams.get("ip");
        if (!validIp(ip)) return send(res, 400, { error: "Bad IP" });
        db.prepare("DELETE FROM blocked WHERE ip=?").run(ip);
        return send(res, 200, {});
      }

      if (m === "PUT" && pathname === "/api/admin/note") {
        const b = await readBody(req);
        if (!validIp(b.ip)) return send(res, 400, { error: "Bad IP" });
        const status = ["New", "Investigating", "False alarm", "Resolved"].includes(b.status) ? b.status : "New";
        db.prepare("INSERT OR REPLACE INTO notes(ip,status,note,updated) VALUES(?,?,?,?)").run(b.ip, status, str(b.note, 1000), new Date().toISOString());
        return send(res, 200, {});
      }

      if (m === "POST" && pathname === "/api/admin/test-alert") {
        const sent = await sendAlert("Vigilix test alert: your alert channel is working.");
        return send(res, 200, { sent });
      }
      return send(res, 404, { error: "Not found" });
    }

    if (pathname.startsWith("/api/")) return send(res, 404, { error: "Not found" });
    serveStatic(req, res, pathname);
  } catch (err) {
    console.error(err);
    if (!res.headersSent) send(res, 500, { error: "Server error" });
  }
}).listen(PORT, "0.0.0.0", () => console.log(`Vigilix API listening on http://localhost:${PORT}`));
