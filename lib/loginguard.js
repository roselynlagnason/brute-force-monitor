import crypto from "node:crypto";
import { supabase } from "../supabase.js";

const env = process.env;

export const CONFIG = {
  adminUser: env.ADMIN_USER || "admin",
  adminPassHash: env.ADMIN_PASS_HASH || "",
  adminIdleMs: (Number(env.ADMIN_IDLE_MIN) || 15) * 60_000,
  maxFails: Number(env.MAX_FAILS) || 5,
  windowMs: (Number(env.LOCK_WINDOW_SEC) || 60) * 1000,
  alertThreshold: Number(env.ALERT_THRESHOLD) || 10,
  alertWindowMs: (Number(env.ALERT_WINDOW_MIN) || 5) * 60_000,
  distributedWindowMs: 10 * 60_000,
  adminFailWindowMs: 15 * 60_000,
  alertCooldownMs: 30 * 60_000,
};

export const str = (value, max = 200) => String(value ?? "").slice(0, max);
export const validIp = (ip) => /^[0-9a-f:.]{2,45}$/i.test(ip || "");
export const sinceIso = (ms) => new Date(Date.now() - ms).toISOString();

export function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  if (typeof req.body === "string") {
    try { return JSON.parse(req.body || "{}"); } catch { return {}; }
  }
  return {};
}

export function clientIp(req) {
  // Vercel supplies these proxy headers. Prefer x-real-ip, then the first
  // x-forwarded-for entry. Never accept an IP supplied in the JSON body.
  const realIp = req.headers["x-real-ip"];
  const forwarded = req.headers["x-forwarded-for"];
  const candidate = realIp ||
    (forwarded ? String(forwarded).split(",")[0].trim() : "") ||
    req.socket?.remoteAddress || "";
  return String(candidate).replace(/^::ffff:/, "").trim();
}

export function checkPassword(password) {
  const [, salt, hash] = CONFIG.adminPassHash.split("$");
  if (!salt || !hash) return false;
  try {
    const calculated = crypto.scryptSync(String(password), salt, 64);
    const expected = Buffer.from(hash, "hex");
    return expected.length === calculated.length &&
      crypto.timingSafeEqual(calculated, expected);
  } catch {
    return false;
  }
}

export const createSessionToken = () => crypto.randomBytes(32).toString("hex");

export async function createAdminSession(token) {
  const now = new Date().toISOString();
  const { error } = await supabase.from("sessions").insert({
    token, last_activity: now, created_at: now,
  });
  if (error) throw error;
}

export async function verifyAdminSession(req) {
  const token = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return false;

  const { data, error } = await supabase
    .from("sessions")
    .select("token,last_activity")
    .eq("token", token)
    .maybeSingle();
  if (error) throw error;
  if (!data) return false;

  const last = Date.parse(data.last_activity);
  if (!Number.isFinite(last) || Date.now() - last > CONFIG.adminIdleMs) {
    const { error: deleteError } = await supabase.from("sessions").delete().eq("token", token);
    if (deleteError) throw deleteError;
    return false;
  }

  if (req.headers["x-poll"] !== "1") {
    const { error: updateError } = await supabase.from("sessions")
      .update({ last_activity: new Date().toISOString() }).eq("token", token);
    if (updateError) throw updateError;
  }
  return true;
}

export async function deleteAdminSession(req) {
  const token = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return;
  const { error } = await supabase.from("sessions").delete().eq("token", token);
  if (error) throw error;
}

const geoCache = new Map();
function isPrivateIp(ip) {
  return ip === "127.0.0.1" || ip === "::1" ||
    ip.startsWith("10.") || ip.startsWith("192.168.") ||
    ip.startsWith("169.254.") || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^f[cd]/i.test(ip) || /^fe80/i.test(ip);
}

export async function lookupGeo(ip) {
  if (!validIp(ip) || isPrivateIp(ip)) {
    return { isp: "Local / private network", location: "—" };
  }
  if (geoCache.has(ip)) return geoCache.get(ip);
  try {
    const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) throw new Error(`Geolocation HTTP ${response.status}`);
    const d = await response.json();
    if (d.success === false) throw new Error("Geolocation unavailable");
    const c = d.connection || {};
    const geo = {
      isp: c.isp || c.org || "Unknown",
      org: c.org || "",
      asn: c.asn || "",
      domain: c.domain || "",
      hostname: "",
      country: d.country || "",
      region: d.region || "",
      city: d.city || "",
      postal: d.postal || "",
      timezone: d.timezone?.id || "",
      location: [d.city, d.region, d.country].filter(Boolean).join(", "),
      lat: d.latitude ?? null,
      lon: d.longitude ?? null,
      proxy: !!d.security?.proxy,
      hosting: !!d.security?.hosting,
      mobile: !!d.security?.mobile,
    };
    geoCache.set(ip, geo);
    return geo;
  } catch (error) {
    console.warn("IP geolocation lookup failed:", error.message);
    return { isp: "Unknown", location: "Unknown" };
  }
}

export async function recordEvent({ kind, username, result, reason, risk = "Normal", ip }) {
  const geo = await lookupGeo(ip);
  const id = `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
  const event = {
    id,
    time: new Date().toISOString(),
    kind,
    username: str(username) || "(empty)",
    result,
    reason: str(reason, 500),
    risk,
    source: ip,
    geo,
  };
  const { error } = await supabase.from("events").insert(event);
  if (error) throw error;
  return { id, geo };
}

export async function updateEventRisk(id, risk) {
  const { error } = await supabase.from("events").update({ risk }).eq("id", id);
  if (error) throw error;
}

export async function isBlockedIp(ip) {
  const { data, error } = await supabase.from("blocked")
    .select("ip,reason,time").eq("ip", ip).maybeSingle();
  if (error) throw error;
  return data || null;
}

export async function blockIp(ip, reason = "Manually blocked") {
  const { error } = await supabase.from("blocked").upsert({
    ip, reason: str(reason, 300), time: new Date().toISOString(),
  }, { onConflict: "ip" });
  if (error) throw error;
}

export async function unblockIp(ip) {
  const { error } = await supabase.from("blocked").delete().eq("ip", ip);
  if (error) throw error;
}

export async function saveIpNote(ip, status, note) {
  const allowed = ["New", "Investigating", "False alarm", "Resolved"];
  if (!allowed.includes(status)) throw new Error("Invalid note status.");
  const { error } = await supabase.from("notes").upsert({
    ip, status, note: str(note, 1000), updated: new Date().toISOString(),
  }, { onConflict: "ip" });
  if (error) throw error;
}

export async function getEvents(filters = {}, limit = 1000, ascending = false) {
  let query = supabase.from("events")
    .select("id,time,kind,username,result,reason,risk,source,geo")
    .order("time", { ascending })
    .limit(Math.min(Math.max(Number(limit) || 1000, 1), 20000));

  if (filters.ip) query = query.eq("source", filters.ip);
  if (filters.kind) query = query.eq("kind", filters.kind);
  if (filters.result) query = query.eq("result", filters.result);
  if (filters.username) query = query.eq("username", filters.username);
  if (filters.from) query = query.gte("time", filters.from);
  if (filters.to) query = query.lte("time", filters.to);
  if (filters.since) query = query.gte("time", filters.since);

  const { data, error } = await query;
  if (error) throw error;
  return (data || []).map(row => ({
    ...row,
    ...(row.geo && typeof row.geo === "object" ? row.geo : {}),
  }));
}

export async function countRecentFailures({ ip, kind = "user", username, windowMs }) {
  let query = supabase.from("events").select("id", { count: "exact", head: true })
    .eq("kind", kind).eq("result", "Failed")
    .gte("time", sinceIso(windowMs));
  if (ip) query = query.eq("source", ip);
  if (username) query = query.eq("username", username);
  const { count, error } = await query;
  if (error) throw error;
  return count || 0;
}

export async function oldestRecentFailure({ ip, kind = "user", username, windowMs }) {
  let query = supabase.from("events").select("time")
    .eq("kind", kind).eq("result", "Failed")
    .gte("time", sinceIso(windowMs)).order("time", { ascending: true }).limit(1);
  if (ip) query = query.eq("source", ip);
  if (username) query = query.eq("username", username);
  const { data, error } = await query;
  if (error) throw error;
  return data?.[0]?.time || null;
}

export async function distinctRecentUsernames(ip, windowMs) {
  const rows = await getEvents({ ip, kind: "user", since: sinceIso(windowMs) }, 1000, false);
  return new Set(rows.map(row => row.username).filter(Boolean)).size;
}

export async function channels() {
  return {
    discord: !!env.DISCORD_WEBHOOK_URL,
    telegram: !!(env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID),
    webhook: !!env.ALERT_WEBHOOK_URL,
  };
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error(`Notification HTTP ${response.status}`);
}

export async function sendAlert(message) {
  const sent = [];
  const jobs = [];
  if (env.DISCORD_WEBHOOK_URL) jobs.push(
    postJson(env.DISCORD_WEBHOOK_URL, { content: message }).then(() => sent.push("Discord"))
  );
  if (env.TELEGRAM_BOT_TOKEN && env.TELEGRAM_CHAT_ID) jobs.push(
    postJson(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
      { chat_id: env.TELEGRAM_CHAT_ID, text: message }).then(() => sent.push("Telegram"))
  );
  if (env.ALERT_WEBHOOK_URL) jobs.push(
    postJson(env.ALERT_WEBHOOK_URL, { text: message }).then(() => sent.push("Webhook"))
  );
  await Promise.allSettled(jobs);
  return sent;
}

export async function maybeAlert(ip, geo = {}) {
  const failures = await countRecentFailures({
    ip, kind: "user", windowMs: CONFIG.alertWindowMs,
  });
  if (failures < CONFIG.alertThreshold) return false;

  const cutoff = sinceIso(CONFIG.alertCooldownMs);
  const { data: prior, error: priorError } = await supabase.from("alerts")
    .select("id").eq("ip", ip).gte("time", cutoff).limit(1);
  if (priorError) throw priorError;
  if (prior?.length) return false;

  const where = [geo.city, geo.country].filter(Boolean).join(", ") || "unknown location";
  const message = `LoginGuard alert: ${ip} (${geo.isp || "unknown ISP"}, ${where}) made ${failures} failed logins in the last ${Math.round(CONFIG.alertWindowMs / 60000)} minutes.`;

  const { data: inserted, error: insertError } = await supabase.from("alerts")
    .insert({ time: new Date().toISOString(), ip, message, sent: "Pending" })
    .select("id").single();
  if (insertError) throw insertError;

  const delivered = await sendAlert(message);
  const { error: updateError } = await supabase.from("alerts")
    .update({ sent: delivered.join(", ") || "dashboard only" }).eq("id", inserted.id);
  if (updateError) throw updateError;
  return true;
}

export function retryAfterSeconds(oldest, windowMs = CONFIG.windowMs) {
  if (!oldest) return Math.ceil(windowMs / 1000);
  return Math.max(1, Math.ceil((Date.parse(oldest) + windowMs - Date.now()) / 1000));
}
