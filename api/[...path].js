import { supabase } from "../supabase.js";
import {
  CONFIG, str, validIp, readBody, clientIp, checkPassword,
  createSessionToken, createAdminSession, verifyAdminSession, deleteAdminSession,
  recordEvent, updateEventRisk, isBlockedIp, blockIp, unblockIp, saveIpNote,
  getEvents, countRecentFailures, oldestRecentFailure, distinctRecentUsernames,
  channels, sendAlert, maybeAlert, retryAfterSeconds,
} from "../lib/loginguard.js";

const json = (res, status, data) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", "no-store");
  return res.status(status).json(data);
};

function mapEvent(row) {
  const { geo, ...rest } = row;
  return { ...rest, ...(geo && typeof geo === "object" ? geo : {}) };
}

async function getNotesMap() {
  const { data, error } = await supabase.from("notes")
    .select("ip,status,note,updated").limit(5000);
  if (error) throw error;
  const notes = {};
  for (const n of data || []) notes[n.ip] = {
    status: n.status, note: n.note, updated: n.updated,
  };
  return notes;
}

async function buildStats(url) {
  const from = url.searchParams.get("from");
  const to = url.searchParams.get("to");
  const tz = Number(url.searchParams.get("tz")) || 0;
  const rows = await getEvents({ from, to }, 20000, false);

  const totals = {
    attempts: 0, failed: 0, suspicious: 0, visits: 0,
    adminSignins: 0, uniqueIps: 0,
  };
  const ips = new Set();
  const users = new Map();
  const perIp = new Map();

  for (const r of rows) {
    if (r.source) ips.add(r.source);
    if (r.kind === "visit") totals.visits++;
    if (r.kind === "admin" && r.result === "Success") totals.adminSignins++;
    if (r.risk === "Suspicious") totals.suspicious++;
    const bad = r.result === "Failed" || r.result === "Blocked";
    if (bad) totals.failed++;

    if (r.kind === "user") {
      totals.attempts++;
      const u = users.get(r.username) || { username: r.username, count: 0, failed: 0 };
      u.count++;
      if (bad) u.failed++;
      users.set(r.username, u);
    }

    const p = perIp.get(r.source) || {
      ip: r.source, total: 0, failed: 0, usernames: new Set(), last: r.time,
    };
    p.total++;
    if (bad) p.failed++;
    if (r.kind === "user" && r.username) p.usernames.add(r.username);
    if (Date.parse(r.time) > Date.parse(p.last)) p.last = r.time;
    perIp.set(r.source, p);
  }
  totals.uniqueIps = ips.size;

  const now = Date.now();
  const fromMs = from ? Date.parse(from) :
    (rows.length ? Date.parse(rows[rows.length - 1].time) : now - 86400000);
  const toMs = to ? Date.parse(to) : now;
  const hourly = toMs - fromMs <= 48 * 3600000;
  const step = hourly ? 3600000 : 86400000;
  const key = ms => Math.floor((ms - tz * 60000) / step) * step;
  const first = Math.max(key(fromMs), key(toMs) - 119 * step);
  const buckets = new Map();
  for (let t = first; t <= key(toMs); t += step) {
    buckets.set(t, { t, failed: 0, blocked: 0, visits: 0 });
  }
  for (const r of rows) {
    const b = buckets.get(key(Date.parse(r.time)));
    if (!b) continue;
    if (r.result === "Failed") b.failed++;
    else if (r.result === "Blocked") b.blocked++;
    else if (r.kind === "visit") b.visits++;
  }

  const topIps = [...perIp.values()]
    .sort((a, b) => b.failed - a.failed || b.total - a.total)
    .slice(0, 10)
    .map(p => ({
      ip: p.ip, total: p.total, failed: p.failed,
      distinctUsernames: p.usernames.size, last: p.last,
      spraying: p.usernames.size >= 5 && p.failed >= 5,
    }));

  return {
    totals,
    bucket: hourly ? "hour" : "day",
    timeline: [...buckets.values()],
    topUsernames: [...users.values()]
      .sort((a, b) => b.count - a.count).slice(0, 8),
    topIps,
  };
}

async function buildIpDetail(ip) {
  const [events, allRows, blocked, note] = await Promise.all([
    getEvents({ ip }, 200, false),
    getEvents({ ip }, 20000, false),
    isBlockedIp(ip),
    (async () => {
      const { data, error } = await supabase.from("notes")
        .select("status,note,updated").eq("ip", ip).maybeSingle();
      if (error) throw error;
      return data || null;
    })(),
  ]);

  const sorted = [...allRows].sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
  const failed = allRows.filter(r => r.result === "Failed").length;
  const userMap = new Map();
  for (const r of allRows.filter(r => r.kind === "user")) {
    const u = userMap.get(r.username) || { username: r.username, count: 0, failed: 0 };
    u.count++;
    if (r.result === "Failed") u.failed++;
    userMap.set(r.username, u);
  }
  const usernames = [...userMap.values()]
    .sort((a, b) => b.count - a.count).slice(0, 20);

  return {
    ip,
    total: allRows.length,
    first: sorted[0]?.time || null,
    last: sorted.at(-1)?.time || null,
    failed,
    geo: events[0] ? Object.fromEntries(
      ["isp","org","asn","domain","hostname","country","region","city","postal","timezone","location","lat","lon","proxy","hosting","mobile"]
        .filter(k => events[0][k] !== undefined).map(k => [k, events[0][k]])
    ) : {},
    events: events.map(mapEvent),
    usernames,
    blocked,
    note,
    patterns: {
      spraying: usernames.filter(u => u.failed > 0).length >= 5 && failed >= 5,
      targeted: usernames.some(u => u.failed >= 10),
    },
  };
}

export default async function handler(req, res) {
  const url = new URL(req.url, "https://loginguard.local");
  const pathname = url.pathname;
  const method = req.method || "GET";

  try {
    // Temporary health endpoint retained for deployment checks.
    if (method === "GET" && pathname === "/api/health") {
      const { error } = await supabase.from("events").select("id").limit(1);
      if (error) throw error;
      return json(res, 200, {
        success: true,
        message: "Vigilix API is connected to Supabase!",
      });
    }

    // Public: record a page visit.
    if (method === "POST" && pathname === "/api/visit") {
      await recordEvent({
        kind: "visit", username: "(visitor)", result: "Visit",
        reason: "Opened login page", ip: clientIp(req),
      });
      return res.status(204).end();
    }

    // Public: monitored login attempt (the app deliberately never authenticates users).
    if (method === "POST" && pathname === "/api/login") {
      const body = readBody(req);
      const ip = clientIp(req);
      const username = str(body.username).trim().toLowerCase();

      const blocked = await isBlockedIp(ip);
      if (blocked) {
        await recordEvent({
          kind: "user", username, result: "Blocked",
          reason: "IP blocked by administrator", risk: "Suspicious", ip,
        });
        return json(res, 403, {
          message: "Access from your network has been blocked by the administrator.",
        });
      }

      const [byIp, byUser] = await Promise.all([
        countRecentFailures({ ip, kind: "user", windowMs: CONFIG.windowMs }),
        countRecentFailures({ username, kind: "user", windowMs: CONFIG.windowMs }),
      ]);

      if (byIp >= CONFIG.maxFails || byUser >= CONFIG.maxFails) {
        const byIpLimit = byIp >= CONFIG.maxFails;
        const oldest = await oldestRecentFailure({
          ...(byIpLimit ? { ip } : { username }),
          kind: "user", windowMs: CONFIG.windowMs,
        });
        const wait = retryAfterSeconds(oldest);
        await recordEvent({
          kind: "user", username, result: "Blocked",
          reason: byIpLimit ? "Rate limit exceeded (IP)" : "Rate limit exceeded (username)",
          risk: "Suspicious", ip,
        });
        return json(res, 429, {
          message: `Too many failed attempts. Try again in ${wait} seconds.`,
          retryAfter: wait,
        });
      }

      const { id, geo } = await recordEvent({
        kind: "user", username, result: "Failed",
        reason: "Invalid credentials", ip,
      });

      const [recentFails, sprayCount] = await Promise.all([
        countRecentFailures({ ip, kind: "user", windowMs: CONFIG.windowMs }),
        distinctRecentUsernames(ip, CONFIG.distributedWindowMs),
      ]);
      if (recentFails >= 3 || sprayCount >= 4) {
        await updateEventRisk(id, "Suspicious");
      }
      maybeAlert(ip, geo).catch(error =>
        console.error("Alert processing failed:", error.message)
      );

      return json(res, 401, {
        message: "Incorrect username or password. Please try again.",
      });
    }

    // Admin login is public, but attempts are audited and rate limited.
    if (method === "POST" && pathname === "/api/admin/login") {
      const body = readBody(req);
      const ip = clientIp(req);
      const prior = await countRecentFailures({
        ip, kind: "admin", windowMs: CONFIG.adminFailWindowMs,
      });

      if (prior >= 5) {
        await recordEvent({
          kind: "admin", username: str(body.username), result: "Blocked",
          reason: "Admin login rate limit", risk: "Suspicious", ip,
        });
        return json(res, 429, {
          error: "Too many failed admin sign-ins. Try again in 15 minutes.",
        });
      }

      if (
        str(body.username).trim() === CONFIG.adminUser &&
        checkPassword(str(body.password, 500))
      ) {
        const token = createSessionToken();
        await createAdminSession(token);
        await recordEvent({
          kind: "admin", username: CONFIG.adminUser, result: "Success",
          reason: "Admin signed in", ip,
        });
        return json(res, 200, {
          token, idleMinutes: CONFIG.adminIdleMs / 60000,
        });
      }

      await recordEvent({
        kind: "admin", username: str(body.username), result: "Failed",
        reason: "Invalid admin credentials", risk: "Suspicious", ip,
      });
      return json(res, 401, {
        error: "Invalid admin credentials. This attempt has been recorded.",
      });
    }

    if (pathname.startsWith("/api/admin/")) {
      if (!(await verifyAdminSession(req))) {
        return json(res, 401, { error: "Unauthorized" });
      }

      if (method === "POST" && pathname === "/api/admin/ping") {
        return json(res, 200, {});
      }
      if (method === "POST" && pathname === "/api/admin/logout") {
        await deleteAdminSession(req);
        return json(res, 200, {});
      }

      if (method === "GET" && pathname === "/api/admin/events") {
        const limit = Math.min(Number(url.searchParams.get("limit")) || 5000, 20000);
        const rows = await getEvents({
          from: url.searchParams.get("from"),
          to: url.searchParams.get("to"),
        }, limit, false);
        return json(res, 200, rows.map(mapEvent));
      }

      if (method === "DELETE" && pathname === "/api/admin/events") {
        const { error } = await supabase.from("events").delete().not("id", "is", null);
        if (error) throw error;
        return json(res, 200, {});
      }

      if (method === "GET" && pathname === "/api/admin/stats") {
        return json(res, 200, await buildStats(url));
      }

      if (method === "GET" && pathname === "/api/admin/ip") {
        const ip = url.searchParams.get("ip");
        if (!validIp(ip)) return json(res, 400, { error: "Bad IP" });
        return json(res, 200, await buildIpDetail(ip));
      }

      if (method === "GET" && pathname === "/api/admin/meta") {
        const [{ data: blocked, error: blockedError }, notes, { data: alerts, error: alertsError }] =
          await Promise.all([
            supabase.from("blocked").select("*").order("time", { ascending: false }).limit(5000),
            getNotesMap(),
            supabase.from("alerts").select("*").order("id", { ascending: false }).limit(50),
          ]);
        if (blockedError) throw blockedError;
        if (alertsError) throw alertsError;
        return json(res, 200, {
          blocked: blocked || [], notes, alerts: alerts || [],
          channels: await channels(),
          config: {
            maxFails: CONFIG.maxFails,
            windowSec: CONFIG.windowMs / 1000,
            alertThreshold: CONFIG.alertThreshold,
            alertWindowMin: CONFIG.alertWindowMs / 60000,
            idleMin: CONFIG.adminIdleMs / 60000,
          },
        });
      }

      if (method === "POST" && pathname === "/api/admin/block") {
        const body = readBody(req);
        if (!validIp(body.ip)) return json(res, 400, { error: "Bad IP" });
        await blockIp(body.ip, str(body.reason, 300));
        return json(res, 200, {});
      }

      if (method === "DELETE" && pathname === "/api/admin/block") {
        const ip = url.searchParams.get("ip");
        if (!validIp(ip)) return json(res, 400, { error: "Bad IP" });
        await unblockIp(ip);
        return json(res, 200, {});
      }

      if (method === "PUT" && pathname === "/api/admin/note") {
        const body = readBody(req);
        if (!validIp(body.ip)) return json(res, 400, { error: "Bad IP" });
        const status = ["New", "Investigating", "False alarm", "Resolved"].includes(body.status)
          ? body.status : "New";
        await saveIpNote(body.ip, status, str(body.note, 1000));
        return json(res, 200, {});
      }

      if (method === "POST" && pathname === "/api/admin/test-alert") {
        const sent = await sendAlert(
          "Vigilix test alert: your alert channel is working."
        );
        return json(res, 200, { sent });
      }

      return json(res, 404, { error: "Not found" });
    }

    if (pathname.startsWith("/api/")) {
      return json(res, 404, { error: "API route not found." });
    }
    return json(res, 404, { error: "Not found" });
  } catch (error) {
    console.error("Vigilix API error:", error);
    return json(res, 500, { error: "Server error" });
  }
}
