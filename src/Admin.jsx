import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ShieldCheck, ShieldAlert, LockKeyhole, LayoutDashboard, Activity, LogOut, Search, RefreshCw,
  AlertTriangle, XCircle, Clock3, Globe, ArrowRight, Menu, X, Moon, Sun, Ban, Bell, Eye, CheckCircle2
} from "lucide-react";
import AttackMap, { groupByIp } from "./AttackMap.jsx";
import IpDetails from "./IpDetails.jsx";
import { TimelineChart, BarList } from "./charts.jsx";
import { api, formatDate } from "./api.js";

const TABS = ["Overview", "Threat map", "Login activity", "Blocked IPs", "Alerts"];
const TAB_ICONS = { "Overview": LayoutDashboard, "Threat map": Globe, "Login activity": Activity, "Blocked IPs": Ban, "Alerts": Bell };
const RANGES = [["24h", "24 hours"], ["7d", "7 days"], ["30d", "30 days"], ["all", "All time"], ["custom", "Custom"]];
const FILTERS = ["All", "Failed", "Blocked", "Suspicious", "Visits", "Admin portal"];
const PAGE_SIZE = 15;
const HOUR = 3_600_000;

function rangeParams(range, from, to) {
  const now = Date.now();
  if (range === "24h") return { from: new Date(now - 24 * HOUR).toISOString() };
  if (range === "7d") return { from: new Date(now - 7 * 24 * HOUR).toISOString() };
  if (range === "30d") return { from: new Date(now - 30 * 24 * HOUR).toISOString() };
  if (range === "custom") {
    const p = {};
    if (from) p.from = new Date(`${from}T00:00:00`).toISOString();
    if (to) p.to = new Date(`${to}T23:59:59.999`).toISOString();
    return p;
  }
  return {};
}

const resultLabel = (ev) => ev.result === "Visit" ? "Visited" : ev.result;
const csvCell = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`; return `"${s.replaceAll('"', '""')}"`; };

export default function Admin({ onSignOut }) {
  const [tab, setTab] = useState("Overview");
  const [mobileMenu, setMobileMenu] = useState(false);
  const [dark, setDark] = useState(() => { try { const t = localStorage.getItem("loginguard_theme"); return t ? t === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches; } catch { return false; } });
  const [range, setRange] = useState("24h");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [events, setEvents] = useState([]);
  const [stats, setStats] = useState(null);
  const [meta, setMeta] = useState({ blocked: [], notes: {}, alerts: [], channels: {}, config: {} });
  const [loading, setLoading] = useState(false);
  const [offline, setOffline] = useState(false);
  const [filter, setFilter] = useState("All");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [selectedIp, setSelectedIp] = useState(null);
  const [blockIp, setBlockIp] = useState("");
  const [blockReason, setBlockReason] = useState("");
  const [testMsg, setTestMsg] = useState("");

  useEffect(() => { try { localStorage.setItem("loginguard_theme", dark ? "dark" : "light"); } catch { /* ignore */ } }, [dark]);

  const load = useCallback(async (poll = false) => {
    if (!poll) setLoading(true);
    const p = new URLSearchParams(rangeParams(range, from, to));
    const withTz = new URLSearchParams(p); withTz.set("tz", String(new Date().getTimezoneOffset()));
    const [e, s, m] = await Promise.all([
      api(`/api/admin/events?${p}`, { admin: true, poll }),
      api(`/api/admin/stats?${withTz}`, { admin: true, poll }),
      api("/api/admin/meta", { admin: true, poll })
    ]);
    setOffline(e.status === 0);
    if (e.ok) setEvents(e.data);
    if (s.ok) setStats(s.data);
    if (m.ok) setMeta(m.data);
    setLoading(false);
  }, [range, from, to]);

  useEffect(() => {
    load();
    const t = setInterval(() => { if (!document.hidden) load(true); }, 5000);
    return () => clearInterval(t);
  }, [load]);

  // Real user activity keeps the admin session alive (the idle timeout is enforced on the server).
  useEffect(() => {
    let last = 0;
    const touch = () => { if (Date.now() - last > 60_000) { last = Date.now(); api("/api/admin/ping", { method: "POST", admin: true }); } };
    const evs = ["mousemove", "keydown", "click", "scroll"];
    evs.forEach(e => window.addEventListener(e, touch, { passive: true }));
    return () => evs.forEach(e => window.removeEventListener(e, touch));
  }, []);

  const blockedSet = useMemo(() => new Set(meta.blocked.map(b => b.ip)), [meta.blocked]);

  const filteredEvents = useMemo(() => {
    const ql = query.toLowerCase();
    return events.filter(ev => {
      const okFilter = filter === "All" ? true
        : filter === "Failed" ? ev.result === "Failed"
        : filter === "Blocked" ? ev.result === "Blocked"
        : filter === "Suspicious" ? ev.risk === "Suspicious"
        : filter === "Visits" ? ev.kind === "visit"
        : ev.kind === "admin";
      return okFilter && (!ql || [ev.username, ev.result, ev.reason, ev.risk, ev.source, ev.isp, ev.org, ev.asn, ev.location].some(v => String(v ?? "").toLowerCase().includes(ql)));
    });
  }, [events, filter, query]);
  useEffect(() => { setPage(1); }, [filter, query, range, from, to]);
  const pages = Math.max(1, Math.ceil(filteredEvents.length / PAGE_SIZE));
  const pageEvents = filteredEvents.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const suspicious = events.filter(e => e.risk === "Suspicious");
  const t = stats?.totals || { attempts: 0, failed: 0, suspicious: 0, visits: 0, uniqueIps: 0 };

  const clearLogs = async () => {
    if (!window.confirm("Delete ALL login records from the database? This cannot be undone.")) return;
    await api("/api/admin/events", { method: "DELETE", admin: true });
    load();
  };
  const exportCSV = () => {
    const head = ["Time", "Type", "Username", "Result", "Reason", "Risk", "IP", "ISP", "Organization", "ASN", "Country", "Region", "City", "Flags"];
    const rows = filteredEvents.map(e => [e.time, e.kind, e.username, e.result, e.reason, e.risk, e.source, e.isp, e.org, e.asn, e.country, e.region, e.city, [e.proxy && "VPN/proxy", e.hosting && "data center"].filter(Boolean).join(" ")]);
    const blob = new Blob([[head, ...rows].map(r => r.map(csvCell).join(",")).join("\n")], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = "loginguard-audit-log.csv"; a.click();
    URL.revokeObjectURL(url);
  };
  const toggleBlock = async (ip, isBlocked) => {
    if (isBlocked) await api(`/api/admin/block?ip=${encodeURIComponent(ip)}`, { method: "DELETE", admin: true });
    else await api("/api/admin/block", { method: "POST", admin: true, body: { ip, reason: "Blocked from dashboard" } });
    load(true);
  };
  const addBlock = async (e) => {
    e.preventDefault();
    if (!blockIp.trim()) return;
    await api("/api/admin/block", { method: "POST", admin: true, body: { ip: blockIp.trim(), reason: blockReason } });
    setBlockIp(""); setBlockReason(""); load(true);
  };
  const testAlert = async () => {
    setTestMsg("Sending…");
    const r = await api("/api/admin/test-alert", { method: "POST", admin: true });
    setTestMsg(r.ok ? (r.data.sent.length ? `Delivered via ${r.data.sent.join(", ")}.` : "No alert channel is configured yet. Add one in your .env file.") : "Could not send.");
  };
  const signOut = async () => { await api("/api/admin/logout", { method: "POST", admin: true }); onSignOut(); };
  const select = (ip) => setSelectedIp(ip);

  const RangeBar = <div className="range-bar" role="group" aria-label="Date range">
    {RANGES.map(([k, l]) => <button key={k} className={range === k ? "on" : ""} onClick={() => setRange(k)}>{l}</button>)}
    {range === "custom" && <span className="range-custom"><input type="date" value={from} max={to || undefined} onChange={e => setFrom(e.target.value)} aria-label="From date" /> to <input type="date" value={to} min={from || undefined} onChange={e => setTo(e.target.value)} aria-label="To date" /></span>}
  </div>;

  return <div className={`admin-shell ${dark ? "dark" : ""}`}>
    <aside className={`sidebar ${mobileMenu ? "open" : ""}`}>
      <div className="side-brand"><div className="logo"><ShieldCheck size={22} /></div><div><b>Vigilix</b><small>SECURITY CONSOLE</small></div><button className="mobile-close" onClick={() => setMobileMenu(false)} aria-label="Close menu"><X /></button></div>
      <div className="nav-label">MONITORING</div>
      {TABS.map(name => { const Icon = TAB_ICONS[name]; return <button key={name} className={`nav-item ${tab === name ? "selected" : ""}`} onClick={() => { setTab(name); setMobileMenu(false); }}>
        <Icon size={18} /><span>{name}</span>
        {name === "Login activity" && t.failed > 0 && <em>{t.failed}</em>}
        {name === "Blocked IPs" && meta.blocked.length > 0 && <em>{meta.blocked.length}</em>}
        {name === "Alerts" && meta.alerts.length > 0 && <em>{meta.alerts.length}</em>}
      </button>; })}
      <div className="side-bottom"><div className="admin-profile"><div className="avatar">A</div><div><b>Administrator</b><small>Admin account</small></div><span className="online-dot" /></div><button className="nav-item logout" onClick={signOut}><LogOut size={18} /> <span>Sign out</span></button></div>
    </aside>

    <main className="admin-main">
      <header className="admin-top"><button className="menu-btn" onClick={() => setMobileMenu(true)} aria-label="Open menu"><Menu /></button><div><span className="crumb">Security console</span><span className="crumb-sep">/</span><b>{tab}</b></div>
        <div className="top-right"><span className={offline ? "dead-dot" : "live-dot"} /> {offline ? "Server unreachable" : "Monitoring active"}
          <button className="theme-btn" onClick={() => setDark(!dark)} aria-label={dark ? "Switch to light mode" : "Switch to dark mode"} title={dark ? "Light mode" : "Dark mode"}>{dark ? <Sun size={16} /> : <Moon size={16} />}</button>
          <span className="top-avatar">A</span></div></header>

      <div className="dashboard-content">
        <div className="page-heading"><div><div className="eyebrow">SECURITY OVERVIEW</div><h1>{tab}</h1><p>Monitor authentication activity and identify potentially suspicious login behavior.</p></div>
          <div className="heading-actions"><button className="outline-btn" onClick={() => load()}><RefreshCw size={15} className={loading ? "spin" : ""} /> Refresh</button><button className="solid-btn" onClick={exportCSV}>Export CSV</button></div></div>
        {(tab === "Overview" || tab === "Threat map" || tab === "Login activity") && RangeBar}

        {tab === "Overview" && <>
          <div className="welcome-banner"><div className="banner-icon"><ShieldCheck size={26} /></div><div><b>Your security monitor is active</b><p>Visits and login attempts are recorded with the visitor's IP, ISP and location, and appear here within seconds.</p></div><span className="banner-chip">LIVE</span></div>
          <div className="metric-grid">
            <Metric icon={<Activity />} label="Login attempts" value={t.attempts} tone="purple" note={`${t.visits} page visits in this period`} />
            <Metric icon={<XCircle />} label="Failed / blocked" value={t.failed} tone="red" note="Unsuccessful authentication" />
            <Metric icon={<AlertTriangle />} label="Suspicious events" value={t.suspicious} tone="amber" note="Repeated failures / spraying" />
            <Metric icon={<Globe />} label="Unique visitors" value={t.uniqueIps} tone="green" note={`${meta.blocked.length} IP${meta.blocked.length === 1 ? "" : "s"} blocked`} />
          </div>
          <section className="content-card chart-card"><div className="card-head"><div><h2>Activity over time</h2><p>{stats?.bucket === "hour" ? "Events per hour" : "Events per day"}, by type</p></div></div>
            <TimelineChart data={stats?.timeline || []} bucket={stats?.bucket || "hour"} /></section>
          <section className="content-card map-card"><div className="card-head"><div><h2>Login attempts by location</h2><p>Where visitors trying to sign in are connecting from</p></div><button className="text-btn" onClick={() => setTab("Threat map")}>Full map <ArrowRight size={14} /></button></div><AttackMap events={events} height={320} onSelect={select} /></section>
          <div className="dashboard-grid">
            <section className="content-card recent-card"><div className="card-head"><div><h2>Recent activity</h2><p>Latest visits and login attempts</p></div><button className="text-btn" onClick={() => setTab("Login activity")}>View all <ArrowRight size={14} /></button></div><EventsTable events={events.slice(0, 6)} onSelect={select} blockedSet={blockedSet} /></section>
            <section className="content-card alert-card"><div className="card-head"><div><h2>Security alerts</h2><p>Events that may need attention</p></div><span className="alert-count">{suspicious.length}</span></div>
              {suspicious.slice(0, 4).length ? suspicious.slice(0, 4).map(ev => <div className="alert-row" key={ev.id}><div className="alert-symbol"><ShieldAlert size={17} /></div><div className="alert-info"><b>Suspicious login activity</b><span>{ev.username} · {ev.reason}</span><small>{ev.source} · {formatDate(ev.time)}</small></div></div>) : <div className="empty-state"><ShieldCheck size={25} /><b>No suspicious events</b><span>Alerts appear when repeated failed logins are detected.</span></div>}
              <div className="tip-box"><LockKeyhole size={17} /><div><b>Automatic protection</b><span>After {meta.config.maxFails ?? 5} failed attempts within {meta.config.windowSec ?? 60}s, the IP and username are locked out by the server.</span></div></div>
            </section>
          </div>
          <section className="content-card" style={{ marginTop: 20 }}><div className="card-head"><div><h2>Most targeted usernames</h2><p>Usernames attackers tried most often</p></div></div>
            <div className="card-pad"><BarList rows={(stats?.topUsernames || []).map(u => ({ name: u.username, count: u.count, failed: u.failed }))} empty="No login attempts in this period" /></div></section>
        </>}

        {tab === "Threat map" && <>
          <section className="content-card map-card"><div className="card-head"><div><h2>Global login map</h2><p>Each circle is one IP address. Bigger means more events; red means failed logins.</p></div><span className="user-count">{groupByIp(events).length} locations</span></div><AttackMap events={events} height={460} onSelect={select} /></section>
          <section className="content-card activity-page" style={{ marginTop: 20 }}><div className="card-head"><div><h2>Top sources</h2><p>IP addresses ranked by failed attempts, with threat flags</p></div></div>
            <SourcesTable rows={stats?.topIps || []} onSelect={select} blockedSet={blockedSet} notes={meta.notes} onToggleBlock={toggleBlock} /></section>
        </>}

        {tab === "Login activity" && <section className="content-card activity-page"><div className="card-head"><div><h2>Authentication audit log</h2><p>Every visit, login attempt and admin sign-in, with outcome and risk.</p></div><button className="danger-ghost" onClick={clearLogs}>Clear logs</button></div>
          <div className="table-tools"><div className="searchbox"><Search size={16} /><input placeholder="Search username, IP, ISP, location…" value={query} onChange={e => setQuery(e.target.value)} aria-label="Search events" /></div><select value={filter} onChange={e => setFilter(e.target.value)} aria-label="Filter events">{FILTERS.map(f => <option key={f}>{f}</option>)}</select></div>
          <EventsTable events={pageEvents} full onSelect={select} blockedSet={blockedSet} />
          <div className="table-foot"><span>Showing {filteredEvents.length ? (page - 1) * PAGE_SIZE + 1 : 0}–{Math.min(page * PAGE_SIZE, filteredEvents.length)} of {filteredEvents.length} events{events.length >= 5000 ? " (latest 5,000 loaded)" : ""}</span>
            <div className="pager"><button className="outline-btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><span>Page {page} of {pages}</span><button className="outline-btn" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</button></div></div></section>}

        {tab === "Blocked IPs" && <section className="content-card activity-page"><div className="card-head"><div><h2>Blocked IP addresses</h2><p>Blocked visitors can still load the page, but every login attempt is rejected and logged.</p></div><span className="user-count">{meta.blocked.length} blocked</span></div>
          <form className="block-form" onSubmit={addBlock}><input value={blockIp} onChange={e => setBlockIp(e.target.value)} placeholder="IP address, e.g. 203.0.113.7" aria-label="IP address to block" required /><input value={blockReason} onChange={e => setBlockReason(e.target.value)} placeholder="Reason (optional)" aria-label="Reason" maxLength={300} /><button className="solid-btn danger" type="submit"><Ban size={15} /> Block IP</button></form>
          {meta.blocked.length ? <div className="table-scroll"><table><thead><tr><th>IP ADDRESS</th><th>REASON</th><th>BLOCKED</th><th /></tr></thead><tbody>{meta.blocked.map(b => <tr key={b.ip}><td><button className="ip-link" onClick={() => select(b.ip)}>{b.ip}</button></td><td>{b.reason || "—"}</td><td className="time-cell"><Clock3 size={13} />{formatDate(b.time)}</td><td><button className="outline-btn" onClick={() => toggleBlock(b.ip, true)}>Unblock</button></td></tr>)}</tbody></table></div>
            : <div className="empty-state"><ShieldCheck size={26} /><b>No blocked IPs</b><span>Open an IP's details and choose “Block this IP”, or add one above.</span></div>}</section>}

        {tab === "Alerts" && <>
          <section className="content-card activity-page"><div className="card-head"><div><h2>Alert channels</h2><p>Where Vigilix sends a message when an IP crosses the threshold ({meta.config.alertThreshold ?? 10} failures in {meta.config.alertWindowMin ?? 5} min).</p></div></div>
            <div className="channels">{[["discord", "Discord"], ["telegram", "Telegram"], ["webhook", "Webhook (Slack-compatible)"]].map(([k, l]) => <span key={k} className={`chip ${meta.channels[k] ? "ok" : ""}`}>{meta.channels[k] ? <CheckCircle2 size={12} /> : <XCircle size={12} />} {l}: {meta.channels[k] ? "connected" : "not set"}</span>)}</div>
            <div className="card-pad"><button className="outline-btn" onClick={testAlert}><Bell size={15} /> Send test alert</button> {testMsg && <span className="test-msg">{testMsg}</span>}
              <p className="hint">Set <code>DISCORD_WEBHOOK_URL</code>, <code>TELEGRAM_BOT_TOKEN</code> + <code>TELEGRAM_CHAT_ID</code>, or <code>ALERT_WEBHOOK_URL</code> in your <code>.env</code> file, then restart the server. Alerts always appear in the list below.</p></div></section>
          <section className="content-card activity-page" style={{ marginTop: 20 }}><div className="card-head"><div><h2>Alert history</h2><p>Latest 50 alerts</p></div></div>
            {meta.alerts.length ? <div className="table-scroll"><table><thead><tr><th>TIME</th><th>IP ADDRESS</th><th>MESSAGE</th><th>DELIVERED VIA</th></tr></thead><tbody>{meta.alerts.map(a => <tr key={a.id}><td className="time-cell"><Clock3 size={13} />{formatDate(a.time)}</td><td><button className="ip-link" onClick={() => select(a.ip)}>{a.ip}</button></td><td className="wrap">{a.message}</td><td>{a.sent || "—"}</td></tr>)}</tbody></table></div>
              : <div className="empty-state"><Bell size={26} /><b>No alerts yet</b><span>An alert is created when one IP reaches {meta.config.alertThreshold ?? 10} failed logins within {meta.config.alertWindowMin ?? 5} minutes.</span></div>}</section>
        </>}

        <div className="footer-note"><ShieldCheck size={15} /> Vigilix · session signs out after {meta.config.idleMin ?? 15} minutes of inactivity.</div>
      </div>
    </main>
    {selectedIp && <IpDetails ip={selectedIp} onClose={() => setSelectedIp(null)} onChanged={() => load(true)} />}
  </div>;
}

function Metric({ icon, label, value, tone, note }) { return <div className="metric-card"><div className={`metric-icon ${tone}`}>{icon}</div><span>{label}</span><strong>{value.toLocaleString()}</strong><small>{note}</small></div>; }

function FlagChips({ ev, blockedSet }) {
  return <>{blockedSet?.has(ev.source) && <span className="chip bad">Blocked IP</span>}{ev.proxy && <span className="chip warn">VPN/proxy</span>}{ev.hosting && <span className="chip warn">Data center</span>}</>;
}

function EventsTable({ events, full = false, onSelect, blockedSet }) {
  if (!events.length) return <div className="empty-state"><Activity size={25} /><b>No events found</b><span>Visits and login attempts will appear here.</span></div>;
  return <div className="table-scroll"><table><thead><tr><th>USER</th><th>RESULT</th>{full && <th>REASON</th>}<th>IP ADDRESS</th><th>ISP / LOCATION</th><th>TIME</th><th>RISK</th></tr></thead><tbody>
    {events.map(ev => <tr key={ev.id}>
      <td><div className="user-cell"><div className="user-avatar">{(ev.kind === "visit" ? "V" : ev.username.slice(0, 1)).toUpperCase()}</div><b>{ev.kind === "visit" ? "Visitor" : ev.username}</b>{ev.kind === "admin" && <span className="chip">Admin portal</span>}</div></td>
      <td><span className={`result-pill ${ev.result.toLowerCase()}`}>{ev.result === "Success" ? <CheckCircle2 size={13} /> : ev.result === "Visit" ? <Eye size={13} /> : <XCircle size={13} />} {resultLabel(ev)}</span></td>
      {full && <td>{ev.reason}</td>}
      <td><button className="ip-link" onClick={() => onSelect(ev.source)} title="View IP details">{ev.source}</button></td>
      <td className="isp"><b>{ev.isp || "—"}</b>{ev.location && ev.location !== "—" && <small className="sub">{ev.location}</small>}<div className="ip-cell"><FlagChips ev={ev} blockedSet={blockedSet} /></div></td>
      <td className="time-cell"><Clock3 size={13} />{formatDate(ev.time, true)}</td>
      <td><span className={`risk-pill ${ev.risk.toLowerCase()}`}>{ev.risk === "Suspicious" && <AlertTriangle size={12} />} {ev.risk}</span></td>
    </tr>)}</tbody></table></div>;
}

function SourcesTable({ rows, onSelect, blockedSet, notes, onToggleBlock }) {
  if (!rows.length) return <div className="empty-state"><Globe size={25} /><b>No sources yet</b><span>Sources appear once someone visits or tries to sign in.</span></div>;
  return <div className="table-scroll"><table><thead><tr><th>IP ADDRESS</th><th>ISP / LOCATION</th><th>EVENTS</th><th>FAILED</th><th>FLAGS</th><th>STATUS</th><th>LAST SEEN</th><th /></tr></thead><tbody>
    {rows.map(r => { const blocked = blockedSet.has(r.ip); return <tr key={r.ip}>
      <td><button className="ip-link" onClick={() => onSelect(r.ip)} title="View IP details">{r.ip}</button></td>
      <td className="isp"><b>{r.isp || "—"}</b>{r.location && r.location !== "—" && <small className="sub">{r.location}</small>}</td>
      <td>{r.total}</td><td><span className={`result-pill ${r.failed ? "failed" : "success"}`}>{r.failed}</span></td>
      <td><div className="ip-cell">{blocked && <span className="chip bad">Blocked</span>}{r.spraying && <span className="chip bad">Spraying</span>}{r.proxy && <span className="chip warn">VPN/proxy</span>}{r.hosting && <span className="chip warn">Data center</span>}{!blocked && !r.spraying && !r.proxy && !r.hosting && "—"}</div></td>
      <td>{notes[r.ip]?.status || "New"}</td>
      <td className="time-cell"><Clock3 size={13} />{formatDate(r.last, true)}</td>
      <td><button className={`outline-btn ${blocked ? "" : "danger-outline"}`} onClick={() => onToggleBlock(r.ip, blocked)}>{blocked ? "Unblock" : "Block"}</button></td>
    </tr>; })}</tbody></table></div>;
}
