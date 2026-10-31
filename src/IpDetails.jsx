import { useEffect, useRef, useState } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { X, ExternalLink, Ban, ShieldCheck, AlertTriangle } from "lucide-react";
import { api, formatDate } from "./api.js";

const STATUSES = ["New", "Investigating", "False alarm", "Resolved"];

function ipType(ip) { return ip.includes(":") ? "IPv6" : /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? "IPv4" : "Unknown"; }

function ipDecimal(ip) {
  try {
    if (ipType(ip) === "IPv4") return String(ip.split(".").reduce((n, o) => n * 256 + Number(o), 0));
    if (ipType(ip) === "IPv6") {
      const [head, tail = ""] = ip.split("::");
      const h = head ? head.split(":") : [], t = tail ? tail.split(":") : [];
      const groups = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
      return groups.reduce((n, g) => (n << 16n) + BigInt(parseInt(g || "0", 16)), 0n).toString();
    }
  } catch { /* fall through */ }
  return "—";
}

function MiniMap({ lat, lon }) {
  const el = useRef(null);
  useEffect(() => {
    const map = L.map(el.current, { zoomControl: true, scrollWheelZoom: false }).setView([lat, lon], 9);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", { attribution: "&copy; OpenStreetMap contributors", maxZoom: 18 }).addTo(map);
    L.circleMarker([lat, lon], { radius: 9, color: "#fff", weight: 3, fillColor: "#e5484d", fillOpacity: 1 }).addTo(map);
    return () => map.remove();
  }, [lat, lon]);
  return <div ref={el} className="ipd-map" />;
}

export default function IpDetails({ ip, onClose, onChanged }) {
  const [d, setD] = useState(null);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("New");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState("");

  const load = async () => {
    const r = await api(`/api/admin/ip?ip=${encodeURIComponent(ip)}`, { admin: true });
    if (!r.ok) { setError(r.status === 0 ? "Cannot reach the server." : "Could not load details."); return; }
    setD(r.data);
    setStatus(r.data.note?.status || "New");
    setNote(r.data.note?.note || "");
  };
  useEffect(() => { load(); }, [ip]);
  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const toggleBlock = async () => {
    if (!d) return;
    setBusy(true);
    if (d.blocked) await api(`/api/admin/block?ip=${encodeURIComponent(ip)}`, { method: "DELETE", admin: true });
    else await api("/api/admin/block", { method: "POST", admin: true, body: { ip, reason: note || "Blocked from IP details" } });
    await load(); onChanged?.(); setBusy(false);
  };
  const saveNote = async () => {
    setBusy(true);
    await api("/api/admin/note", { method: "PUT", admin: true, body: { ip, status, note } });
    setSaved("Saved"); setTimeout(() => setSaved(""), 1800);
    await load(); onChanged?.(); setBusy(false);
  };

  const g = d?.geo || {};
  const hasGeo = typeof g.lat === "number" && typeof g.lon === "number";
  const rows = [
    ["IP address", ip], ["Decimal", ipDecimal(ip)], ["Type", ipType(ip)], ["ASN", g.asn], ["ISP", g.isp], ["Organization", g.org],
    ["Domain", g.domain], ["Country", g.country], ["Region", g.region], ["City", g.city], ["Postal", g.postal],
    ["Latitude", hasGeo ? g.lat : ""], ["Longitude", hasGeo ? g.lon : ""], ["Timezone", g.timezone]
  ];

  return <div className="modal-backdrop" onClick={onClose}>
    <div className="ipd-modal" onClick={e => e.stopPropagation()} role="dialog" aria-label={`IP details for ${ip}`}>
      <button className="modal-close" onClick={onClose} aria-label="Close"><X size={19} /></button>
      <h2>IP details for <span>{ip}</span></h2>
      {error && <div className="form-message error"><AlertTriangle size={17} />{error}</div>}
      {!d && !error && <p className="ipd-note">Loading…</p>}
      {d && <>
        <div className="ipd-flags">
          {d.blocked && <span className="chip bad"><Ban size={12} /> Blocked</span>}
          {g.proxy && <span className="chip warn">VPN / proxy / Tor</span>}
          {g.hosting && <span className="chip warn">Data center</span>}
          {g.mobile && <span className="chip">Mobile network</span>}
          {d.patterns.spraying && <span className="chip bad">Password spraying ({d.usernames.length} usernames)</span>}
          {d.patterns.targeted && <span className="chip bad">Targeted brute force</span>}
          {!d.blocked && !g.proxy && !g.hosting && !d.patterns.spraying && !d.patterns.targeted && <span className="chip ok"><ShieldCheck size={12} /> No threat flags</span>}
        </div>

        <div className="ipd-body">
          <dl className="ipd-list">{rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v || "—"}</dd></div>)}</dl>
          <div className="ipd-side">
            {hasGeo
              ? <><MiniMap lat={g.lat} lon={g.lon} /><a className="ipd-link" href={`https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=10/${g.lat}/${g.lon}`} target="_blank" rel="noreferrer">View larger map <ExternalLink size={13} /></a></>
              : <div className="ipd-nomap">No map available. Local and private addresses have no location.</div>}
          </div>
        </div>

        <h3 className="ipd-h">Activity from this IP</h3>
        <div className="ipd-stats">
          <div><b>{d.total}</b><span>events</span></div>
          <div><b>{d.failed}</b><span>failed logins</span></div>
          <div><b>{d.first ? formatDate(d.first) : "—"}</b><span>first seen</span></div>
          <div><b>{d.last ? formatDate(d.last) : "—"}</b><span>last seen</span></div>
        </div>
        {d.usernames.length > 0 && <div className="ipd-users"><span>Usernames tried:</span>{d.usernames.map(u => <em key={u.username}>{u.username} <b>×{u.count}</b></em>)}</div>}
        <div className="ipd-history">
          <table><thead><tr><th>TIME</th><th>EVENT</th><th>USERNAME</th><th>REASON</th></tr></thead>
            <tbody>{d.events.slice(0, 30).map(e => <tr key={e.id}><td>{formatDate(e.time)}</td><td>{e.kind === "visit" ? "Visited" : e.kind === "admin" ? `Admin ${e.result}` : e.result}</td><td>{e.username}</td><td>{e.reason}</td></tr>)}</tbody></table>
        </div>

        <h3 className="ipd-h">Investigation</h3>
        <div className="ipd-notes">
          <select value={status} onChange={e => setStatus(e.target.value)} aria-label="Investigation status">{STATUSES.map(s => <option key={s}>{s}</option>)}</select>
          <textarea value={note} onChange={e => setNote(e.target.value)} placeholder="Add a note about this IP…" maxLength={1000} rows={2} />
          <div className="ipd-actions">
            <button className="outline-btn light" onClick={saveNote} disabled={busy}>{saved || "Save status & note"}</button>
            <button className={`solid-btn ${d.blocked ? "neutral" : "danger"}`} onClick={toggleBlock} disabled={busy}>{d.blocked ? <><ShieldCheck size={15} /> Unblock this IP</> : <><Ban size={15} /> Block this IP</>}</button>
          </div>
        </div>
      </>}
      <p className="ipd-note">Latitude and longitude are near the center of population and are not precise enough to identify a specific address or individual.</p>
    </div>
  </div>;
}
