import { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { MapPin } from "lucide-react";

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Groups login events by IP and plots each one on a world map.
export function groupByIp(events) {
  const map = new Map();
  for (const ev of events) {
    if (typeof ev.lat !== "number" || typeof ev.lon !== "number") continue;
    const g = map.get(ev.source) || { ip: ev.source, isp: ev.isp, location: ev.location, lat: ev.lat, lon: ev.lon, total: 0, bad: 0, last: ev.time, users: new Set() };
    g.total++;
    if (ev.result === "Failed" || ev.result === "Blocked") g.bad++;
    if (ev.username !== "(visitor)") g.users.add(ev.username);
    if (ev.time > g.last) g.last = ev.time;
    map.set(ev.source, g);
  }
  return [...map.values()];
}

export default function AttackMap({ events, height = 360, onSelect }) {
  const el = useRef(null);
  const mapRef = useRef(null);
  const layerRef = useRef(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  const points = groupByIp(events);

  useEffect(() => {
    const map = L.map(el.current, { worldCopyJump: true, minZoom: 2, zoomControl: true, scrollWheelZoom: false }).setView([20, 10], 2);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap contributors", maxZoom: 18
    }).addTo(map);
    layerRef.current = L.layerGroup().addTo(map);
    mapRef.current = map;
    return () => { map.remove(); mapRef.current = null; };
  }, []);

  useEffect(() => {
    const layer = layerRef.current, map = mapRef.current;
    if (!layer || !map) return;
    layer.clearLayers();
    points.forEach(p => {
      const hostile = p.bad > 0;
      const color = hostile ? "#ff6b81" : "#4ade80";
      const r = Math.min(8 + Math.sqrt(p.total) * 4, 30);
      L.circleMarker([p.lat, p.lon], { radius: r + 8, color, weight: 0, fillColor: color, fillOpacity: 0.15 }).addTo(layer);
      L.circleMarker([p.lat, p.lon], { radius: r, color: "#fff", weight: 2, fillColor: color, fillOpacity: 0.85 })
        .bindPopup(`<div class="map-pop"><b>${esc(p.ip)}</b><span>${esc(p.isp)}</span><span>${esc(p.location)}</span><hr/><span>${p.total} event${p.total > 1 ? "s" : ""} &middot; <b style="color:#ff6b81">${p.bad} failed</b></span><span>Usernames: ${esc([...p.users].slice(0, 4).join(", ") || "—")}</span>${onSelectRef.current ? `<button class="map-pop-btn" data-ip="${esc(p.ip)}">View IP details</button>` : ""}</div>`)
        .on("popupopen", (e) => {
          const btn = e.popup.getElement()?.querySelector(".map-pop-btn");
          if (btn) btn.onclick = () => onSelectRef.current?.(btn.dataset.ip);
        })
        .addTo(layer);
    });
    if (points.length) map.fitBounds(L.latLngBounds(points.map(p => [p.lat, p.lon])).pad(0.4), { maxZoom: 6 });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(points.map(p => [p.ip, p.total, p.bad]))]);

  return <div className="map-wrap" style={{ height }}>
    <div ref={el} className="map-canvas" />
    {!points.length && <div className="map-empty"><MapPin size={22} /><b>No locations to plot yet</b><span>Attempts from public IP addresses will appear here. Local and private addresses (127.0.0.1, 192.168.x.x) have no location.</span></div>}
    <div className="map-legend"><span><i className="lg red" />Failed attempts</span><span><i className="lg green" />No failed logins</span></div>
  </div>;
}
