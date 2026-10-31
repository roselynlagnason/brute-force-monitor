import { useEffect, useRef, useState } from "react";

// Series colors come from CSS variables (--series-1..3) so light/dark swap in one place (see theme.css).
const SERIES = [
  { key: "visits", label: "Page visits", color: "var(--series-1)" },
  { key: "failed", label: "Failed logins", color: "var(--series-2)" },
  { key: "blocked", label: "Blocked", color: "var(--series-3)" }
];

function useWidth() {
  const ref = useRef(null);
  const [w, setW] = useState(640);
  useEffect(() => {
    if (!ref.current) return;
    const ro = new ResizeObserver(([e]) => setW(Math.max(280, Math.floor(e.contentRect.width))));
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);
  return [ref, w];
}

function label(t, bucket, long = false) {
  // `t` is already shifted into the viewer's timezone by the server, so format it as UTC.
  const d = new Date(t);
  const opts = bucket === "hour"
    ? (long ? { month: "short", day: "numeric", hour: "numeric", timeZone: "UTC" } : { hour: "numeric", timeZone: "UTC" })
    : { month: "short", day: "numeric", timeZone: "UTC" };
  return new Intl.DateTimeFormat(undefined, opts).format(d);
}

// Axis max that gives 4 whole-number gridline steps (1, 2, 5, 10 x 10^k per step).
const niceMax = (n) => { const raw = Math.max(1, n) / 4; const p = 10 ** Math.floor(Math.log10(raw)); return [1, 2, 5, 10].find(k => k * p >= raw) * p * 4; };

export function TimelineChart({ data, bucket }) {
  const [ref, width] = useWidth();
  const [hover, setHover] = useState(null);
  const [table, setTable] = useState(false);
  const H = 240, m = { t: 12, r: 12, b: 28, l: 38 };
  const iw = width - m.l - m.r, ih = H - m.t - m.b;
  const totals = SERIES.map(s => ({ ...s, total: data.reduce((n, d) => n + d[s.key], 0) }));
  const max = niceMax(Math.max(1, ...data.map(d => d.visits + d.failed + d.blocked)));
  const step = iw / Math.max(1, data.length);
  const bw = Math.max(2, Math.min(34, step - 2));
  const y = (v) => m.t + ih - (v / max) * ih;
  const every = Math.ceil(data.length / Math.max(2, Math.floor(iw / 62)));
  const ticks = [0, 1, 2, 3, 4].map(i => (max / 4) * i);
  const empty = totals.every(s => s.total === 0);

  return <div className="chart" ref={ref}>
    <div className="chart-top">
      <div className="legend" role="list">{totals.map(s => <span role="listitem" key={s.key}><i style={{ background: s.color }} />{s.label} <b>{s.total.toLocaleString()}</b></span>)}</div>
      <button className="text-btn" onClick={() => setTable(!table)}>{table ? "Show chart" : "Show table"}</button>
    </div>
    {table ? <div className="table-scroll chart-table"><table><thead><tr><th>{bucket === "hour" ? "HOUR" : "DAY"}</th>{SERIES.map(s => <th key={s.key}>{s.label.toUpperCase()}</th>)}</tr></thead>
      <tbody>{[...data].reverse().map(d => <tr key={d.t}><td>{label(d.t, bucket, true)}</td>{SERIES.map(s => <td key={s.key}>{d[s.key]}</td>)}</tr>)}</tbody></table></div>
    : <div className="chart-plot" onMouseLeave={() => setHover(null)}>
      <svg width={width} height={H} role="img" aria-label="Login activity over time, stacked by page visits, failed logins and blocked attempts">
        {ticks.map(v => <g key={v}><line x1={m.l} x2={width - m.r} y1={y(v)} y2={y(v)} className="grid-line" /><text x={m.l - 8} y={y(v) + 4} textAnchor="end" className="axis-text">{Math.round(v)}</text></g>)}
        {data.map((d, i) => {
          const x = m.l + i * step + (step - bw) / 2;
          let acc = 0;
          return <g key={d.t}>
            {SERIES.map(s => { const v = d[s.key]; if (!v) return null; const y1 = y(acc + v), h = y(acc) - y1; acc += v; return <rect key={s.key} x={x} y={y1} width={bw} height={Math.max(1, h)} rx="3" fill={s.color} stroke="var(--surface)" strokeWidth="2" />; })}
            {i % every === 0 && <text x={x + bw / 2} y={H - 8} textAnchor="middle" className="axis-text">{label(d.t, bucket)}</text>}
            <rect x={m.l + i * step} y={m.t} width={step} height={ih} fill="transparent" onMouseEnter={() => setHover(i)} onFocus={() => setHover(i)} tabIndex={0} aria-label={`${label(d.t, bucket, true)}: ${d.visits} visits, ${d.failed} failed, ${d.blocked} blocked`} />
          </g>;
        })}
        {hover !== null && <rect x={m.l + hover * step} y={m.t} width={step} height={ih} className="hover-band" pointerEvents="none" />}
      </svg>
      {empty && <div className="chart-empty">No activity in this period yet.</div>}
      {hover !== null && <div className="tooltip" style={{ left: Math.min(width - 190, Math.max(0, m.l + hover * step + step / 2 - 90)), top: 4 }}>
        <b>{label(data[hover].t, bucket, true)}</b>
        {SERIES.map(s => <span key={s.key}><i style={{ background: s.color }} />{s.label}<em>{data[hover][s.key]}</em></span>)}
      </div>}
    </div>}
  </div>;
}

export function BarList({ rows, empty }) {
  if (!rows.length) return <div className="empty-state"><b>{empty}</b></div>;
  const max = Math.max(...rows.map(r => r.count));
  return <ul className="barlist">{rows.map(r => <li key={r.name} title={`${r.name}: ${r.count} attempts, ${r.failed} failed`}>
    <span className="bl-name">{r.name}</span>
    <span className="bl-track"><span style={{ width: `${(r.count / max) * 100}%` }} /></span>
    <span className="bl-num">{r.count}</span>
  </li>)}</ul>;
}
