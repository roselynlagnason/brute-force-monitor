// Local API server. Runs the exact same handler as Vercel (api/[...path].js),
// so local and deployed share one Supabase database and one set of logs.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import handler from "./api/[...path].js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 3001;
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".json": "application/json" };

function readRaw(req) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => { size += c.length; if (size < 1_000_000) chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", () => resolve(""));
  });
}

function serveStatic(res, pathname) {
  const dist = path.join(ROOT, "dist");
  if (!fs.existsSync(dist)) { res.statusCode = 404; return res.end("Not found. Run `npm run build`, or use `npm run dev` for the UI."); }
  let file = path.join(dist, path.normalize(decodeURIComponent(pathname)));
  if (!file.startsWith(dist) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(dist, "index.html");
  res.setHeader("Content-Type", TYPES[path.extname(file)] || "application/octet-stream");
  fs.createReadStream(file).pipe(res);
}

http.createServer(async (req, res) => {
  const { pathname } = new URL(req.url, "http://localhost");
  if (!pathname.startsWith("/api/")) return serveStatic(res, pathname);

  // Minimal Express/Vercel-style helpers expected by the handler.
  res.status = (code) => { res.statusCode = code; return res; };
  res.json = (data) => { if (!res.getHeader("Content-Type")) res.setHeader("Content-Type", "application/json"); res.end(JSON.stringify(data)); return res; };
  const raw = await readRaw(req);
  try { req.body = raw ? JSON.parse(raw) : {}; } catch { req.body = {}; }

  try { await handler(req, res); }
  catch (err) {
    console.error(err);
    if (!res.headersSent) res.status(500).json({ error: "Server error" });
  }
}).listen(PORT, "0.0.0.0", () => console.log(`Vigilix API (Supabase) listening on http://localhost:${PORT}`));
