const TOKEN_KEY = "loginguard_admin_token";

export function getToken() { try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; } }
export function setToken(t) { try { sessionStorage.setItem(TOKEN_KEY, t); } catch { /* ignore */ } }
export function clearToken() { try { sessionStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ } }

// Returns { ok, status, data }. status 0 means the server could not be reached.
// A 401 on an admin call clears the token and tells the app the session ended.
export async function api(path, { method = "GET", body, admin = false, poll = false } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (admin) headers.Authorization = `Bearer ${getToken()}`;
  if (poll) headers["X-Poll"] = "1";   // background refresh: does not count as user activity
  try {
    const res = await fetch(path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
    let data = null;
    try { data = await res.json(); } catch { /* empty body */ }
    if (admin && res.status === 401) { clearToken(); window.dispatchEvent(new Event("loginguard:expired")); }
    return { ok: res.ok, status: res.status, data };
  } catch {
    return { ok: false, status: 0, data: null };
  }
}

export function formatDate(value, short = false) {
  try { return new Intl.DateTimeFormat(undefined, short ? { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" } : { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)); }
  catch { return value; }
}
