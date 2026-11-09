import { useEffect, useState } from "react";
import { ShieldCheck, LockKeyhole, Users, Eye, EyeOff, AlertTriangle, ArrowRight } from "lucide-react";
import Admin from "./Admin.jsx";
import { api, getToken, setToken } from "./api.js";

// Standalone admin app: sign-in screen + dashboard. Run with `npm run admin`.
export default function AdminApp() {
  const [signedIn, setSignedIn] = useState(() => !!getToken());
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  // Admin session ended (idle timeout or server restart).
  useEffect(() => {
    const onExpired = () => { setSignedIn(false); setMessage("Your admin session has ended. Please sign in again."); };
    window.addEventListener("loginguard:expired", onExpired);
    return () => window.removeEventListener("loginguard:expired", onExpired);
  }, []);

  const login = async (e) => {
    e.preventDefault();
    setMessage("");
    setBusy(true);
    const r = await api("/api/admin/login", { method: "POST", body: { username: user, password: pass } });
    setBusy(false);
    if (r.ok) { setToken(r.data.token); setPass(""); setSignedIn(true); }
    else setMessage(r.status === 0 ? "Cannot reach the server." : r.data?.error || "Sign-in failed.");
  };

  const signOut = () => { setSignedIn(false); setMessage(""); setUser(""); setPass(""); };

  if (signedIn) return <Admin onSignOut={signOut} />;

  return <div className="auth-page">
    <header className="auth-top"><div className="auth-brand"><div className="logo"><ShieldCheck size={22} /></div><div><b>Vigilix</b><small>ADMIN CONSOLE</small></div></div></header>
    <main className="auth-layout">
      <section className="auth-card">
        <div className="card-icon"><ShieldCheck size={23} /></div><h2>Administrator access</h2><p className="card-sub">Sign in to view security events and login attempts.</p>
        {message && <div className="form-message error" role="alert"><span><AlertTriangle size={17} /></span>{message}</div>}
        <form onSubmit={login} className="auth-form">
          <label htmlFor="adminUser">Admin username</label><div className="field"><Users size={17} /><input id="adminUser" value={user} onChange={e => setUser(e.target.value)} required placeholder="Admin username" autoComplete="username" /></div>
          <label htmlFor="adminPass">Admin password</label><div className="field"><LockKeyhole size={17} /><input id="adminPass" type={showPass ? "text" : "password"} value={pass} onChange={e => setPass(e.target.value)} required placeholder="Admin password" autoComplete="current-password" /><button className="eye-btn" type="button" onClick={() => setShowPass(!showPass)} aria-label="Toggle password visibility">{showPass ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>
          <button className="submit-btn" type="submit" disabled={busy}>{busy ? "Checking…" : <>Open dashboard <ArrowRight size={17} /></>}</button>
        </form>
        <div className="demo-note"><span className="info-mini">i</span><span>Every admin sign-in attempt is recorded in the audit log, and repeated failures are rate limited.</span></div>
      </section>
    </main>
  </div>;
}
