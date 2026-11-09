import { useEffect, useState } from "react";
import { ShieldCheck, LockKeyhole, Users, Eye, EyeOff, AlertTriangle, ArrowRight } from "lucide-react";
import { api } from "./api.js";

// Public login page. The admin console lives in a separate app (admin.html, `npm run admin`).
export default function App() {
  const [loginUser, setLoginUser] = useState("");
  const [loginPass, setLoginPass] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  // Log one "visit" per browser session (the server records the visitor's IP, ISP and location).
  useEffect(() => {
    try { if (sessionStorage.getItem("loginguard_visit_logged")) return; sessionStorage.setItem("loginguard_visit_logged", "1"); } catch { /* ignore */ }
    api("/api/visit", { method: "POST" });
  }, []);

  // Every attempt is sent to the server, which records it and decides the outcome.
  const attemptLogin = async (e) => {
    e.preventDefault();
    setMessage("");
    setBusy(true);
    const r = await api("/api/login", { method: "POST", body: { username: loginUser, password: loginPass } });
    setBusy(false);
    setMessage(r.status === 0 ? "Cannot reach the server. Please try again in a moment." : r.data?.message || "Login failed.");
    setLoginPass("");
  };

  return <div className="auth-page">
    <div className="auth-decoration decor-one" /><div className="auth-decoration decor-two" />
    <header className="auth-top"><div className="auth-brand"><div className="logo"><ShieldCheck size={22} /></div><div><b>Vigilix</b><small>SECURE ACCESS PORTAL</small></div></div></header>
    <main className="auth-layout">
      <section className="auth-card">
        <div className="card-icon"><LockKeyhole size={22} /></div><h2>Welcome back</h2><p className="card-sub">Sign in to continue to your account</p>
        {message && <div className="form-message error" role="alert"><span><AlertTriangle size={17} /></span>{message}</div>}
        <form onSubmit={attemptLogin} className="auth-form">
          <label htmlFor="loginUser">Username or email</label><div className="field"><Users size={17} /><input id="loginUser" value={loginUser} onChange={e => setLoginUser(e.target.value)} placeholder="you@example.com" required autoComplete="username" /></div>
          <label htmlFor="loginPass">Password</label><div className="field"><LockKeyhole size={17} /><input id="loginPass" type={showPass ? "text" : "password"} value={loginPass} onChange={e => setLoginPass(e.target.value)} placeholder="Enter your password" required autoComplete="current-password" /><button className="eye-btn" type="button" onClick={() => setShowPass(!showPass)} aria-label="Toggle password visibility">{showPass ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>
          <button className="submit-btn" type="submit" disabled={busy}>{busy ? "Signing in…" : <>Sign in <ArrowRight size={17} /></>}</button>
        </form>
      </section>
    </main>
    <footer className="auth-footer"><span>© 2026 Vigilix · Brute Force Detection</span><span><span className="live-dot" /> Monitoring active</span></footer>
  </div>;
}
