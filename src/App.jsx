import { useEffect, useState } from "react";
import { ShieldCheck, LockKeyhole, Users, Eye, EyeOff, AlertTriangle, ArrowRight, X } from "lucide-react";
import Admin from "./Admin.jsx";
import { api, getToken, setToken } from "./api.js";

export default function App() {
  const [page, setPage] = useState(() => (getToken() ? "admin" : "login"));
  const [loginUser, setLoginUser] = useState("");
  const [loginPass, setLoginPass] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [adminUser, setAdminUser] = useState("");
  const [adminPass, setAdminPass] = useState("");
  const [showAdminPass, setShowAdminPass] = useState(false);
  const [adminMessage, setAdminMessage] = useState("");

  // Log one "visit" per browser session (the server records the visitor's IP, ISP and location).
  useEffect(() => {
    try { if (sessionStorage.getItem("loginguard_visit_logged")) return; sessionStorage.setItem("loginguard_visit_logged", "1"); } catch { /* ignore */ }
    api("/api/visit", { method: "POST" });
  }, []);

  // Admin session ended (idle timeout or server restart).
  useEffect(() => {
    const onExpired = () => { setPage("login"); setMessage("Your admin session has ended. Please sign in again."); };
    window.addEventListener("loginguard:expired", onExpired);
    return () => window.removeEventListener("loginguard:expired", onExpired);
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

  const adminLogin = async (e) => {
    e.preventDefault();
    setBusy(true);
    const r = await api("/api/admin/login", { method: "POST", body: { username: adminUser, password: adminPass } });
    setBusy(false);
    if (r.ok) {
      setToken(r.data.token);
      setAdminMessage(""); setAdminPass("");
      setPage("admin");
    } else {
      setAdminMessage(r.status === 0 ? "Cannot reach the server." : r.data?.error || "Sign-in failed.");
    }
  };

  const signOut = () => { setPage("login"); setMessage(""); setLoginPass(""); setAdminUser(""); setAdminPass(""); };

  if (page === "admin") return <Admin onSignOut={signOut} />;

  return <div className="auth-page">
    <div className="auth-decoration decor-one" /><div className="auth-decoration decor-two" />
    <header className="auth-top"><div className="auth-brand"><div className="logo"><ShieldCheck size={22} /></div><div><b>LoginGuard</b><small>SECURE ACCESS PORTAL</small></div></div><button className="admin-link" onClick={() => { setPage("adminLogin"); setMessage(""); }}>Admin console <ArrowRight size={15} /></button></header>
    <main className="auth-layout">
      <section className="auth-card">
        <div className="card-icon"><LockKeyhole size={22} /></div><h2>Welcome back</h2><p className="card-sub">Sign in to continue to your account</p>
        {message && <div className="form-message error" role="alert"><span><AlertTriangle size={17} /></span>{message}</div>}
        <form onSubmit={attemptLogin} className="auth-form">
          <label htmlFor="loginUser">Username or email</label><div className="field"><Users size={17} /><input id="loginUser" value={loginUser} onChange={e => setLoginUser(e.target.value)} placeholder="you@example.com" required autoComplete="username" /></div>
          <label htmlFor="loginPass">Password</label><div className="field"><LockKeyhole size={17} /><input id="loginPass" type={showPass ? "text" : "password"} value={loginPass} onChange={e => setLoginPass(e.target.value)} placeholder="Enter your password" required autoComplete="current-password" /><button className="eye-btn" type="button" onClick={() => setShowPass(!showPass)} aria-label="Toggle password visibility">{showPass ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>
          <button className="submit-btn" type="submit" disabled={busy}>{busy ? "Signing in…" : <>Sign in securely <ArrowRight size={17} /></>}</button>
        </form>
      </section>
    </main>
    <footer className="auth-footer"><span>© 2026 LoginGuard · Brute Force Detection</span><span><span className="live-dot" /> Monitoring active</span></footer>
    {page === "adminLogin" && <div className="modal-backdrop"><div className="admin-modal"><button className="modal-close" onClick={() => setPage("login")} aria-label="Close"><X size={19} /></button><div className="card-icon"><ShieldCheck size={23} /></div><h2>Administrator access</h2><p className="card-sub">Sign in to view security events and login attempts.</p>
      {adminMessage && <div className="form-message error" role="alert"><AlertTriangle size={17} />{adminMessage}</div>}
      <form onSubmit={adminLogin} className="auth-form"><label htmlFor="adminUser">Admin username</label><div className="field"><Users size={17} /><input id="adminUser" value={adminUser} onChange={e => setAdminUser(e.target.value)} required placeholder="Admin username" autoComplete="username" /></div>
        <label htmlFor="adminPass">Admin password</label><div className="field"><LockKeyhole size={17} /><input id="adminPass" type={showAdminPass ? "text" : "password"} value={adminPass} onChange={e => setAdminPass(e.target.value)} required placeholder="Admin password" autoComplete="current-password" /><button className="eye-btn" type="button" onClick={() => setShowAdminPass(!showAdminPass)} aria-label="Toggle password visibility">{showAdminPass ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>
        <button className="submit-btn" type="submit" disabled={busy}>{busy ? "Checking…" : <>Open dashboard <ArrowRight size={17} /></>}</button></form>
      <div className="demo-note"><span className="info-mini">i</span><span>Every admin sign-in attempt is recorded in the audit log, and repeated failures are rate limited.</span></div></div></div>}
  </div>;
}
