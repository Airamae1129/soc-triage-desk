import { useState } from "react";
import { AlertCircle, Eye, EyeOff, Loader2, Lock, LogIn, User, WifiOff } from "lucide-react";
import { login } from "./api";

export default function Login({ onDone, offline, Logo }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [caps, setCaps] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const submit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) return setErr("Enter your username and password.");
    setBusy(true); setErr("");
    try {
      const { user } = await login(username.trim(), password);
      setPassword("");
      onDone(user);
    } catch (ex) {
      setErr(ex.message || "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  };
  const capsCheck = (e) => setCaps(!!e.getModifierState?.("CapsLock"));
  return (
    <div className="login-wrap" data-testid="login-screen">
      <main className="login-main">
        <form className="login-card" onSubmit={submit} noValidate aria-labelledby="login-title">
          <div className="login-brand">
            <span className="login-mark">{Logo && <Logo />}</span>
            <h1 id="login-title" className="login-title">SOC Triage Playbook</h1>
            <p className="login-sub">Sign in to continue to the analyst console</p>
            <p className="login-credit">Created by Aira Mae Bugay</p>
          </div>

          {offline && <p className="login-alert" data-testid="login-offline"><WifiOff size={15} /> Can't reach the server. Check that it is running.</p>}

          <label className="login-field">
            <span className="field-l">Username</span>
            <span className="login-input">
              <User size={16} aria-hidden="true" />
              <input autoComplete="username" autoFocus spellCheck={false} autoCapitalize="none" placeholder="e.g. jdoe"
                value={username} onChange={(e) => { setUsername(e.target.value); setErr(""); }} data-testid="login-username" />
            </span>
          </label>

          <label className="login-field">
            <span className="field-l">Password</span>
            <span className="login-input">
              <Lock size={16} aria-hidden="true" />
              <input type={show ? "text" : "password"} autoComplete="current-password" placeholder="Your password"
                value={password} onChange={(e) => { setPassword(e.target.value); setErr(""); }}
                onKeyDown={capsCheck} onKeyUp={capsCheck} onBlur={() => setCaps(false)} data-testid="login-password" />
              <button type="button" className="login-eye" onClick={() => setShow((s) => !s)}
                aria-label={show ? "Hide password" : "Show password"} aria-pressed={show} data-testid="login-toggle-password">
                {show ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </span>
            {caps && <span className="login-hint" data-testid="login-capslock">Caps Lock is on</span>}
          </label>

          {err && <p className="login-alert" role="alert" data-testid="login-error"><AlertCircle size={15} /> {err}</p>}

          <button className="login-submit" disabled={busy} data-testid="login-submit">
            {busy ? <Loader2 size={16} className="spin" /> : <LogIn size={16} />} {busy ? "Signing in…" : "Sign in"}
          </button>

          <p className="login-help">Need an account or a password reset? Ask your admin.</p>
        </form>
        <p className="login-foot">Authorized personnel only · All activity is audited</p>
      </main>
    </div>
  );
}
