import { useEffect, useState } from "react";
import { Loader2, UserPlus } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "../components/ui/dialog";
import { listUsers, createUser, updateUser, getAudit } from "./api";
import { fmtDTm } from "./util";

/** Admin only: users (create, disable, reset password, role) and the audit log. */
export default function Admin({ open, onClose, me }) {
  const [tab, setTab] = useState("users");
  const [users, setUsers] = useState([]);
  const [audit, setAudit] = useState([]);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [nu, setNu] = useState({ username: "", displayName: "", password: "", role: "analyst" });

  const load = async () => {
    setErr("");
    try {
      if (tab === "users") setUsers((await listUsers()).users);
      else setAudit((await getAudit(300)).entries);
    } catch (e) { setErr(e.message); }
  };
  useEffect(() => { if (open) load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [open, tab]);

  const add = async (e) => {
    e.preventDefault();
    setBusy(true); setErr(""); setMsg("");
    try { await createUser(nu); setMsg(`Created ${nu.username}.`); setNu({ username: "", displayName: "", password: "", role: "analyst" }); await load(); }
    catch (ex) { setErr(ex.details?.[0]?.message || ex.message); }
    finally { setBusy(false); }
  };
  const patch = async (u, p, done) => {
    setErr(""); setMsg("");
    try { await updateUser(u.id, p); setMsg(done); await load(); } catch (ex) { setErr(ex.details?.[0]?.message || ex.message); }
  };
  const reset = (u) => {
    const pw = window.prompt(`New password for ${u.username} (at least 12 characters). Their sessions will end.`);
    if (pw) patch(u, { password: pw }, `Password reset for ${u.username}.`);
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="dlg dlg-wide" data-testid="admin-dialog">
        <DialogHeader>
          <DialogTitle className="dlg-title">Admin</DialogTitle>
          <DialogDescription className="dlg-desc">Manage user accounts and review the audit log.</DialogDescription>
        </DialogHeader>
        <div className="seg" role="tablist">
          {[["users", "Users"], ["audit", "Audit log"]].map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} className={`seg-btn ${tab === k ? "on" : ""}`} onClick={() => setTab(k)} data-testid={`admin-tab-${k}`}>{l}</button>)}
        </div>
        {err && <p className="err small" role="alert">{err}</p>}
        {msg && <p className="muted small">{msg}</p>}
        {tab === "users" && (
          <>
            <div className="tbl-wrap admin-scroll">
              <table className="tbl" data-testid="admin-users-table">
                <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last sign-in</th><th></th></tr></thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id}>
                      <td><b>{u.displayName}</b><br /><span className="mono small muted">{u.username}</span></td>
                      <td>
                        <select className="input input-sm" value={u.role} disabled={u.id === me.id} onChange={(e) => patch(u, { role: e.target.value }, `${u.username} is now ${e.target.value}.`)} aria-label="Role">
                          <option value="analyst">analyst</option><option value="admin">admin</option>
                        </select>
                      </td>
                      <td>{u.active ? "Active" : <span className="err">Disabled</span>}</td>
                      <td className="mono small">{u.lastLoginAt ? fmtDTm(u.lastLoginAt) : "—"}</td>
                      <td className="btn-row">
                        <button className="btn btn-xs" onClick={() => reset(u)}>Reset password</button>
                        {u.id !== me.id && <button className="btn btn-xs" onClick={() => patch(u, { active: !u.active }, `${u.username} ${u.active ? "disabled" : "enabled"}.`)}>{u.active ? "Disable" : "Enable"}</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <form className="form-grid" onSubmit={add} data-testid="admin-new-user">
              <label className="field"><span className="field-l">Username</span><input className="input" value={nu.username} onChange={(e) => setNu({ ...nu, username: e.target.value })} autoComplete="off" /></label>
              <label className="field"><span className="field-l">Display name</span><input className="input" value={nu.displayName} onChange={(e) => setNu({ ...nu, displayName: e.target.value })} /></label>
              <label className="field"><span className="field-l">Password (12+ characters)</span><input className="input" type="password" value={nu.password} onChange={(e) => setNu({ ...nu, password: e.target.value })} autoComplete="new-password" /></label>
              <label className="field"><span className="field-l">Role</span>
                <select className="input" value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value })}><option value="analyst">analyst</option><option value="admin">admin</option></select>
              </label>
              <div className="btn-row field-wide"><button className="btn btn-primary" disabled={busy}>{busy ? <Loader2 size={13} className="spin" /> : <UserPlus size={13} />} Create user</button></div>
            </form>
          </>
        )}
        {tab === "audit" && (
          <div className="tbl-wrap admin-scroll">
            <table className="tbl" data-testid="admin-audit-table">
              <thead><tr><th>Time (UTC+08:00)</th><th>User</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
              <tbody>
                {audit.map((a) => (
                  <tr key={a.id}>
                    <td className="mono small">{fmtDTm(a.at)}</td>
                    <td className="small">{a.user || "—"}</td>
                    <td className="mono small">{a.action}</td>
                    <td className="small brk">{a.target}</td>
                    <td className="mono small brk muted">{a.details ? JSON.stringify(a.details) : ""}</td>
                  </tr>
                ))}
                {!audit.length && <tr><td colSpan={5} className="muted">No entries.</td></tr>}
              </tbody>
            </table>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
