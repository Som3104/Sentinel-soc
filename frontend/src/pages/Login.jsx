import { useState } from "react";
import { Eye, KeyRound, LogIn, ShieldCheck, UserCog } from "lucide-react";
import { apiSend } from "../lib/api";
import { setSession } from "../lib/auth";

// Lab only: the accounts created on first start. Shown so a reviewer can try each role.
const DEMO = [
  { username: "admin", password: "Admin@123", role: "admin", icon: UserCog, what: "Everything, incl. rules, playbooks, ML and users" },
  { username: "analyst", password: "Analyst@123", role: "analyst", icon: ShieldCheck, what: "Triage, contain threats, approve actions, run the lab" },
  { username: "viewer", password: "Viewer@123", role: "viewer", icon: Eye, what: "Read-only: dashboards, incidents, audit log" },
];

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e, creds) => {
    e?.preventDefault();
    const body = creds ?? { username, password };
    if (!body.username || !body.password) return;
    setBusy(true); setError(null);
    try {
      setSession(await apiSend("/api/auth/login", "POST", body));
    } catch (err) {
      setError(err.message === "Failed to fetch" ? "Can't reach the backend on port 8000. Is docker compose up?" : err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-grid flex min-h-full items-center justify-center px-4 py-10">
      <div className="w-full max-w-[400px]">
        <div className="mb-6 flex items-center justify-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-accent/15 ring-1 ring-accent/40">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="var(--color-accent)" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <div>
            <div className="text-lg font-semibold tracking-wide">Sentinel SOC</div>
            <div className="text-xs text-muted">Threat Detection Lab</div>
          </div>
        </div>

        <form onSubmit={submit} className="rounded-xl border border-line bg-panel p-6 shadow-2xl shadow-black/30">
          <h1 className="text-base font-semibold">Sign in</h1>
          <p className="mt-1 text-xs text-muted">Every action you take is recorded in the audit log under your name.</p>

          <label className="mt-5 block">
            <span className="text-xs font-medium text-muted">Username</span>
            <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username"
              className="mt-1 block h-10 w-full rounded-lg border border-line bg-bg px-3 text-sm outline-none focus:border-accent" />
          </label>
          <label className="mt-3 block">
            <span className="text-xs font-medium text-muted">Password</span>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password"
              className="mt-1 block h-10 w-full rounded-lg border border-line bg-bg px-3 text-sm outline-none focus:border-accent" />
          </label>

          {error && <div className="mt-3 rounded-lg border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical">{error}</div>}

          <button type="submit" disabled={busy || !username || !password}
            className="mt-5 flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-accent text-sm font-semibold text-bg transition-opacity hover:opacity-90 disabled:opacity-40">
            <LogIn size={16} /> {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="mt-3 flex items-center gap-1.5 text-[11px] text-faint">
            <KeyRound size={12} /> 5 wrong passwords lock the account for 5 minutes.
          </p>
        </form>

        <div className="mt-5 rounded-xl border border-dashed border-line bg-panel/60 p-4">
          <div className="text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">Demo accounts · lab only</div>
          <div className="mt-2 space-y-1">
            {DEMO.map(({ username: u, password: p, role, icon: Icon, what }) => (
              <button key={u} type="button" disabled={busy} onClick={() => { setUsername(u); setPassword(p); submit(null, { username: u, password: p }); }}
                className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left hover:bg-panel-2 disabled:opacity-50">
                <Icon size={16} className="shrink-0 text-accent" />
                <div className="min-w-0 flex-1">
                  <div className="text-sm"><span className="font-mono">{u}</span> <span className="text-faint">· {role}</span></div>
                  <div className="truncate text-[11px] text-muted">{what}</div>
                </div>
                <span className="font-mono text-[11px] text-faint">{p}</span>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
