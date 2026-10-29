import { useState } from "react";
import { Check, KeyRound, Lock, Minus, Unlock, UserPlus } from "lucide-react";
import { api, apiSend } from "../lib/api";
import { usePolling } from "../lib/usePolling";
import { useUser } from "../lib/auth";
import { fmtAgo, parseTs } from "../lib/format";
import { Button, ErrorBanner, Panel, Pill, RoleBadge, Toggle } from "../components/ui";

const ROLES = ["viewer", "analyst", "admin"];
const inputCls = "h-9 rounded-lg border border-line bg-bg px-3 text-sm outline-none focus:border-accent";

// ------------------------------------------------------------------ accounts table
function UserRow({ u, me, onSave, busy }) {
  const [resetting, setResetting] = useState(false);
  const [pw, setPw] = useState("");
  const locked = u.locked_until && parseTs(u.locked_until) > new Date();
  const self = u.id === me.id;

  return (
    <>
      <tr className={`border-b border-line/50 ${u.active ? "" : "opacity-55"}`}>
        <td className="py-3 pl-5 pr-4">
          <div className="text-sm font-medium">{u.display_name}{self && <span className="ml-2 text-[11px] text-faint">(you)</span>}</div>
          <div className="font-mono text-xs text-muted">{u.username}</div>
        </td>
        <td className="pr-4">
          <select value={u.role} disabled={busy || self} title={self ? "You can't change your own role" : undefined}
            onChange={(e) => onSave(u.id, { role: e.target.value })} className={`${inputCls} h-8 text-xs`}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </td>
        <td className="pr-4">
          {locked ? <Pill color="var(--color-high)"><Lock size={11} /> locked {fmtAgo(u.locked_until).replace(" ago", "")}</Pill>
            : u.active ? <Pill color="var(--color-ok)">active</Pill> : <Pill color="var(--color-muted)">disabled</Pill>}
        </td>
        <td className="pr-4 text-xs text-muted">{u.last_login ? fmtAgo(u.last_login) : <span className="text-faint">never</span>}</td>
        <td className="pr-5">
          <div className="flex items-center justify-end gap-2">
            {locked && <Button disabled={busy} onClick={() => onSave(u.id, { unlock: true })}><Unlock size={13} /> Unlock</Button>}
            <Button disabled={busy} onClick={() => setResetting((r) => !r)}><KeyRound size={13} /> Reset password</Button>
            <span title={self ? "You can't disable yourself" : u.active ? "Disable account" : "Enable account"}>
              <Toggle checked={u.active} disabled={busy || self} onChange={(v) => onSave(u.id, { active: v })} />
            </span>
          </div>
        </td>
      </tr>
      {resetting && (
        <tr className="border-b border-line/50 bg-panel-2/40">
          <td colSpan={5} className="px-5 py-3">
            <form className="flex flex-wrap items-center gap-2" onSubmit={async (e) => {
              e.preventDefault();
              if (await onSave(u.id, { password: pw })) { setPw(""); setResetting(false); }
            }}>
              <span className="text-xs text-muted">New password for <span className="font-mono text-ink">{u.username}</span>:</span>
              <input type="password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="at least 8 characters"
                autoComplete="new-password" className={`${inputCls} w-56`} />
              <Button type="submit" variant="primary" disabled={busy || pw.length < 8}>Set password</Button>
              <Button onClick={() => setResetting(false)}>Cancel</Button>
            </form>
          </td>
        </tr>
      )}
    </>
  );
}

// ------------------------------------------------------------------ add user
function AddUser({ onCreate, busy }) {
  const empty = { username: "", display_name: "", role: "analyst", password: "" };
  const [f, setF] = useState(empty);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value });
  const valid = /^[a-zA-Z0-9_.-]{3,}$/.test(f.username) && f.display_name.trim() && f.password.length >= 8;
  return (
    <Panel title="Add a user" subtitle="New analysts start with the role you pick here. Passwords need at least 8 characters.">
      <form className="grid gap-3 sm:grid-cols-2" onSubmit={async (e) => {
        e.preventDefault();
        if (await onCreate(f)) setF(empty);
      }}>
        <input value={f.username} onChange={set("username")} placeholder="username (e.g. neha)" className={inputCls} />
        <input value={f.display_name} onChange={set("display_name")} placeholder="Full name" className={inputCls} />
        <select value={f.role} onChange={set("role")} className={inputCls}>
          {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <input type="password" value={f.password} onChange={set("password")} placeholder="Temporary password"
          autoComplete="new-password" className={inputCls} />
        <div className="sm:col-span-2">
          <Button type="submit" variant="primary" disabled={busy || !valid}><UserPlus size={14} /> Create user</Button>
        </div>
      </form>
    </Panel>
  );
}

// ------------------------------------------------------------------ permission matrix
function Permissions({ data }) {
  if (!data) return null;
  const rank = Object.fromEntries(data.roles.map((r, i) => [r, i]));
  return (
    <Panel title="What each role can do"
      subtitle="Enforced by the API on every request (auth/permissions.py). Routes not listed need admin to change anything: secure by default."
      bodyClass="p-0">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-sm">
          <thead>
            <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
              <th className="py-2.5 pl-5 pr-4 font-medium">Permission</th>
              {data.roles.map((r) => <th key={r} className="w-24 pr-4 text-center font-medium">{r}</th>)}
            </tr>
          </thead>
          <tbody>
            {data.policy.map((p) => (
              <tr key={`${p.method} ${p.path}`} className="border-b border-line/50">
                <td className="py-2 pl-5 pr-4">
                  <div>{p.what}</div>
                  <div className="font-mono text-[11px] text-faint">{p.method} {p.path}</div>
                </td>
                {data.roles.map((r) => (
                  <td key={r} className="pr-4 text-center">
                    {rank[r] >= rank[p.role]
                      ? <Check size={15} className="inline text-ok" />
                      : <Minus size={15} className="inline text-faint" />}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

// ------------------------------------------------------------------ page
export default function Users() {
  const me = useUser();
  const { data: users, error, refresh } = usePolling(() => api("/api/users"), 15000);
  const { data: perms } = usePolling(() => api("/api/auth/permissions"), 300000);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);
  const [notice, setNotice] = useState(null);

  const run = async (fn, okText) => {
    setBusy(true); setActionError(null); setNotice(null);
    try {
      await fn();
      setNotice(okText);
      return true;
    } catch (e) {
      setActionError(e.message);
      return false;
    } finally {
      setBusy(false);
      refresh();
    }
  };

  const save = (id, body) => run(() => apiSend(`/api/users/${id}`, "PATCH", body),
    body.password ? "Password reset. Share it with the user securely." : "Saved.");
  const create = (f) => run(() => apiSend("/api/users", "POST", f), `Created ${f.username}.`);

  return (
    <div className="mx-auto max-w-[1400px] space-y-6">
      <ErrorBanner error={error || actionError} />
      <p className="text-sm text-muted">
        Who can sign in, and what they're allowed to do. Every change here is written to the audit log.
        {notice && <span className="ml-2 text-ok">{notice}</span>}
      </p>

      <Panel title={`Accounts · ${users?.length ?? 0}`} bodyClass="p-0">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px]">
            <thead>
              <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                <th className="py-2.5 pl-5 pr-4 font-medium">User</th>
                <th className="pr-4 font-medium">Role</th>
                <th className="pr-4 font-medium">Status</th>
                <th className="pr-4 font-medium">Last sign-in</th>
                <th className="pr-5 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users?.map((u) => <UserRow key={u.id} u={u} me={me} onSave={save} busy={busy} />)}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <div className="space-y-6">
          <AddUser onCreate={create} busy={busy} />
          <Panel title="Roles">
            <div className="space-y-3 text-sm">
              <div className="flex gap-3"><RoleBadge role="viewer" /><span className="text-muted">Read-only. For managers, auditors, new joiners shadowing the team.</span></div>
              <div className="flex gap-3"><RoleBadge role="analyst" /><span className="text-muted">Day-to-day SOC work: triage, containment, approvals, running the lab.</span></div>
              <div className="flex gap-3"><RoleBadge role="admin" /><span className="text-muted">Changes how the SOC behaves: rules, playbooks, ML, accounts. Keep this list short.</span></div>
            </div>
          </Panel>
        </div>
        <Permissions data={perms} />
      </div>
    </div>
  );
}
