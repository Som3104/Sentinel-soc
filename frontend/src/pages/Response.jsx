import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Ban, Check, Clock, Cpu, Hand, Network, RotateCcw, Server, ShieldBan, ShieldCheck, Timer, X, Zap,
} from "lucide-react";
import { api, apiSend } from "../lib/api";
import { usePolling } from "../lib/usePolling";
import { ACTION_LABEL, CONTAINMENT_KIND, SEVERITY, fmtAgo, fmtNumber, fmtSeconds, parseTs } from "../lib/format";
import { useCan } from "../lib/auth";
import { ActorBadge, Button, ErrorBanner, Panel, Pill, ReadOnlyNote, StatCard, Toggle } from "../components/ui";

const KIND_ICON = { ip: Network, process: Cpu, host: Server };

// ------------------------------------------------------------------ approvals
function Approvals({ pending, onDecide, busy }) {
  if (!pending.length) return null;
  return (
    <Panel title={`Waiting for your approval · ${pending.length}`}
      subtitle="Playbooks proposed these but they're high-impact, so a human decides."
      className="border-medium/50" bodyClass="p-0">
      <div className="divide-y divide-line/60">
        {pending.map((p) => {
          const s = p.incident ? SEVERITY[p.incident.severity] : null;
          return (
            <div key={p.id} className="flex flex-wrap items-center gap-4 px-5 py-3">
              <Hand size={16} className="shrink-0 text-medium" />
              <div className="min-w-0 flex-1">
                <div className="text-sm">
                  <span className="font-medium">{ACTION_LABEL[p.action]}</span>{" "}
                  <span className="font-mono text-accent">{p.target}</span>
                  <span className="ml-2 font-mono text-xs text-faint">{p.playbook_id}</span>
                </div>
                <div className="truncate text-xs text-muted">{p.details.reason}</div>
              </div>
              {p.incident && (
                <Link to={`/incidents/${p.incident.id}`} className="shrink-0 text-xs hover:text-accent">
                  <span className="font-mono text-faint">INC-{p.incident.id}</span>{" "}
                  <span style={{ color: s?.color }}>{Math.round(p.incident.score)}</span>
                </Link>
              )}
              <span className="shrink-0 text-xs text-faint">{fmtAgo(p.created_at)}</span>
              <div className="flex shrink-0 gap-2">
                <Button need="analyst" variant="primary" disabled={busy} onClick={() => onDecide(p.id, "approve")}><Check size={14} /> Approve</Button>
                <Button need="analyst" disabled={busy} onClick={() => onDecide(p.id, "reject")}><X size={14} /> Reject</Button>
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

// ------------------------------------------------------------------ containments
function Containments({ items, onRelease, busy }) {
  const canAct = useCan("analyst");
  const [kind, setKind] = useState("");
  const shown = items.filter((c) => !kind || c.kind === kind);
  return (
    <Panel title="Active containments" subtitle="What the simulated firewall and EDR are enforcing right now" bodyClass="p-0"
      action={
        <div className="flex rounded-lg border border-line bg-panel-2 p-0.5">
          {[["", "All"], ["ip", "IPs"], ["process", "Processes"], ["host", "Hosts"]].map(([k, l]) => (
            <button key={k} onClick={() => setKind(k)}
              className={`rounded-md px-2.5 py-1 text-xs font-medium ${kind === k ? "bg-accent/15 text-accent" : "text-muted hover:text-ink"}`}>{l}</button>
          ))}
        </div>
      }>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
              <th className="py-2.5 pl-5 pr-4 font-medium">Target</th>
              <th className="pr-4 font-medium">Why</th>
              <th className="pr-4 font-medium">By</th>
              <th className="pr-4 text-right font-medium">Stopped</th>
              <th className="pr-4 font-medium">Active</th>
              <th className="pr-5" />
            </tr>
          </thead>
          <tbody>
            {shown.map((c) => {
              const Icon = KIND_ICON[c.kind];
              return (
                <tr key={c.id} className="border-b border-line/50">
                  <td className="py-3 pl-5 pr-4">
                    <div className="flex items-center gap-2">
                      <Icon size={14} className="shrink-0 text-muted" />
                      <span className="break-all font-mono text-xs text-ink">{c.target}</span>
                    </div>
                    <div className="ml-6 text-[11px] text-faint">{CONTAINMENT_KIND[c.kind].text}</div>
                  </td>
                  <td className="max-w-[230px] pr-4">
                    <div className="truncate text-xs text-muted" title={c.reason}>{c.reason}</div>
                    {c.incident_id && <Link to={`/incidents/${c.incident_id}`} className="font-mono text-[11px] text-faint hover:text-accent">INC-{c.incident_id}</Link>}
                  </td>
                  <td className="pr-4"><ActorBadge actor={c.created_by} />{c.playbook_id && <div className="mt-0.5 font-mono text-[11px] text-faint">{c.playbook_id}</div>}</td>
                  <td className="pr-4 text-right" title={c.last_dropped_at ? `last stopped ${fmtAgo(c.last_dropped_at)}` : "nothing stopped yet"}>
                    <div className={`font-mono text-sm ${c.dropped_count ? "text-ok" : "text-faint"}`}>{fmtNumber(c.dropped_count)}</div>
                    <div className="text-[11px] text-faint">events</div>
                  </td>
                  <td className="whitespace-nowrap pr-4 text-xs">
                    <div className="text-muted">since {fmtAgo(c.created_at)}</div>
                    <div className="text-faint">{c.expires_at ? `expires in ${timeUntil(c.expires_at)}` : "no expiry"}</div>
                  </td>
                  <td className="pr-5 text-right">
                    <button disabled={busy || !canAct} onClick={() => onRelease(c)} title={canAct ? "Release (undo this containment)" : "Needs the analyst role"}
                      className="inline-flex h-8 items-center gap-1 rounded-lg border border-line bg-panel-2 px-2.5 text-xs hover:border-accent disabled:opacity-50">
                      <RotateCcw size={12} /> Release
                    </button>
                  </td>
                </tr>
              );
            })}
            {shown.length === 0 && (
              <tr><td colSpan={7} className="py-12 text-center text-sm text-muted">
                <ShieldCheck size={24} className="mx-auto mb-2 text-faint" />Nothing contained right now.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function timeUntil(ts) {
  const ms = parseTs(ts).getTime() - Date.now();
  if (ms <= 0) return "now";
  const h = Math.floor(ms / 3_600_000);
  const m = Math.round((ms % 3_600_000) / 60_000);
  return h ? `${h}h ${m}m` : `${m}m`;
}

// ------------------------------------------------------------------ manual block
function ManualBlock({ onDone }) {
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [hours, setHours] = useState("24");
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await apiSend("/api/response/actions", "POST", {
        action: "block_ip", ip: ip.trim(), reason: reason || "Manual block by analyst", hours: hours ? Number(hours) : null,
      });
      setMsg({ ok: true, text: r.message });
      setIp("");
      setReason("");
      onDone();
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Block an IP manually" subtitle="e.g. from a threat-intel report. Guardrails still apply: try 10.0.0.5 or 8.8.8.8.">
      <form onSubmit={submit} className="space-y-2.5">
        <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="IP address, e.g. 198.51.100.200"
          className="h-9 w-full rounded-lg border border-line bg-panel-2 px-3 font-mono text-sm outline-none placeholder:font-sans placeholder:text-faint focus:border-accent" />
        <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (goes in the audit log)"
          className="h-9 w-full rounded-lg border border-line bg-panel-2 px-3 text-sm outline-none placeholder:text-faint focus:border-accent" />
        <div className="flex gap-2">
          <select value={hours} onChange={(e) => setHours(e.target.value)}
            className="h-9 flex-1 rounded-lg border border-line bg-panel-2 px-3 text-sm outline-none focus:border-accent">
            <option value="1">for 1 hour</option><option value="24">for 24 hours</option>
            <option value="168">for 7 days</option><option value="">permanently</option>
          </select>
          <Button need="analyst" type="submit" variant="danger" disabled={busy || !ip.trim()}><Ban size={14} /> Block</Button>
        </div>
        {msg && <div className={`rounded-md px-3 py-2 text-xs ${msg.ok ? "bg-ok/10 text-ok" : "bg-high/10 text-high"}`}>{msg.text}</div>}
      </form>
    </Panel>
  );
}

// ------------------------------------------------------------------ playbooks
function Playbooks({ playbooks, onChange, busy }) {
  const canEdit = useCan("admin");
  return (
    <Panel title="Playbooks" subtitle="When X happens, do Y. Auto acts instantly; Approval waits for an analyst." bodyClass="p-0">
      <div className="divide-y divide-line/60">
        {playbooks.map((p) => (
          <div key={p.id} className={`px-5 py-4 ${p.enabled ? "" : "opacity-55"}`}>
            <div className="flex items-start gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-faint">{p.id}</span>
                  <span className="font-medium">{p.name}</span>
                  <span className="text-xs text-faint">· ran {p.runs}×</span>
                </div>
                <p className="mt-1 text-xs text-muted">{p.description}</p>
                <div className="mt-2 grid gap-1 text-xs sm:grid-cols-2">
                  <div><span className="text-faint">When: </span>{p.trigger}</div>
                  <div><span className="text-faint">Do: </span>{p.action}</div>
                </div>
              </div>
              <div className="flex shrink-0 flex-col items-end gap-2">
                <Toggle need="admin" checked={p.enabled} disabled={busy} onChange={(v) => onChange(p.id, { enabled: v })} />
                <div className="flex rounded-md border border-line bg-panel-2 p-0.5">
                  {["auto", "approval"].map((m) => (
                    <button key={m} disabled={busy || !p.enabled || !canEdit} title={canEdit ? undefined : "Needs the admin role"} onClick={() => onChange(p.id, { mode: m })}
                      className={`flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium ${p.mode === m ? (m === "auto" ? "bg-accent/20 text-accent" : "bg-medium/20 text-medium") : "text-muted hover:text-ink"}`}>
                      {m === "auto" ? <Zap size={11} /> : <Hand size={11} />}{m === "auto" ? "Auto" : "Approval"}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function Guardrails({ g }) {
  return (
    <Panel title="Guardrails" subtitle="Hard limits automation (and analysts) can't cross">
      <ul className="space-y-2">
        {g.rules.map((r) => (
          <li key={r} className="flex gap-2.5 text-sm"><ShieldCheck size={15} className="mt-0.5 shrink-0 text-ok" />{r}</li>
        ))}
      </ul>
      <div className="mb-1.5 mt-4 text-[10px] uppercase tracking-wider text-faint">Allowlist</div>
      <div className="space-y-1">
        {g.allowlist.map((a) => (
          <div key={a.ip} className="flex justify-between text-xs"><span className="font-mono">{a.ip}</span><span className="text-muted">{a.service}</span></div>
        ))}
      </div>
    </Panel>
  );
}

// ------------------------------------------------------------------ page
export default function Response() {
  const { data: summary, error, refresh: refreshSummary } = usePolling(() => api("/api/response/summary"), 4000);
  const { data: items, refresh: refreshItems } = usePolling(() => api("/api/response/containments"), 4000);
  const { data: pending, refresh: refreshPending } = usePolling(() => api("/api/response/pending"), 4000);
  const { data: playbooks, refresh: refreshPlaybooks } = usePolling(() => api("/api/response/playbooks"), 15000);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const refreshAll = () => Promise.all([refreshSummary(), refreshItems(), refreshPending(), refreshPlaybooks()]);
  const run = async (fn) => {
    setBusy(true);
    setErr(null);
    try { await fn(); } catch (e) { setErr(e.message); } finally { setBusy(false); refreshAll(); }
  };

  const a = summary?.active;
  return (
    <div className="mx-auto max-w-[1400px] space-y-4">
      <ReadOnlyNote need="analyst" what="contain threats or approve actions" />
      <ErrorBanner error={error} />
      {err && <div className="rounded-lg border border-high/40 bg-high/10 px-4 py-2 text-sm text-high">{err}</div>}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Blocked IPs" value={fmtNumber(a?.ip)} sub="simulated firewall" icon={Network} tone="var(--color-critical)" />
        <StatCard label="Quarantined" value={fmtNumber(a?.process)} sub="processes (EDR)" icon={Cpu} tone="var(--color-high)" />
        <StatCard label="Isolated hosts" value={fmtNumber(a?.host)} sub="cut off the network" icon={Server} tone="var(--color-medium)" />
        <StatCard label="Awaiting approval" value={fmtNumber(summary?.pending_approvals)} sub="needs an analyst" icon={Hand} tone="var(--color-medium)" />
        <StatCard label="Attack events stopped" value={fmtNumber(summary?.events_dropped)} sub="dropped by containments" icon={ShieldBan} tone="var(--color-ok)" />
        <StatCard label="Time to contain" value={fmtSeconds(summary?.time_to_contain_s.auto)}
          sub={`automatic · analyst ${fmtSeconds(summary?.time_to_contain_s.analyst)}`} icon={Timer} tone="var(--color-accent)" />
      </div>

      {pending && <Approvals pending={pending} busy={busy}
        onDecide={(id, d) => run(() => apiSend(`/api/response/pending/${id}/${d}`, "POST"))} />}

      <div className="grid items-start gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          {items && <Containments items={items} busy={busy}
            onRelease={(c) => run(() => apiSend(`/api/response/containments/${c.id}/release`, "POST"))} />}
          {playbooks && <Playbooks playbooks={playbooks} busy={busy}
            onChange={(id, body) => run(() => apiSend(`/api/response/playbooks/${id}`, "PATCH", body))} />}
        </div>
        <div className="space-y-4">
          <ManualBlock onDone={refreshAll} />
          {summary && <Guardrails g={summary.guardrails} />}
          <Panel title="Lab reset" subtitle="Lift every containment so you can replay attacks">
            <p className="mb-3 text-xs text-muted">
              Blocked attackers can't attack again, which is the point. To replay a scenario from the simulator, release everything first.
              Each release is written to the <Link to="/audit" className="text-accent hover:underline">audit log</Link>.
            </p>
            <Button need="analyst" disabled={busy || !items?.length} onClick={() => {
              if (window.confirm(`Release all ${items.length} active containments?`)) run(() => apiSend("/api/response/release-all", "POST"));
            }}><RotateCcw size={14} /> Release all ({items?.length ?? 0})</Button>
          </Panel>
          {summary && (
            <Panel title="Last 24 hours">
              <div className="grid grid-cols-3 gap-2 text-center">
                {[["Automatic", summary.last_24h.auto_actions, Zap], ["By analysts", summary.last_24h.analyst_actions, Hand],
                  ["Refused", summary.last_24h.guardrail_blocks, Clock]].map(([l, v, I]) => (
                  <div key={l} className="rounded-lg border border-line bg-panel-2 py-2.5">
                    <I size={14} className="mx-auto text-muted" />
                    <div className="mt-1 font-mono text-lg">{v}</div>
                    <div className="text-[11px] text-muted">{l}</div>
                  </div>
                ))}
              </div>
              <p className="mt-3 text-[11px] text-faint">"Refused" = actions a guardrail stopped. <Pill color="var(--color-muted)">{summary.contained_incidents} incidents contained</Pill></p>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
