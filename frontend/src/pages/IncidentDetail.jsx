import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis } from "recharts";
import {
  ArrowLeft, Brain, Check, CheckCircle2, Cpu, Globe, Hand, Lock, Network, RotateCcw, Search, Server, ShieldCheck, User, X, XCircle,
} from "lucide-react";
import { api, apiSend } from "../lib/api";
import { usePolling } from "../lib/usePolling";
import { ACTION_LABEL, CRITICALITY, SEVERITY, TACTICS, fmtAgo, fmtDuration, fmtNumber, fmtTime, parseTs } from "../lib/format";
import { ActorBadge, Button, ErrorBanner, IncidentStatusBadge, MitreChip, Panel, Pill, ReadOnlyNote, SeverityBadge } from "../components/ui";

// ------------------------------------------------------------------ kill chain
function KillChain({ chain }) {
  const reached = chain.filter((k) => k.reached).length;
  return (
    <Panel title="Kill chain" subtitle={`${reached} of ${TACTICS.length} MITRE ATT&CK tactics reached (time = first seen, then number of alerts)`} bodyClass="p-4">
      <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-4 lg:grid-cols-7 2xl:grid-cols-14">
        {chain.map((k) => (
          <div key={k.tactic}
            className={`rounded-lg border px-2 py-2 ${k.reached ? "border-accent/40 bg-accent/[0.08]" : "border-dashed border-line"}`}>
            <div className={`text-[11px] font-semibold leading-tight ${k.reached ? "text-ink" : "text-faint"}`}>{k.tactic}</div>
            {k.reached ? (
              <div className="mt-1.5 font-mono text-[11px] text-accent">{fmtTime(k.first_seen)}<span className="text-faint"> · {k.alerts}</span></div>
            ) : <div className="mt-1.5 text-[10px] text-faint">—</div>}
          </div>
        ))}
      </div>
    </Panel>
  );
}

// ------------------------------------------------------------------ swimlane timeline
function Swimlane({ alerts, first, last }) {
  const t0 = parseTs(first).getTime();
  const t1 = parseTs(last).getTime();
  const pad = Math.max(30_000, (t1 - t0) * 0.04);
  const start = t0 - pad;
  const span = t1 + pad - start;
  const x = (ts) => ((parseTs(ts).getTime() - start) / span) * 100;
  const ticks = Array.from({ length: 5 }, (_, i) => start + (span * (i + 0.5)) / 5);

  return (
    <div>
      <div className="relative ml-[220px] h-5 border-b border-line">
        {ticks.map((t) => (
          <span key={t} className="absolute -translate-x-1/2 font-mono text-[10px] text-faint" style={{ left: `${((t - start) / span) * 100}%` }}>
            {new Date(t).toLocaleTimeString([], { hour12: false })}
          </span>
        ))}
      </div>
      <div className="space-y-1 pt-2">
        {alerts.map((a) => {
          const left = x(a.first_seen);
          const width = Math.max(0.8, x(a.last_seen) - left);
          const color = SEVERITY[a.severity]?.color ?? "var(--color-muted)";
          return (
            <Link key={a.id} to={`/alerts?id=${a.id}`} className="group flex items-center rounded hover:bg-panel-2"
              title={`${a.title}\n${fmtTime(a.first_seen)} – ${fmtTime(a.last_seen)} · ${a.event_count} events`}>
              <div className="flex w-[220px] shrink-0 items-center gap-1.5 truncate pr-3 text-xs">
                {a.detector === "ml" && <Brain size={11} className="shrink-0 text-accent" />}
                <span className="truncate group-hover:text-accent">{a.title.replace("ML: ", "")}</span>
              </div>
              <div className="relative h-5 flex-1">
                {ticks.map((t) => <span key={t} className="absolute inset-y-0 w-px bg-line/50" style={{ left: `${((t - start) / span) * 100}%` }} />)}
                <span className="absolute top-1 h-3 rounded-sm" style={{ left: `${left}%`, width: `${width}%`, background: color, minWidth: 6 }} />
              </div>
            </Link>
          );
        })}
      </div>
      <div className="ml-[220px] mt-3 flex flex-wrap gap-3 text-[11px] text-muted">
        {["critical", "high", "medium", "low"].map((s) => (
          <span key={s} className="flex items-center gap-1.5"><span className="h-2 w-3 rounded-sm" style={{ background: SEVERITY[s].color }} />{SEVERITY[s].text}</span>
        ))}
        <span className="flex items-center gap-1.5"><Brain size={11} className="text-accent" />ML detection</span>
      </div>
    </div>
  );
}

function Activity({ data }) {
  if (data.length < 2) return null;
  return (
    <div className="mt-5">
      <div className="mb-1 text-[10px] uppercase tracking-wider text-faint">Evidence events per minute</div>
      <ResponsiveContainer width="100%" height={70}>
        <BarChart data={data} margin={{ top: 4, right: 0, left: 0, bottom: 0 }}>
          <XAxis dataKey="time" hide />
          <Tooltip cursor={{ fill: "rgb(255 255 255 / 0.04)" }}
            content={({ active, payload }) => (active && payload?.length ? (
              <div className="rounded border border-line bg-panel-2 px-2 py-1 font-mono text-xs">{fmtTime(payload[0].payload.time)} · {payload[0].value} events</div>
            ) : null)} />
          <Bar dataKey="events" fill="var(--color-accent)" radius={[2, 2, 0, 0]} isAnimationActive={false} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ------------------------------------------------------------------ narrative
function Narrative({ alerts, actions }) {
  // Alerts (what the attacker did) and response actions (what we did), in one timeline.
  const items = [
    ...alerts.map((a) => ({ kind: "alert", at: a.first_seen, a })),
    ...actions.filter((r) => ["success", "pending_approval"].includes(r.status))
      .map((r) => ({ kind: "action", at: r.decided_at || r.created_at, r })),
  ].sort((x, y) => parseTs(x.at) - parseTs(y.at));
  return (
    <ol className="relative ml-2 border-l border-line">
      {items.map((it) => it.kind === "alert" ? (
        <li key={`a${it.a.id}`} className="relative pb-4 pl-5 last:pb-0">
          <span className="absolute -left-[5px] top-1.5 h-2.5 w-2.5 rounded-full ring-4 ring-panel" style={{ background: SEVERITY[it.a.severity]?.color }} />
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="font-mono text-muted">{fmtTime(it.a.first_seen)}</span>
            {it.a.mitre_tactic && <span className="text-faint">{it.a.mitre_tactic}</span>}
            {it.a.mitre_technique && <MitreChip technique={it.a.mitre_technique} tactic={it.a.mitre_tactic} />}
            {it.a.detector === "ml" && <Pill color="var(--color-accent)"><Brain size={10} />ML</Pill>}
          </div>
          <Link to={`/alerts?id=${it.a.id}`} className="mt-0.5 block text-sm font-medium hover:text-accent">{it.a.title}</Link>
          <div className="text-xs text-muted">{it.a.summary}</div>
        </li>
      ) : (
        <li key={`r${it.r.id}`} className="relative pb-4 pl-5 last:pb-0">
          <span className="absolute -left-[7px] top-1 grid h-3.5 w-3.5 place-items-center rounded-full bg-ok ring-4 ring-panel">
            <ShieldCheck size={9} className="text-bg" />
          </span>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="font-mono text-muted">{fmtTime(it.r.decided_at || it.r.created_at)}</span>
            <span className="font-semibold text-ok">RESPONSE</span>
            <ActorBadge actor={it.r.actor} />
            {it.r.username && <span className="font-mono text-ink/80">{it.r.username}</span>}
            {it.r.playbook_id && <span className="font-mono text-faint">{it.r.playbook_id}</span>}
          </div>
          <div className="mt-0.5 text-sm font-medium">{ACTION_LABEL[it.r.action]} <span className="font-mono text-accent">{it.r.target}</span></div>
          <div className="text-xs text-muted">{it.r.result}</div>
        </li>
      ))}
    </ol>
  );
}

// ------------------------------------------------------------------ side panels
function ScoreBreakdown({ inc }) {
  const s = SEVERITY[inc.severity];
  const total = inc.score_breakdown.reduce((n, b) => n + b.points, 0);
  return (
    <Panel title="Why this risk score" subtitle="Each factor adds points; the total is capped at 100">
      <div className="flex items-end gap-3">
        <span className="font-mono text-4xl font-semibold" style={{ color: s.color }}>{Math.round(inc.score)}</span>
        <span className="pb-1 text-sm" style={{ color: s.color }}>{s.text}</span>
        {total > 100 && <span className="pb-1 text-xs text-faint">({total} before cap)</span>}
      </div>
      <div className="mt-4 space-y-3">
        {inc.score_breakdown.map((b) => (
          <div key={b.factor}>
            <div className="flex justify-between text-xs"><span>{b.factor}</span><span className="font-mono">+{b.points}</span></div>
            <div className="mt-1 h-1.5 rounded-full bg-panel-2"><div className="h-1.5 rounded-full bg-accent" style={{ width: `${b.points}%` }} /></div>
            <div className="mt-0.5 text-[11px] text-faint">{b.detail}</div>
          </div>
        ))}
      </div>
      <p className="mt-4 text-[11px] text-faint">Bands: 85+ critical · 65+ high · 40+ medium · below 40 low.</p>
    </Panel>
  );
}

function Involved({ inc }) {
  return (
    <Panel title="Who and what is involved">
      <div className="space-y-4 text-sm">
        {inc.actors.length > 0 && (
          <div>
            <div className="mb-1.5 text-[10px] uppercase tracking-wider text-faint">Attacker IPs</div>
            {inc.actors.map((ip) => (
              <Link key={ip} to={`/events?src_ip=${ip}`} className="flex items-center gap-2 rounded px-1 py-1 hover:bg-panel-2">
                <Globe size={14} className="text-high" /><span className="font-mono text-accent">{ip}</span>
                <span className="ml-auto text-xs text-faint">events →</span>
              </Link>
            ))}
          </div>
        )}
        <div>
          <div className="mb-1.5 text-[10px] uppercase tracking-wider text-faint">Our machines</div>
          {inc.assets.map((a) => (
            <Link key={a.host} to={`/events?host=${a.host}`} className="flex items-center gap-2 rounded px-1 py-1 hover:bg-panel-2">
              <Server size={14} className="text-muted" />
              <span className="font-mono">{a.host}</span>
              <span className="truncate text-xs text-muted">{a.role}</span>
              <span className="ml-auto"><Pill color={CRITICALITY[a.criticality]}>{a.criticality}</Pill></span>
            </Link>
          ))}
          {inc.assets.length === 0 && <span className="text-xs text-faint">—</span>}
        </div>
        {inc.users.length > 0 && (
          <div>
            <div className="mb-1.5 text-[10px] uppercase tracking-wider text-faint">Accounts targeted</div>
            <div className="flex flex-wrap gap-1.5">
              {inc.users.map((u) => (
                <span key={u.user} className="inline-flex items-center gap-1 rounded-md border border-line bg-panel-2 px-2 py-0.5 text-xs">
                  <User size={11} className="text-muted" />{u.user}<span className="font-mono text-faint">{u.events}</span>
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </Panel>
  );
}

function Notes({ inc, onAdd, busy }) {
  const [text, setText] = useState("");
  return (
    <Panel title="Case notes">
      <div className="max-h-64 space-y-2 overflow-y-auto">
        {inc.notes.length === 0 && <p className="text-sm text-faint">No notes yet.</p>}
        {inc.notes.map((n, i) => (
          <div key={i} className={`rounded-lg px-3 py-2 text-sm ${n.system ? "text-muted" : "border border-line bg-panel-2"}`}>
            <div className="mb-0.5 font-mono text-[10px] text-faint">{fmtTime(n.at)} · {n.author}</div>
            {n.text}
          </div>
        ))}
      </div>
      <form className="mt-3 flex gap-2" onSubmit={async (e) => { e.preventDefault(); if (await onAdd(text)) setText(""); }}>
        <input value={text} onChange={(e) => setText(e.target.value)} placeholder="What you checked, what you found…"
          className="h-9 flex-1 rounded-lg border border-line bg-panel-2 px-3 text-sm outline-none placeholder:text-faint focus:border-accent" />
        <Button need="analyst" type="submit" variant="primary" disabled={busy || !text.trim()}>Add</Button>
      </form>
    </Panel>
  );
}

const KIND_ICON = { ip: Network, process: Cpu, host: Server };

function Containment({ inc, onAction, onDecide, onRelease, busy }) {
  const r = inc.response;
  const verb = { ip: "Block", process: "Quarantine", host: "Isolate" };
  return (
    <Panel title="Containment" subtitle="Stop the attack. Everything here is simulated and written to the audit log.">
      {r.pending.length > 0 && (
        <div className="mb-4 space-y-2">
          {r.pending.map((p) => (
            <div key={p.id} className="rounded-lg border border-medium/40 bg-medium/[0.07] px-3 py-2.5">
              <div className="flex items-center gap-2 text-xs text-medium"><Hand size={13} /> {p.playbook_id} asks for approval</div>
              <div className="mt-1 text-sm">{ACTION_LABEL[p.action]} <span className="font-mono text-accent">{p.target}</span></div>
              <div className="mt-2 flex gap-2">
                <Button need="analyst" variant="primary" disabled={busy} onClick={() => onDecide(p.id, "approve")}><Check size={13} /> Approve</Button>
                <Button need="analyst" disabled={busy} onClick={() => onDecide(p.id, "reject")}><X size={13} /> Reject</Button>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="space-y-1.5">
        {r.suggestions.map((sg) => {
          const Icon = KIND_ICON[sg.kind];
          return (
            <div key={sg.target} className="flex items-center gap-3 rounded-lg border border-line px-3 py-2">
              <Icon size={15} className={sg.done ? "text-ok" : "text-muted"} />
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm">{sg.label}</div>
                <div className="truncate text-[11px] text-faint">{sg.done ? "Contained" : sg.why}</div>
              </div>
              {sg.done ? (
                <Button need="analyst" disabled={busy} onClick={() => onRelease(sg.containment_id)}><RotateCcw size={12} /> Release</Button>
              ) : (
                <Button need="analyst" variant="danger" disabled={busy} onClick={() => onAction(sg)}>{verb[sg.kind]}</Button>
              )}
            </div>
          );
        })}
      </div>
      <Link to="/response" className="mt-3 inline-block text-xs text-accent hover:underline">Response Center →</Link>
    </Panel>
  );
}

// ------------------------------------------------------------------ page
export default function IncidentDetail() {
  const { id } = useParams();
  const { data: inc, error, refresh } = usePolling(() => api(`/api/incidents/${id}`), 5000, [id]);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);

  const update = async (body) => {
    setBusy(true);
    setActionError(null);
    try {
      await apiSend(`/api/incidents/${id}`, "PATCH", body);
      await refresh();
      return true;
    } catch (e) {
      setActionError(e.message);
      return false;
    } finally {
      setBusy(false);
    }
  };

  if (error && !inc) return <div className="mx-auto max-w-[1400px]"><ErrorBanner error={error} /></div>;
  if (!inc) return <div className="p-8 text-sm text-muted">Loading incident…</div>;

  const respond = async (fn) => {
    setBusy(true);
    setActionError(null);
    try { await fn(); await refresh(); } catch (e) { setActionError(e.message); } finally { setBusy(false); }
  };
  const doAction = (sg) => respond(() => apiSend("/api/response/actions", "POST", {
    action: { ip: "block_ip", process: "quarantine_process", host: "isolate_host" }[sg.kind],
    ip: sg.ip, host: sg.host, path: sg.path, incident_id: inc.id, reason: `Analyst action on INC-${inc.id}`,
  }));
  const decide = (id, d) => respond(() => apiSend(`/api/response/pending/${id}/${d}`, "POST"));
  const releaseC = (cid) => respond(() => apiSend(`/api/response/containments/${cid}/release`, "POST"));

  const s = SEVERITY[inc.severity];
  const closed = inc.status === "resolved" || inc.status === "false_positive";

  return (
    <div className="mx-auto max-w-[1400px] space-y-4">
      <Link to="/incidents" className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-ink"><ArrowLeft size={14} /> All incidents</Link>
      <ReadOnlyNote need="analyst" what="triage or contain this incident" />

      <section className="relative overflow-hidden rounded-xl border border-line bg-panel">
        <div className="absolute inset-y-0 left-0 w-1.5" style={{ background: s.color }} />
        <div className="flex flex-wrap items-start justify-between gap-6 px-6 py-5 pl-8">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-faint">INC-{inc.id}</span>
              <SeverityBadge severity={inc.severity} />
              <IncidentStatusBadge status={inc.status} />
              {inc.detectors.includes("ml") && <Pill color="var(--color-accent)"><Brain size={10} />ML involved</Pill>}
            </div>
            <h2 className="mt-2 text-xl font-semibold">{inc.title}</h2>
            <p className="mt-1 text-sm text-muted">{inc.summary}</p>
            <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-muted">
              <span>Started <span className="font-mono text-ink">{fmtTime(inc.first_seen)}</span></span>
              <span>Last activity <span className="text-ink">{fmtAgo(inc.last_seen)}</span></span>
              <span>Duration <span className="font-mono text-ink">{fmtDuration(inc.first_seen, inc.last_seen)}</span></span>
              <span>Evidence <span className="font-mono text-ink">{fmtNumber(inc.event_count)}</span> events</span>
            </div>
          </div>
          <div className="text-right">
            <div className="font-mono text-5xl font-semibold leading-none" style={{ color: s.color }}>{Math.round(inc.score)}</div>
            <div className="mt-1 text-xs text-muted">risk score</div>
          </div>
        </div>
        <div className="flex flex-wrap gap-2 border-t border-line px-6 py-3 pl-8">
          {!closed && <>
            <Button need="analyst" variant="primary" disabled={busy || inc.status === "investigating"} onClick={() => update({ status: "investigating" })}><Search size={14} /> Investigate</Button>
            <Button need="analyst" disabled={busy || inc.status === "contained"} onClick={() => update({ status: "contained" })}><Lock size={14} /> Mark contained</Button>
            <Button need="analyst" disabled={busy} onClick={() => update({ status: "resolved" })}><CheckCircle2 size={14} /> Resolve</Button>
            <Button need="analyst" disabled={busy} onClick={() => update({ status: "false_positive" })}><XCircle size={14} /> False positive</Button>
          </>}
          {closed && <Button need="analyst" disabled={busy} onClick={() => update({ status: "open" })}>Reopen</Button>}
          <span className="ml-auto self-center text-xs text-faint">Resolving closes all {inc.alert_count} alerts in this incident.</span>
        </div>
        {actionError && <div className="border-t border-line px-8 py-2 text-xs text-critical">{actionError}</div>}
      </section>

      <KillChain chain={inc.kill_chain} />

      <div className="grid items-start gap-4 xl:grid-cols-3">
        <div className="space-y-4 xl:col-span-2">
          <Panel title="Attack timeline" subtitle="Each bar is one alert, from first to last evidence. Click a row to investigate it.">
            <Swimlane alerts={inc.alerts} first={inc.first_seen} last={inc.last_seen} />
            <Activity data={inc.activity} />
          </Panel>
          <Panel title="What happened, step by step" subtitle={`${inc.alerts.length} alerts and ${inc.response.actions.filter((a) => a.status === "success").length} response actions, in time order`}>
            <Narrative alerts={inc.alerts} actions={inc.response.actions} />
          </Panel>
        </div>
        <div className="space-y-4">
          <Containment inc={inc} busy={busy} onAction={doAction} onDecide={decide} onRelease={releaseC} />
          <ScoreBreakdown inc={inc} />
          <Involved inc={inc} />
          <Panel title="Analyst checklist" subtitle="Investigation steps from every alert, most severe first">
            <ol className="space-y-2">
              {inc.recommended.map((r, i) => (
                <li key={r} className="flex gap-3 text-sm">
                  <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-panel-2 font-mono text-[11px] text-accent">{i + 1}</span>{r}
                </li>
              ))}
            </ol>
          </Panel>
          <Notes inc={inc} busy={busy} onAdd={(text) => update({ note: text })} />
        </div>
      </div>
    </div>
  );
}
