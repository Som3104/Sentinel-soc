import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis } from "recharts";
import { Brain, CheckCircle2, ClipboardList, Code2, ExternalLink, Search, ShieldQuestion, X, XCircle } from "lucide-react";
import { api, apiSend } from "../lib/api";
import { SEVERITY, eventSummary, fmtAgo, fmtDuration, fmtTime, mitreUrl, parseTs } from "../lib/format";
import { Button, LabelBadge, SeverityBadge, SourceBadge, StatusBadge } from "./ui";

function Section({ title, icon: Icon, children, action }) {
  return (
    <section className="border-t border-line px-6 py-5">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-muted">
          {Icon && <Icon size={14} />}
          {title}
        </h3>
        {action}
      </div>
      {children}
    </section>
  );
}

function Fact({ label, children, mono = true }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] uppercase tracking-wider text-faint">{label}</div>
      <div className={`truncate text-sm ${mono ? "font-mono" : ""}`}>{children}</div>
    </div>
  );
}

function fmtMetric(v) {
  if (Array.isArray(v)) return v.join(", ");
  if (v && typeof v === "object") return Object.entries(v).map(([k, n]) => `${k}: ${n}`).join(", ");
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
}

// Evidence events bucketed over time: shows the SHAPE of the attack (a burst, a steady drip...).
function ActivityChart({ evidence, color }) {
  if (evidence.length < 2) return null;
  const times = evidence.map((e) => parseTs(e.timestamp).getTime());
  const min = Math.min(...times);
  const span = Math.max(...times) - min || 1;
  const n = 24;
  const buckets = Array.from({ length: n }, (_, i) => ({ i, t: new Date(min + (span * i) / n).toISOString(), count: 0 }));
  times.forEach((t) => { buckets[Math.min(n - 1, Math.floor(((t - min) / span) * n))].count += 1; });
  return (
    <ResponsiveContainer width="100%" height={70}>
      <BarChart data={buckets} margin={{ top: 4, right: 0, left: 0, bottom: 0 }}>
        <XAxis dataKey="t" hide />
        <Tooltip
          cursor={{ fill: "rgb(255 255 255 / 0.04)" }}
          content={({ active, payload }) => active && payload?.length ? (
            <div className="rounded border border-line bg-panel-2 px-2 py-1 font-mono text-xs">
              {fmtTime(payload[0].payload.t)} · {payload[0].value} events
            </div>
          ) : null}
        />
        <Bar dataKey="count" fill={color} radius={[2, 2, 0, 0]} isAnimationActive={false} />
      </BarChart>
    </ResponsiveContainer>
  );
}

const HIDDEN_METRICS = new Set(["signals", "class_probabilities", "window_start", "anomaly_score", "anomaly_threshold"]);
const CLASS_LABELS = { normal: "Normal", brute_force: "Brute force", port_scan: "Port scan", suspicious_process: "Suspicious process", exfiltration: "Exfiltration" };

function MlExplanation({ metrics }) {
  const probs = Object.entries(metrics.class_probabilities ?? {}).sort((a, b) => b[1] - a[1]);
  const over = metrics.anomaly_score - metrics.anomaly_threshold;
  return (
    <div className="space-y-5">
      <div>
        <div className="mb-1.5 flex items-baseline justify-between text-xs">
          <span className="text-muted">Isolation Forest anomaly score</span>
          <span className="font-mono">
            {metrics.anomaly_score} <span className="text-faint">/ threshold {metrics.anomaly_threshold}</span>
          </span>
        </div>
        <div className="relative h-2 rounded-full bg-panel-2">
          <div className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${Math.min(100, (metrics.anomaly_score / 0.9) * 100)}%`, background: over >= 0 ? "var(--color-critical)" : "var(--color-muted)" }} />
          <div className="absolute -top-1 h-4 w-0.5 bg-ink" style={{ left: `${(metrics.anomaly_threshold / 0.9) * 100}%` }} title="threshold" />
        </div>
        <div className="mt-1 text-[11px] text-faint">{over >= 0 ? "Above the line: unlike normal traffic." : "Below the line: the Random Forest raised this one."}</div>
      </div>

      {metrics.signals?.length > 0 && (
        <div>
          <div className="mb-2 text-[10px] uppercase tracking-wider text-faint">Most unusual behaviours in this minute</div>
          <table className="w-full text-xs">
            <thead><tr className="text-left text-faint"><th className="pb-1 font-normal">Feature</th><th className="pb-1 text-right font-normal">This minute</th><th className="pb-1 text-right font-normal">Normal avg</th><th className="pb-1 text-right font-normal">Std devs away</th></tr></thead>
            <tbody>
              {metrics.signals.map((g) => (
                <tr key={g.feature} className="border-t border-line/50">
                  <td className="py-1.5 font-mono">{g.feature}</td>
                  <td className="text-right font-mono text-ink">{g.value}</td>
                  <td className="text-right font-mono text-muted">{g.normal}</td>
                  <td className="text-right font-mono" style={{ color: Math.abs(g.z) >= 5 ? "var(--color-critical)" : "var(--color-high)" }}>{g.z > 0 ? "+" : ""}{g.z}σ</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div>
        <div className="mb-2 text-[10px] uppercase tracking-wider text-faint">Random Forest: which attack does it resemble?</div>
        <div className="space-y-1.5">
          {probs.map(([c, p]) => (
            <div key={c} className="flex items-center gap-3 text-xs">
              <span className="w-32 shrink-0 text-muted">{CLASS_LABELS[c] ?? c}</span>
              <div className="h-1.5 flex-1 rounded-full bg-panel-2">
                <div className="h-1.5 rounded-full" style={{ width: `${p * 100}%`, background: c === "normal" ? "var(--color-muted)" : "var(--color-accent)" }} />
              </div>
              <span className="w-10 text-right font-mono">{Math.round(p * 100)}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function AlertDrawer({ alertId, onClose, onChanged }) {
  const [alert, setAlert] = useState(null);
  const [error, setError] = useState(null);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setAlert(null);
    setError(null);
    api(`/api/alerts/${alertId}`).then(setAlert).catch((e) => setError(e.message));
  }, [alertId]);

  useEffect(() => {
    const onKey = (e) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const update = async (body) => {
    setBusy(true);
    try {
      const updated = await apiSend(`/api/alerts/${alertId}`, "PATCH", body);
      setAlert(updated);
      onChanged?.();
      return true;
    } catch (e) {
      setError(e.message);
      return false;
    } finally {
      setBusy(false);
    }
  };

  const sev = SEVERITY[alert?.severity] ?? SEVERITY.medium;

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-[1px]" onClick={onClose} />
      <aside className="relative flex h-full w-full max-w-[640px] flex-col overflow-y-auto border-l border-line bg-panel shadow-2xl">
        <div className="h-1 shrink-0" style={{ background: sev.color }} />

        {!alert && !error && <div className="p-8 text-sm text-muted">Loading alert…</div>}
        {error && <div className="m-6 rounded-lg border border-critical/40 bg-critical/10 p-4 text-sm text-critical">{error}</div>}

        {alert && (
          <>
            <header className="px-6 pb-5 pt-5">
              <div className="flex items-start justify-between gap-4">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={alert.severity} score={alert.score} />
                  <StatusBadge status={alert.status} />
                  <span className="font-mono text-xs text-faint">ALERT #{alert.id} · {alert.rule_id}</span>
                </div>
                <button onClick={onClose} className="rounded-md p-1 text-muted hover:bg-panel-2 hover:text-ink" aria-label="Close">
                  <X size={18} />
                </button>
              </div>
              <h2 className="mt-3 text-xl font-semibold">{alert.title}</h2>
              <p className="mt-1.5 text-sm text-ink/80">{alert.summary}</p>

              <div className="mt-5 flex flex-wrap gap-2">
                <Button need="analyst" variant="primary" disabled={busy || alert.status === "investigating"} onClick={() => update({ status: "investigating" })}>
                  <Search size={14} /> Investigate
                </Button>
                <Button need="analyst" disabled={busy || alert.status === "resolved"} onClick={() => update({ status: "resolved" })}>
                  <CheckCircle2 size={14} /> Resolve
                </Button>
                <Button need="analyst" disabled={busy || alert.status === "false_positive"} onClick={() => update({ status: "false_positive" })}>
                  <XCircle size={14} /> False positive
                </Button>
                {(alert.status === "resolved" || alert.status === "false_positive") && (
                  <Button need="analyst" disabled={busy} onClick={() => update({ status: "new" })}>Reopen</Button>
                )}
              </div>
            </header>

            <Section title="Key facts">
              <div className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3">
                <Fact label="Entity">
                  <Link to={`/events?q=${encodeURIComponent(alert.entity)}`} className="text-accent hover:underline">{alert.entity}</Link>
                </Fact>
                <Fact label="Host">{alert.host ?? "—"}</Fact>
                <Fact label="Detector">{alert.detector}</Fact>
                <Fact label="First seen">{fmtTime(alert.first_seen)}</Fact>
                <Fact label="Last seen">{fmtTime(alert.last_seen)} <span className="text-faint">({fmtAgo(alert.last_seen)})</span></Fact>
                <Fact label="Duration">{fmtDuration(alert.first_seen, alert.last_seen)}</Fact>
                <Fact label="Evidence events">{alert.event_count}</Fact>
                <Fact label="Created">{fmtAgo(alert.created_at)}</Fact>
                <Fact label="Incident">{alert.incident_id
                  ? <Link to={`/incidents/${alert.incident_id}`} className="text-accent hover:underline">INC-{alert.incident_id} →</Link>
                  : <span className="text-faint">not grouped</span>}</Fact>
              </div>
            </Section>

            {alert.detector === "ml" && (
              <Section title="Why the model flagged this" icon={Brain}>
                <MlExplanation metrics={alert.metrics} />
              </Section>
            )}

            <Section title="MITRE ATT&CK">
              {!alert.mitre_technique ? (
                <div className="rounded-lg border border-dashed border-line px-4 py-3 text-sm text-muted">
                  No ATT&CK technique: the activity is unusual but doesn't resemble any attack the model knows.
                  These "unknown unknowns" are exactly what anomaly detection is for. Investigate the evidence below.
                </div>
              ) : (
              <a href={mitreUrl(alert.mitre_technique)} target="_blank" rel="noreferrer"
                 className="group flex items-center justify-between rounded-lg border border-line bg-panel-2 px-4 py-3 hover:border-accent">
                <div>
                  <div className="text-xs text-muted">{alert.mitre_tactic}</div>
                  <div className="mt-0.5 font-medium">
                    <span className="font-mono text-accent">{alert.mitre_technique}</span>
                    {alert.detector !== "ml" && <> · {alert.rule?.technique_name}</>}
                  </div>
                </div>
                <ExternalLink size={16} className="text-faint group-hover:text-accent" />
              </a>
              )}
              {alert.rule?.description && <p className="mt-3 text-sm text-muted">{alert.rule.description}</p>}
            </Section>

            <Section title="What the detector measured">
              <div className="grid grid-cols-2 gap-x-6 gap-y-3">
                {Object.entries(alert.metrics).filter(([k]) => !HIDDEN_METRICS.has(k)).map(([k, v]) => (
                  <Fact key={k} label={k.replaceAll("_", " ")}><span title={fmtMetric(v)}>{fmtMetric(v)}</span></Fact>
                ))}
              </div>
              <div className="mt-4">
                <div className="mb-1 text-[10px] uppercase tracking-wider text-faint">Activity over time</div>
                <ActivityChart evidence={alert.evidence} color={sev.color} />
              </div>
            </Section>

            <Section title={`Evidence · ${alert.evidence.length} events`}
              action={<Link to={`/events?q=${encodeURIComponent(alert.entity)}`} className="text-xs text-accent hover:underline">Open in Live Events →</Link>}>
              <div className="max-h-72 overflow-y-auto rounded-lg border border-line">
                <table className="w-full text-xs">
                  <tbody>
                    {alert.evidence.map((e) => (
                      <tr key={e.id} className="border-b border-line/60 last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-muted">{fmtTime(e.timestamp)}</td>
                        <td className="px-2"><SourceBadge source={e.source} /></td>
                        <td className="whitespace-nowrap px-2 font-mono">{e.host}</td>
                        <td className="w-full px-2 text-ink/85">{eventSummary(e)}</td>
                        <td className="px-3"><LabelBadge label={e.label} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>

            <Section title="Recommended response" icon={ClipboardList}>
              <ol className="space-y-2">
                {alert.recommended.map((r, i) => (
                  <li key={r} className="flex gap-3 text-sm">
                    <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-panel-2 font-mono text-[11px] text-accent">{i + 1}</span>
                    {r}
                  </li>
                ))}
              </ol>
              <p className="mt-3 text-xs text-faint">One-click and automated actions arrive in Phase 6 (Response Center).</p>
            </Section>

            {alert.related.length > 0 && (
              <Section title={`Other alerts on ${alert.entity}`} icon={ShieldQuestion}>
                <div className="space-y-1.5">
                  {alert.related.map((r) => (
                    <Link key={r.id} to={`/alerts?id=${r.id}`} className="flex items-center justify-between gap-3 rounded-lg px-2 py-1.5 text-sm hover:bg-panel-2">
                      <span className="flex min-w-0 items-center gap-2">
                        <SeverityBadge severity={r.severity} />
                        <span className="truncate">{r.title}</span>
                      </span>
                      <span className="shrink-0 font-mono text-xs text-faint">#{r.id} · {fmtAgo(r.last_seen)}</span>
                    </Link>
                  ))}
                </div>
                {alert.incident_id && <Link to={`/incidents/${alert.incident_id}`} className="mt-3 inline-block text-xs text-accent hover:underline">See the whole attack in INC-{alert.incident_id} →</Link>}
              </Section>
            )}

            <Section title="Detection logic" icon={Code2}>
              <code className="block rounded-lg border border-line bg-bg px-3 py-2.5 font-mono text-xs leading-relaxed text-ink/90">{alert.logic}</code>
              <Link to={alert.detector === "ml" ? "/models" : "/rules"} className="mt-2 inline-block text-xs text-accent hover:underline">
                {alert.detector === "ml" ? "See model metrics →" : "Tune this rule →"}
              </Link>
            </Section>

            <Section title="Analyst notes">
              <div className="space-y-2.5">
                {alert.notes.length === 0 && <p className="text-sm text-faint">No notes yet.</p>}
                {alert.notes.map((n, i) => (
                  <div key={i} className={`rounded-lg px-3 py-2 text-sm ${n.system ? "text-muted" : "border border-line bg-panel-2"}`}>
                    <div className="mb-0.5 font-mono text-[10px] text-faint">{fmtTime(n.at)} · {n.author}</div>
                    {n.text}
                  </div>
                ))}
              </div>
              <form
                className="mt-3 flex gap-2"
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (await update({ note })) setNote("");
                }}
              >
                <input
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  placeholder="Add a note: what you checked, what you found…"
                  className="h-9 flex-1 rounded-lg border border-line bg-panel-2 px-3 text-sm outline-none placeholder:text-faint focus:border-accent"
                />
                <Button need="analyst" type="submit" variant="primary" disabled={busy || !note.trim()}>Add</Button>
              </form>
            </Section>
          </>
        )}
      </aside>
    </div>
  );
}
