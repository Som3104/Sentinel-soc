import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Brain, Crosshair, Eraser, FlaskConical, Hand, ListChecks, Pause, Play, Radio, RotateCcw, ShieldAlert,
  ShieldBan, ShieldCheck, Siren, Trash2, Unlock, Zap,
} from "lucide-react";
import { api, apiSend } from "../lib/api";
import { usePolling, useRealtimeStatus } from "../lib/usePolling";
import { getFeed, onMessage } from "../lib/realtime";
import { SEVERITY, fmtAgo, fmtNumber } from "../lib/format";
import { useCan } from "../lib/auth";
import { Button, ErrorBanner, MitreChip, Panel, Pill, ReadOnlyNote, Select, Toggle } from "../components/ui";

// ------------------------------------------------------------------ helpers
function ResultLine({ r }) {
  if (!r) return null;
  if (r.error) return <div className="mt-3 rounded-lg border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical">{r.error}</div>;
  const parts = [
    [fmtNumber(r.stored), "stored"],
    r.dropped_blocked > 0 && [fmtNumber(r.dropped_blocked), "dropped by firewall"],
    [r.alerts_created, r.alerts_created === 1 ? "new alert" : "new alerts"],
    r.alerts_updated > 0 && [r.alerts_updated, "updated"],
    [r.incidents_created, r.incidents_created === 1 ? "new incident" : "new incidents"],
    r.responses_executed > 0 && [r.responses_executed, "auto-contained"],
    r.responses_pending > 0 && [r.responses_pending, "awaiting approval"],
  ].filter(Boolean);
  return (
    <div className="mt-3 flex flex-wrap gap-x-3 gap-y-1 rounded-lg border border-line bg-panel-2 px-3 py-2 text-xs text-muted">
      {parts.map(([n, label]) => (
        <span key={label}><span className="font-mono text-ink">{n}</span> {label}</span>
      ))}
    </div>
  );
}

const DETECTOR = {
  rules: { icon: ListChecks, text: "Rules", color: "var(--color-accent)" },
  ml: { icon: Brain, text: "ML", color: "var(--color-auth)" },
};

// ------------------------------------------------------------------ scenario card
function ScenarioCard({ s, onLaunch, onRelease, busy, result }) {
  const canAct = useCan("analyst");
  const mlOnly = s.detected_by.length === 1 && s.detected_by[0] === "ml";
  return (
    <div className="flex flex-col rounded-xl border border-line bg-panel p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold">{s.name}</h3>
          <div className="mt-0.5 text-xs text-muted">
            target <span className="font-mono text-ink/90">{s.target}</span>
            {s.attacker_ip && <> · from <span className="font-mono text-critical/90">{s.attacker_ip}</span></>}
          </div>
        </div>
        <div className="flex shrink-0 gap-1">
          {s.detected_by.map((d) => {
            const D = DETECTOR[d];
            return <Pill key={d} color={D.color}><D.icon size={11} />{D.text}</Pill>;
          })}
        </div>
      </div>

      <p className="mt-3 text-[13px] leading-relaxed text-ink/85">{s.description}</p>
      <div className="mt-3 flex flex-wrap gap-1">
        {s.techniques.map((t) => <MitreChip key={t} technique={t} />)}
      </div>

      <div className={`mt-3 rounded-lg border px-3 py-2 text-xs leading-relaxed ${
        mlOnly ? "border-auth/30 bg-auth/5 text-ink/80" : "border-line bg-panel-2/60 text-muted"}`}>
        <span className="font-semibold text-ink/90">Expected: </span>{s.expect}
      </div>

      {s.blocked && (
        <div className="mt-3 flex items-center gap-2 rounded-lg border border-medium/40 bg-medium/10 px-3 py-2 text-xs text-medium">
          <ShieldBan size={14} className="shrink-0" />
          <span className="flex-1">Attacker is blocked ({fmtAgo(s.blocked.since)}). A replay will be dropped by the firewall.</span>
          <button disabled={busy || !canAct} onClick={() => onRelease(s.blocked.containment_id)}
            title={canAct ? undefined : "Needs the analyst role"}
            className="flex items-center gap-1 font-medium underline-offset-2 enabled:hover:underline disabled:cursor-not-allowed disabled:opacity-40">
            <Unlock size={12} /> Unblock
          </button>
        </div>
      )}

      <ResultLine r={result} />

      <div className="mt-auto pt-4">
        <Button need="analyst" variant={s.blocked ? "default" : "danger"} disabled={busy} onClick={() => onLaunch(s.id)} className="w-full justify-center">
          <Crosshair size={14} /> {busy ? "Running…" : s.blocked ? "Replay (will be blocked)" : "Launch attack"}
        </Button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------ live traffic
const RATES = [10, 20, 60, 120].map((r) => ({ value: String(r), label: `${r} events / min` }));
const EVERY = [20, 45, 90, 180].map((s) => ({ value: String(s), label: `every ${s}s` }));

function LiveTraffic({ status, onChange, busy }) {
  const live = status?.live;
  const running = live?.running;
  const [rate, setRate] = useState("20");
  const [attacks, setAttacks] = useState(false);
  const [every, setEvery] = useState("45");

  useEffect(() => {
    if (!live) return;
    setRate(String(live.rate_per_min));
    setAttacks(live.attacks);
    setEvery(String(live.attack_every_s));
    // only sync from the server when it starts/stops, not on every tick
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  const send = (next) => onChange({
    running: next.running ?? running, rate_per_min: Number(next.rate ?? rate),
    attacks: next.attacks ?? attacks, attack_every_s: Number(next.every ?? every),
  });
  // While running, changing a setting applies it immediately.
  const update = (key, value, setter) => { setter(value); if (running) send({ [key]: value }); };

  return (
    <Panel title="Live traffic"
      subtitle="A background generator streams normal activity every 5 seconds, like a real network that never sleeps."
      action={running && (
        <span className="flex items-center gap-1.5 text-xs font-semibold text-ok"><Radio size={14} className="pulse-dot" />RUNNING</span>
      )}>
      <div className="flex flex-wrap items-center gap-3">
        <Select value={rate} onChange={(v) => update("rate", v || "20", setRate)} options={RATES} />
        <label className="flex items-center gap-2 text-sm text-muted">
          <Toggle need="analyst" checked={attacks} onChange={(v) => update("attacks", v, setAttacks)} />
          Random attacks
        </label>
        {attacks && <Select value={every} onChange={(v) => update("every", v || "45", setEvery)} options={EVERY} />}
        <div className="ml-auto">
          {running
            ? <Button need="analyst" disabled={busy} onClick={() => send({ running: false })}><Pause size={14} /> Stop</Button>
            : <Button need="analyst" variant="primary" disabled={busy} onClick={() => send({ running: true })}><Play size={14} /> Start</Button>}
        </div>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          ["Batches", live?.ticks ?? 0],
          ["Events sent", live?.events_sent ?? 0],
          ["Dropped", live?.events_dropped ?? 0],
          ["Alerts", (live?.alerts_created ?? 0) + (live?.alerts_updated ?? 0)],
        ].map(([label, v]) => (
          <div key={label} className="rounded-lg border border-line bg-panel-2/60 px-3 py-2">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">{label}</div>
            <div className="mt-0.5 font-mono text-lg text-ink">{fmtNumber(v)}</div>
          </div>
        ))}
      </div>

      {live?.attacks_launched?.length > 0 && (
        <div className="mt-3 text-xs text-muted">
          Random attacks so far:{" "}
          {live.attacks_launched.slice().reverse().map((a, i) => (
            <span key={a.at} className="font-mono text-ink/85">{i > 0 && ", "}{a.scenario} <span className="text-faint">{fmtAgo(a.at)}</span></span>
          ))}
        </div>
      )}
      {(live?.alerts_updated > 0 || live?.incidents_created > 0) && (
        <div className="mt-2 text-[11px] text-faint">
          Alerts = {live.alerts_created} new + {live.alerts_updated} merged into existing ones · {live.incidents_created} incidents opened
        </div>
      )}
      {live?.last_error && <div className="mt-3 text-xs text-critical">Last tick failed: {live.last_error}</div>}
      {running && live?.started_at && (
        <div className="mt-3 text-[11px] text-faint">Started {fmtAgo(live.started_at)} · stops if the backend restarts</div>
      )}
    </Panel>
  );
}

// ------------------------------------------------------------------ live feed
const FEED_ICON = { incident: Siren, response: ShieldCheck, approval: Hand, alert: ShieldAlert };
const FEED_COLOR = { response: "var(--color-ok)", approval: "var(--color-medium)" };

function LiveFeed({ items }) {
  const ws = useRealtimeStatus();
  return (
    <Panel title="Live feed"
      subtitle={ws === "live" ? "Pushed by the backend over WebSocket the moment it happens" : "Waiting for the real-time connection…"}
      bodyClass="p-0"
      action={<span className={`h-2 w-2 rounded-full ${ws === "live" ? "pulse-dot bg-ok" : "bg-faint"}`} />}>
      {items.length === 0 ? (
        <div className="px-5 py-10 text-center text-sm text-muted">
          Launch an attack and watch detections, incidents and responses arrive here.
        </div>
      ) : (
        <div className="max-h-[520px] divide-y divide-line/60 overflow-y-auto">
          {items.map((f) => {
            const Icon = FEED_ICON[f.kind] ?? Zap;
            const color = FEED_COLOR[f.kind] ?? SEVERITY[f.severity]?.color ?? "var(--color-muted)";
            return (
              <Link key={f.key} to={f.link} className="row-new flex items-start gap-3 px-5 py-2.5 hover:bg-panel-2">
                <Icon size={14} className="mt-0.5 shrink-0" style={{ color }} />
                <div className="min-w-0 flex-1">
                  <div className={`truncate text-[13px] ${f.kind === "alert" ? "text-ink/80" : "font-medium text-ink"}`}>{f.text}</div>
                  <div className="text-[11px] text-faint">
                    {f.kind}{f.detector === "ml" ? " · ML" : ""} · {f.source}
                  </div>
                </div>
                <span className="shrink-0 font-mono text-[11px] text-faint">{f.time}</span>
              </Link>
            );
          })}
        </div>
      )}
    </Panel>
  );
}

// ------------------------------------------------------------------ page
export default function Simulator() {
  const { data: scenarios, error, refresh: refreshScenarios } = usePolling(() => api("/api/lab/scenarios"), 10000);
  const { data: status, refresh: refreshStatus } = usePolling(() => api("/api/lab/status"), 5000);
  const [busy, setBusy] = useState(null);           // scenario id | "demo" | "reset" | "live"
  const [results, setResults] = useState({});
  const [actionError, setActionError] = useState(null);
  const [confirmWipe, setConfirmWipe] = useState(false);
  const [feed, setFeed] = useState(getFeed);

  // realtime.js keeps the recent feed (so it survives page changes); re-read it on every push.
  useEffect(() => onMessage(() => setFeed(getFeed())), []);

  const run = async (key, fn) => {
    setBusy(key); setActionError(null);
    try {
      return await fn();
    } catch (e) {
      setActionError(e.message);
      return null;
    } finally {
      setBusy(null);
      refreshScenarios(); refreshStatus();
    }
  };

  const launch = (id) => run(id, async () => {
    const r = await apiSend("/api/lab/run", "POST", { attacks: [id], include_normal: true }).catch((e) => ({ error: e.message }));
    setResults((rs) => ({ ...rs, [id]: r }));
  });
  const demo = () => run("demo", async () => {
    const r = await apiSend("/api/lab/demo");
    setResults((rs) => ({ ...rs, demo: r }));
  });
  const release = (cid) => run("release", () => apiSend(`/api/response/containments/${cid}/release`));
  const setLive = (body) => run("live", () => apiSend("/api/lab/live", "POST", body));
  const reset = (scope) => run("reset", async () => {
    const r = await apiSend("/api/lab/reset", "POST", { scope });
    setConfirmWipe(false);
    setResults(scope === "full" ? {} : (rs) => rs);
    setResults((rs) => ({ ...rs, reset: r }));
  });

  const blocked = (scenarios ?? []).filter((s) => s.blocked).length;
  const resetMsg = results.reset && (results.reset.scope === "full"
    ? `Wiped ${fmtNumber(results.reset.deleted.events)} events, ${results.reset.deleted.alerts} alerts, ${results.reset.deleted.incidents} incidents.`
    : `Released ${results.reset.released} containment${results.reset.released === 1 ? "" : "s"}.`);

  return (
    <div className="mx-auto max-w-[1400px] space-y-6">
      <ReadOnlyNote need="analyst" what="launch attacks or control the lab" />
      <ErrorBanner error={error || actionError} />

      <div className="flex flex-wrap items-center gap-4 rounded-xl border border-line bg-panel px-5 py-4">
        <div className="grid h-10 w-10 shrink-0 place-items-center rounded-lg bg-critical/10 text-critical ring-1 ring-critical/30">
          <FlaskConical size={18} />
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-semibold">Attack lab</h2>
          <p className="mt-0.5 text-xs text-muted">
            Launch real attack patterns into the SOC and watch every stage react: detection, correlation into incidents,
            automated containment. Everything is simulated log data. Nothing leaves this lab or touches a real machine.
          </p>
        </div>
        <Button need="analyst" variant="primary" disabled={!!busy} onClick={demo}>
          <Zap size={14} /> {busy === "demo" ? "Running full demo…" : "Run full demo"}
        </Button>
      </div>
      {results.demo && (
        <div className="-mt-3 rounded-xl border border-line bg-panel px-5 py-3 text-xs text-muted">
          <span className="font-semibold text-ink">Full demo:</span> 30 minutes of normal traffic with all 7 attacks hidden in it.{" "}
          <Link to="/incidents" className="text-accent hover:underline">Open incidents →</Link>
          <ResultLine r={results.demo} />
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-[1fr_420px]">
        <div className="space-y-6">
          <div>
            <div className="mb-3 flex items-baseline justify-between">
              <h2 className="text-sm font-semibold">Scenarios</h2>
              <span className="text-xs text-muted">
                Each attack ends "now", hidden in 2+ minutes of normal traffic
                {blocked > 0 && <> · <span className="text-medium">{blocked} attacker{blocked > 1 ? "s" : ""} blocked</span></>}
              </span>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              {(scenarios ?? []).map((s) => (
                <ScenarioCard key={s.id} s={s} busy={!!busy} result={results[s.id]}
                  onLaunch={launch} onRelease={release} />
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <LiveTraffic status={status} onChange={setLive} busy={!!busy} />
          <LiveFeed items={feed} />

          <Panel title="Reset the lab" subtitle="Start a demo from a known state.">
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="flex-1 text-xs text-muted">Unblock every IP, un-quarantine every process and reconnect every host, so attacks can be replayed. History is kept.</div>
                <Button need="analyst" disabled={!!busy} onClick={() => reset("containments")} className="shrink-0"><RotateCcw size={14} /> Release all</Button>
              </div>
              <div className="flex items-center gap-3 border-t border-line pt-3">
                <div className="flex-1 text-xs text-muted">Delete all events, alerts and incidents. Rules, playbooks, ML models and the audit log stay (an audit log is never deleted).</div>
                {confirmWipe ? (
                  <div className="flex shrink-0 gap-2">
                    <Button need="admin" variant="danger" disabled={!!busy} onClick={() => reset("full")}><Trash2 size={14} /> Wipe</Button>
                    <Button need="admin" onClick={() => setConfirmWipe(false)}>Cancel</Button>
                  </div>
                ) : (
                  <Button need="admin" variant="danger" disabled={!!busy} onClick={() => setConfirmWipe(true)} className="shrink-0"><Eraser size={14} /> Wipe data</Button>
                )}
              </div>
              {resetMsg && <div className="text-xs text-ok">{resetMsg}</div>}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
