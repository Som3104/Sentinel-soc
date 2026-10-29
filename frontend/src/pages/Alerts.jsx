import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Brain, Play, Search, ShieldCheck } from "lucide-react";
import { api, apiSend } from "../lib/api";
import { usePolling } from "../lib/usePolling";
import { SEVERITY, fmtAgo, fmtNumber } from "../lib/format";
import AlertDrawer from "../components/AlertDrawer";
import { Button, ErrorBanner, MitreChip, Panel, Pill, SeverityBadge, StatusBadge } from "../components/ui";

const STATUS_FILTERS = [
  { value: "open", label: "Open" },
  { value: "new", label: "New" },
  { value: "investigating", label: "Investigating" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
  { value: "", label: "All" },
];

function SeverityCard({ severity, count, active, onClick }) {
  const s = SEVERITY[severity];
  return (
    <button
      onClick={onClick}
      className={`relative overflow-hidden rounded-xl border bg-panel px-4 py-3.5 text-left transition-colors ${active ? "border-transparent ring-1" : "border-line hover:border-faint"}`}
      style={active ? { boxShadow: `inset 0 0 0 1px ${s.color}`, background: `color-mix(in srgb, ${s.color} 8%, var(--color-panel))` } : undefined}
    >
      <div className="absolute inset-y-0 left-0 w-1" style={{ background: s.color, opacity: count ? 1 : 0.25 }} />
      <div className="text-xs font-medium uppercase tracking-wider text-muted">{s.text}</div>
      <div className={`mt-1 font-mono text-2xl ${count ? "" : "text-faint"}`}>{fmtNumber(count ?? 0)}</div>
      <div className="text-[11px] text-faint">open alerts</div>
    </button>
  );
}

export default function Alerts() {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "open";
  const severity = params.get("severity") ?? "";
  const ruleId = params.get("rule_id") ?? "";
  const detector = params.get("detector") ?? "";
  const openId = params.get("id");
  const [search, setSearch] = useState(params.get("q") ?? "");
  const [scan, setScan] = useState({ busy: false, result: null, error: null });

  const setParam = (key, value) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value === null || value === undefined || (value === "" && key !== "status")) next.delete(key);
      else next.set(key, value);
      return next;
    }, { replace: key !== "id" });
  };

  useEffect(() => {
    const id = setTimeout(() => setParam("q", search.trim()), 350);
    return () => clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  const { data: summary, refresh: refreshSummary } = usePolling(() => api("/api/alerts/summary"), 5000);
  const { data: rules } = usePolling(() => api("/api/rules"), 60000);
  const { data: alerts, error, refresh } = usePolling(
    () => api("/api/alerts", { status, severity, rule_id: ruleId, detector, q: params.get("q") }),
    5000,
    [status, severity, ruleId, detector, params.get("q")],
  );

  const runDetection = async () => {
    setScan({ busy: true, result: null, error: null });
    try {
      const result = await apiSend("/api/detection/run", "POST", undefined, { hours: 24 });
      setScan({ busy: false, result, error: null });
      refresh();
      refreshSummary();
    } catch (e) {
      setScan({ busy: false, result: null, error: e.message });
    }
  };

  return (
    <div className="mx-auto max-w-[1400px]">
      <ErrorBanner error={error} />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        {["critical", "high", "medium", "low"].map((s) => (
          <SeverityCard key={s} severity={s} count={summary?.open_by_severity[s]} active={severity === s}
            onClick={() => setParam("severity", severity === s ? "" : s)} />
        ))}
        <div className="col-span-2 flex flex-col justify-between rounded-xl border border-line bg-panel px-4 py-3.5 lg:col-span-1">
          <div>
            <div className="text-xs font-medium uppercase tracking-wider text-muted">Detection engine</div>
            <div className="mt-1 text-xs text-faint">
              Runs automatically on every log batch.
              {scan.result && <span className="text-ok"> Scanned {fmtNumber(scan.result.events_scanned)} events: {scan.result.alerts_created} new, {scan.result.alerts_updated} updated.</span>}
              {scan.error && <span className="text-critical"> {scan.error}</span>}
            </div>
          </div>
          <Button need="analyst" variant="primary" onClick={runDetection} disabled={scan.busy} className="mt-2 justify-center">
            <Play size={14} /> {scan.busy ? "Scanning…" : "Re-scan last 24h"}
          </Button>
        </div>
      </div>

      <div className="mb-4 mt-6 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search IP, host, alert…"
            className="h-9 w-64 rounded-lg border border-line bg-panel-2 pl-9 pr-3 text-sm outline-none placeholder:text-faint focus:border-accent"
          />
        </div>
        <div className="flex rounded-lg border border-line bg-panel p-0.5">
          {STATUS_FILTERS.map((f) => (
            <button key={f.value} onClick={() => setParam("status", f.value)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium ${status === f.value ? "bg-accent/15 text-accent" : "text-muted hover:text-ink"}`}>
              {f.label}
              {f.value === "open" && summary ? <span className="ml-1.5 font-mono">{summary.open}</span> : null}
            </button>
          ))}
        </div>
        <select value={ruleId} onChange={(e) => setParam("rule_id", e.target.value)}
          className="h-9 max-w-[220px] rounded-lg border border-line bg-panel-2 px-3 text-sm outline-none focus:border-accent">
          <option value="">All rules</option>
          {rules?.map((r) => <option key={r.id} value={r.id}>{r.id} · {r.name}</option>)}
        </select>
        <select value={detector} onChange={(e) => setParam("detector", e.target.value)}
          className="h-9 rounded-lg border border-line bg-panel-2 px-3 text-sm outline-none focus:border-accent">
          <option value="">Rules + ML</option>
          <option value="rule">Rules only</option>
          <option value="ml">ML only</option>
        </select>
        {(severity || ruleId || detector || params.get("q")) && (
          <button onClick={() => { setSearch(""); setParams({ status }); }} className="text-xs text-accent hover:underline">Clear filters</button>
        )}
      </div>

      <Panel title="Alert queue" subtitle="Most recent activity first. Click an alert to investigate." bodyClass="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                <th className="py-2.5 pl-5 pr-4 font-medium">Severity</th>
                <th className="pr-4 font-medium">Alert</th>
                <th className="pr-4 font-medium">Entity</th>
                <th className="pr-4 font-medium">MITRE</th>
                <th className="pr-4 text-right font-medium">Events</th>
                <th className="pr-4 font-medium">Last seen</th>
                <th className="pr-5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts?.map((a) => (
                <tr key={a.id} onClick={() => setParam("id", a.id)}
                  className={`cursor-pointer border-b border-line/50 hover:bg-panel-2 ${String(a.id) === openId ? "bg-panel-2" : ""}`}>
                  <td className="whitespace-nowrap py-3 pl-5 pr-4"><SeverityBadge severity={a.severity} score={a.score} /></td>
                  <td className="max-w-[420px] pr-4">
                    <div className="flex items-center gap-2 font-medium">
                      {a.title}
                      {a.detector === "ml" && <Pill color="var(--color-accent)"><Brain size={11} /> ML</Pill>}
                    </div>
                    <div className="truncate text-xs text-muted" title={a.summary}>{a.summary}</div>
                  </td>
                  <td className="whitespace-nowrap pr-4">
                    <div className="font-mono text-xs text-accent">{a.entity}</div>
                    {a.host && a.host !== a.entity && <div className="font-mono text-[11px] text-faint">on {a.host}</div>}
                  </td>
                  <td className="pr-4">{a.mitre_technique ? <MitreChip technique={a.mitre_technique} tactic={a.mitre_tactic} /> : <span className="text-xs text-faint">unknown</span>}</td>
                  <td className="pr-4 text-right font-mono text-xs">{fmtNumber(a.event_count)}</td>
                  <td className="whitespace-nowrap pr-4 text-xs text-muted">{fmtAgo(a.last_seen)}</td>
                  <td className="pr-5">
                    <StatusBadge status={a.status} />
                    {a.incident_id && (
                      <Link to={`/incidents/${a.incident_id}`} onClick={(e) => e.stopPropagation()}
                        className="mt-1 block font-mono text-[11px] text-faint hover:text-accent">INC-{a.incident_id}</Link>
                    )}
                  </td>
                </tr>
              ))}
              {alerts?.length === 0 && (
                <tr><td colSpan={7} className="py-16 text-center">
                  <ShieldCheck size={28} className="mx-auto text-ok" />
                  <div className="mt-2 text-sm">No alerts match these filters.</div>
                  <div className="mt-1 text-xs text-muted">Run <span className="font-mono">python simulator\simulator.py</span> to generate attacks.</div>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      {openId && (
        <AlertDrawer
          alertId={openId}
          onClose={() => setParam("id", null)}
          onChanged={() => { refresh(); refreshSummary(); }}
        />
      )}
    </div>
  );
}
