import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Brain, Search, ShieldCheck } from "lucide-react";
import { api } from "../lib/api";
import { usePolling } from "../lib/usePolling";
import { SEVERITY, fmtAgo, fmtDuration, fmtNumber } from "../lib/format";
import { ErrorBanner, IncidentStatusBadge, KillChainStrip, Panel, Pill } from "../components/ui";

const STATUS_FILTERS = [
  { value: "active", label: "Active" },
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
  { value: "false_positive", label: "False positive" },
  { value: "all", label: "All" },
];
const RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function RiskBadge({ severity, score }) {
  const s = SEVERITY[severity] ?? SEVERITY.medium;
  return (
    <div className="flex items-center gap-3">
      <div className="grid h-11 w-11 shrink-0 place-items-center rounded-lg font-mono text-lg font-semibold"
        style={{ color: s.color, background: `color-mix(in srgb, ${s.color} 14%, transparent)`, boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${s.color} 40%, transparent)` }}
        title={`Risk score ${Math.round(score)} / 100`}>
        {Math.round(score)}
      </div>
      <span className="text-xs font-medium" style={{ color: s.color }}>{s.text}</span>
    </div>
  );
}

export default function Incidents() {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "active";
  const severity = params.get("severity") ?? "";
  const [search, setSearch] = useState(params.get("q") ?? "");

  const setParam = (key, value) => setParams((prev) => {
    const next = new URLSearchParams(prev);
    if (value) next.set(key, value);
    else next.delete(key);
    return next;
  }, { replace: true });

  useEffect(() => {
    const id = setTimeout(() => setParam("q", search.trim()), 350);
    return () => clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  const { data: summary } = usePolling(() => api("/api/incidents/summary"), 5000);
  const { data: incidents, error } = usePolling(
    () => api("/api/incidents", { status, severity, q: params.get("q") }),
    5000, [status, severity, params.get("q")],
  );
  // Highest risk first: that's the order an analyst should work in.
  const sorted = incidents ? [...incidents].sort((a, b) => b.score - a.score || (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0)) : [];

  return (
    <div className="mx-auto max-w-[1400px]">
      <ErrorBanner error={error} />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {["critical", "high", "medium", "low"].map((s) => {
          const n = summary?.active_by_severity[s] ?? 0;
          const active = severity === s;
          return (
            <button key={s} onClick={() => setParam("severity", active ? "" : s)}
              className="relative overflow-hidden rounded-xl border border-line bg-panel px-4 py-3.5 text-left hover:border-faint"
              style={active ? { boxShadow: `inset 0 0 0 1px ${SEVERITY[s].color}` } : undefined}>
              <div className="absolute inset-y-0 left-0 w-1" style={{ background: SEVERITY[s].color, opacity: n ? 1 : 0.25 }} />
              <div className="text-xs font-medium uppercase tracking-wider text-muted">{SEVERITY[s].text}</div>
              <div className={`mt-1 font-mono text-2xl ${n ? "" : "text-faint"}`}>{n}</div>
              <div className="text-[11px] text-faint">active incidents</div>
            </button>
          );
        })}
      </div>

      <div className="mb-4 mt-6 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search IP, host, title…"
            className="h-9 w-64 rounded-lg border border-line bg-panel-2 pl-9 pr-3 text-sm outline-none placeholder:text-faint focus:border-accent" />
        </div>
        <div className="flex flex-wrap rounded-lg border border-line bg-panel p-0.5">
          {STATUS_FILTERS.map((f) => (
            <button key={f.value} onClick={() => setParam("status", f.value === "active" ? "" : f.value)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium ${status === f.value ? "bg-accent/15 text-accent" : "text-muted hover:text-ink"}`}>
              {f.label}
              {f.value === "active" && summary ? <span className="ml-1.5 font-mono">{summary.active}</span> : null}
            </button>
          ))}
        </div>
      </div>

      <Panel title="Incident queue" subtitle="Related alerts grouped into one case each. Highest risk first." bodyClass="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                <th className="py-2.5 pl-5 pr-4 font-medium">Risk</th>
                <th className="pr-4 font-medium">Incident</th>
                <th className="pr-4 font-medium">Kill chain</th>
                <th className="pr-4 text-right font-medium">Alerts</th>
                <th className="pr-4 font-medium">Duration</th>
                <th className="pr-4 font-medium">Last activity</th>
                <th className="pr-5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((i) => (
                <tr key={i.id} className="border-b border-line/50 hover:bg-panel-2">
                  <td className="py-3 pl-5 pr-4"><Link to={`/incidents/${i.id}`}><RiskBadge severity={i.severity} score={i.score} /></Link></td>
                  <td className="max-w-[480px] pr-4">
                    <Link to={`/incidents/${i.id}`} className="block">
                      <div className="flex items-center gap-2">
                        <span className="whitespace-nowrap font-mono text-xs text-faint">INC-{i.id}</span>
                        <span className="truncate font-medium hover:text-accent">{i.title}</span>
                      </div>
                      <div className="mt-0.5 truncate text-xs text-muted">{i.summary}</div>
                    </Link>
                  </td>
                  <td className="pr-4"><KillChainStrip tactics={i.tactics} /><div className="mt-1 text-[11px] text-faint">{i.tactics.length} of 14 tactics</div></td>
                  <td className="pr-4 text-right">
                    <div className="font-mono text-xs">{fmtNumber(i.alert_count)}</div>
                    <div className="mt-0.5 flex justify-end gap-1">
                      {i.detectors.includes("rule") && <Pill color="var(--color-muted)">rules</Pill>}
                      {i.detectors.includes("ml") && <Pill color="var(--color-accent)"><Brain size={10} />ML</Pill>}
                    </div>
                  </td>
                  <td className="whitespace-nowrap pr-4 font-mono text-xs text-muted">{fmtDuration(i.first_seen, i.last_seen)}</td>
                  <td className="whitespace-nowrap pr-4 text-xs text-muted">{fmtAgo(i.last_seen)}</td>
                  <td className="pr-5"><IncidentStatusBadge status={i.status} /></td>
                </tr>
              ))}
              {incidents?.length === 0 && (
                <tr><td colSpan={7} className="py-16 text-center">
                  <ShieldCheck size={28} className="mx-auto text-ok" />
                  <div className="mt-2 text-sm">No incidents match.</div>
                  <div className="mt-1 text-xs text-muted">Try <span className="font-mono">python simulator\simulator.py --attacks intrusion</span></div>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
