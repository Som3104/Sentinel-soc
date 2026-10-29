import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Activity, Ban, Globe, KeyRound, Server, ShieldAlert, Siren } from "lucide-react";
import { api } from "../lib/api";
import { usePolling } from "../lib/usePolling";
import { LABEL_STYLES, SEVERITY, SOURCE_COLORS, fmtAgo, fmtNumber, fmtTime, parseTs } from "../lib/format";
import { ErrorBanner, KillChainStrip, Panel, Pill, StatCard } from "../components/ui";

const WINDOWS = [
  { value: 15, label: "15m" },
  { value: 60, label: "1h" },
  { value: 240, label: "4h" },
  { value: 1440, label: "24h" },
];

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((s, p) => s + p.value, 0);
  return (
    <div className="rounded-lg border border-line bg-panel-2 px-3 py-2 text-xs shadow-xl">
      <div className="mb-1 font-mono text-muted">{fmtTime(label)}</div>
      {payload.slice().reverse().map((p) => (
        <div key={p.dataKey} className="flex items-center justify-between gap-6">
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: p.color }} />{p.dataKey}</span>
          <span className="font-mono">{p.value}</span>
        </div>
      ))}
      <div className="mt-1 flex justify-between border-t border-line pt-1 text-muted"><span>total</span><span className="font-mono">{total}</span></div>
    </div>
  );
}

function EventTimeline({ data }) {
  const tick = (t) => parseTs(t)?.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
        <defs>
          {Object.entries(SOURCE_COLORS).map(([k, c]) => (
            <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={c} stopOpacity={0.45} />
              <stop offset="100%" stopColor={c} stopOpacity={0.03} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid stroke="var(--color-line)" strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="time" tickFormatter={tick} stroke="var(--color-faint)" fontSize={11} tickLine={false} axisLine={false} minTickGap={40} />
        <YAxis stroke="var(--color-faint)" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
        <Tooltip content={<ChartTooltip />} cursor={{ stroke: "var(--color-muted)", strokeDasharray: "3 3" }} />
        {["network", "process", "auth"].map((k) => (
          <Area key={k} type="monotone" dataKey={k} stackId="1" stroke={SOURCE_COLORS[k]} strokeWidth={1.5} fill={`url(#g-${k})`} isAnimationActive={false} />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

function SourceDonut({ bySource }) {
  const data = Object.entries(bySource).map(([name, value]) => ({ name, value }));
  const total = data.reduce((s, d) => s + d.value, 0);
  return (
    <div className="flex items-center gap-6">
      <div className="relative h-40 w-40 shrink-0">
        <ResponsiveContainer>
          <PieChart>
            <Pie data={data} dataKey="value" innerRadius={50} outerRadius={72} paddingAngle={2} stroke="none" isAnimationActive={false}>
              {data.map((d) => <Cell key={d.name} fill={SOURCE_COLORS[d.name]} />)}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
          <div>
            <div className="font-mono text-lg">{fmtNumber(total)}</div>
            <div className="text-[10px] uppercase tracking-wider text-muted">events</div>
          </div>
        </div>
      </div>
      <div className="flex-1 space-y-3">
        {data.sort((a, b) => b.value - a.value).map((d) => (
          <div key={d.name}>
            <div className="flex justify-between text-sm">
              <span className="flex items-center gap-2 capitalize"><span className="h-2 w-2 rounded-sm" style={{ background: SOURCE_COLORS[d.name] }} />{d.name}</span>
              <span className="font-mono text-muted">{total ? Math.round((d.value / total) * 100) : 0}%</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function GroundTruth({ byLabel }) {
  const entries = Object.entries(byLabel).sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, n]) => n));
  return (
    <div className="space-y-3">
      {entries.map(([label, n]) => {
        const s = LABEL_STYLES[label] ?? { text: label, color: "var(--color-muted)" };
        return (
          <div key={label}>
            <div className="mb-1 flex justify-between text-xs">
              <span className="text-ink/90">{s.text}</span>
              <span className="font-mono text-muted">{fmtNumber(n)}</span>
            </div>
            <div className="h-1.5 rounded-full bg-panel-2">
              <div className="h-1.5 rounded-full" style={{ width: `${Math.max(2, (n / max) * 100)}%`, background: s.color }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function TopIps({ ips }) {
  const maxFailed = Math.max(1, ...ips.map((i) => i.failed_logins));
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-[11px] uppercase tracking-wider text-faint">
          <th className="pb-2 font-medium">Source IP</th>
          <th className="pb-2 font-medium">Origin</th>
          <th className="pb-2 text-right font-medium">Events</th>
          <th className="pb-2 pl-6 font-medium">Failed logins</th>
        </tr>
      </thead>
      <tbody>
        {ips.map((ip) => (
          <tr key={ip.ip} className="border-t border-line/60">
            <td className="py-2.5">
              <Link to={`/events?src_ip=${ip.ip}`} className="font-mono text-accent hover:underline">{ip.ip}</Link>
            </td>
            <td>{ip.external ? <Pill color="var(--color-high)">external</Pill> : <Pill color="var(--color-muted)">internal</Pill>}</td>
            <td className="text-right font-mono">{fmtNumber(ip.events)}</td>
            <td className="pl-6">
              <div className="flex items-center gap-2">
                <div className="h-1.5 w-24 rounded-full bg-panel-2">
                  <div className="h-1.5 rounded-full" style={{
                    width: `${(ip.failed_logins / maxFailed) * 100}%`,
                    background: ip.failed_logins >= 5 ? "var(--color-critical)" : "var(--color-muted)",
                  }} />
                </div>
                <span className="font-mono text-xs text-muted">{ip.failed_logins}</span>
              </div>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TopIncidents({ incidents }) {
  if (!incidents.length) {
    return <div className="py-10 text-center text-sm text-muted">No active incidents. All quiet.</div>;
  }
  return (
    <div className="divide-y divide-line/60">
      {incidents.map((i) => {
        const s = SEVERITY[i.severity];
        return (
          <Link key={i.id} to={`/incidents/${i.id}`} className="flex items-center gap-4 px-5 py-3 hover:bg-panel-2">
            <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg font-mono text-sm font-semibold"
              style={{ color: s.color, background: `color-mix(in srgb, ${s.color} 14%, transparent)` }}>{Math.round(i.score)}</div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-sm font-medium"><span className="mr-2 font-mono text-xs text-faint">INC-{i.id}</span>{i.title}</div>
              <div className="truncate text-xs text-muted">{i.summary}</div>
            </div>
            <KillChainStrip tactics={i.tactics} />
            <div className="w-16 shrink-0 text-right text-xs text-faint">{fmtAgo(i.last_seen)}</div>
          </Link>
        );
      })}
    </div>
  );
}

function AlertBreakdown({ summary }) {
  const sev = Object.entries(summary.open_by_severity);
  const max = Math.max(1, ...sev.map(([, n]) => n));
  const tactics = Object.entries(summary.by_tactic).sort((a, b) => b[1] - a[1]);
  return (
    <div>
      <div className="space-y-2.5">
        {sev.map(([s, n]) => (
          <Link key={s} to={`/alerts?severity=${s}`} className="block">
            <div className="mb-1 flex justify-between text-xs">
              <span>{SEVERITY[s].text}</span>
              <span className="font-mono text-muted">{n}</span>
            </div>
            <div className="h-1.5 rounded-full bg-panel-2">
              <div className="h-1.5 rounded-full" style={{ width: `${n ? Math.max(4, (n / max) * 100) : 0}%`, background: SEVERITY[s].color }} />
            </div>
          </Link>
        ))}
      </div>
      {tactics.length > 0 && (
        <>
          <div className="mb-2 mt-5 text-[10px] font-semibold uppercase tracking-wider text-faint">ATT&CK tactics seen</div>
          <div className="flex flex-wrap gap-1.5">
            {tactics.map(([t, n]) => (
              <span key={t} className="rounded-md border border-line bg-panel-2 px-2 py-0.5 text-[11px]">
                {t} <span className="font-mono text-muted">{n}</span>
              </span>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

export default function Overview() {
  const [windowMin, setWindowMin] = useState(60);
  const { data, error, lastUpdated } = usePolling(() => api("/api/stats/overview", { window: windowMin }), 5000, [windowMin]);
  const { data: alertSummary } = usePolling(() => api("/api/alerts/summary"), 5000);
  const { data: incSummary } = usePolling(() => api("/api/incidents/summary"), 5000);
  const t = data?.totals;
  const crit = alertSummary?.open_by_severity.critical ?? 0;

  // Merge failed-login IPs into the top list so a quiet brute-forcer never hides behind noisy IPs.
  const ips = data ? [...data.top_ips] : [];
  data?.top_failed_login_ips.forEach((f) => {
    if (!ips.some((i) => i.ip === f.ip)) ips.push({ ...f, events: f.failed_logins });
  });
  // External IPs first (that's where attacks come from), then failed logins, then volume.
  ips.sort((a, b) => b.external - a.external || b.failed_logins - a.failed_logins || b.events - a.events);

  return (
    <div className="mx-auto max-w-[1400px]">
      <ErrorBanner error={error} />

      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted">
          Security telemetry across all monitored hosts
          {lastUpdated && <span className="text-faint"> · updated {lastUpdated.toLocaleTimeString([], { hour12: false })}</span>}
        </p>
        <div className="flex rounded-lg border border-line bg-panel p-0.5">
          {WINDOWS.map((w) => (
            <button
              key={w.value}
              onClick={() => setWindowMin(w.value)}
              className={`rounded-md px-3 py-1 text-xs font-medium ${windowMin === w.value ? "bg-accent/15 text-accent" : "text-muted hover:text-ink"}`}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <StatCard label="Events" value={fmtNumber(t?.events_in_window)} sub={`${fmtNumber(t?.events_last_15m)} in last 15 min`} icon={Activity} />
        <StatCard label="Failed logins" value={fmtNumber(t?.failed_logins)} sub="auth failures in window" icon={KeyRound} tone="var(--color-auth)" />
        <StatCard label="External IPs" value={fmtNumber(t?.external_ips)} sub={`of ${fmtNumber(t?.unique_src_ips)} unique sources`} icon={Globe} tone="var(--color-high)" />
        <Link to="/incidents" className="block">
          <StatCard label="Active incidents" value={fmtNumber(incSummary?.active)} sub={`${incSummary?.active_by_severity.critical ?? 0} critical · ${incSummary?.active_by_severity.high ?? 0} high`} icon={Siren} tone="var(--color-critical)" />
        </Link>
        <Link to="/alerts" className="block">
          <StatCard label="Open alerts" value={fmtNumber(alertSummary?.open)} sub={`${crit} critical · ${alertSummary?.open_by_severity.high ?? 0} high`} icon={ShieldAlert} tone="var(--color-critical)" />
        </Link>
        <Link to="/response" className="block">
          <StatCard label="Blocked IPs" value={fmtNumber(t?.blocked_ips)} sub={`${fmtNumber(t?.events_dropped)} attack events stopped`} icon={Ban} tone="var(--color-ok)" />
        </Link>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Panel title="Highest-risk incidents" subtitle="Each one groups the alerts from one attack. Work top to bottom." className="xl:col-span-2" bodyClass="p-0"
          action={<Link to="/incidents" className="text-xs text-accent hover:underline">All incidents →</Link>}>
          {incSummary && <TopIncidents incidents={incSummary.top_active} />}
        </Panel>
        <Panel title="Open alerts" subtitle="By severity and ATT&CK tactic">
          {alertSummary && <AlertBreakdown summary={alertSummary} />}
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Panel title="Event volume" subtitle="Events per minute by log source" className="xl:col-span-2"
          action={
            <div className="flex gap-3 text-xs text-muted">
              {Object.entries(SOURCE_COLORS).map(([k, c]) => (
                <span key={k} className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm" style={{ background: c }} />{k}</span>
              ))}
            </div>
          }>
          {data ? <EventTimeline data={data.timeline} /> : <div className="h-[260px]" />}
        </Panel>

        <Panel title="Log sources" subtitle="Share of events in window">
          {data && <SourceDonut bySource={data.by_source} />}
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Panel title="Top source IPs" subtitle="External sources first, then failed logins and volume. Click an IP to see its events." className="xl:col-span-2">
          {data && <TopIps ips={ips.slice(0, 8)} />}
        </Panel>

        <div className="space-y-4">
          <Panel title="Ground truth" subtitle="Simulator labels. Real logs won't have these; we use them to score detection accuracy.">
            {data && <GroundTruth byLabel={data.by_label} />}
          </Panel>
          <Panel title="Hosts" subtitle="Events per host">
            <div className="space-y-2">
              {data?.hosts.map((h) => (
                <Link key={h.host} to={`/events?host=${h.host}`} className="flex items-center justify-between rounded-lg px-2 py-1.5 text-sm hover:bg-panel-2">
                  <span className="flex items-center gap-2"><Server size={14} className="text-muted" /><span className="font-mono">{h.host}</span></span>
                  <span className="font-mono text-muted">{fmtNumber(h.events)}</span>
                </Link>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
