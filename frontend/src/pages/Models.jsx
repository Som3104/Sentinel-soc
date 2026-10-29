import { useState } from "react";
import { Link } from "react-router-dom";
import {
  Area, AreaChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { Brain, CheckCircle2, Crosshair, RefreshCw, ShieldCheck, Sparkles, TriangleAlert } from "lucide-react";
import { api, apiSend } from "../lib/api";
import { usePolling } from "../lib/usePolling";
import { fmtAgo, fmtNumber } from "../lib/format";
import { Button, ErrorBanner, Panel, Pill, ReadOnlyNote, StatCard } from "../components/ui";

const pct = (v, digits = 0) => (v === undefined || v === null ? "—" : `${(v * 100).toFixed(digits)}%`);
const LABELS = {
  normal: "Normal", brute_force: "Brute force", port_scan: "Port scan",
  suspicious_process: "Suspicious process", exfiltration: "Exfiltration",
  slow_brute_force: "Slow brute force", slow_scan: "Slow scan",
};
const STEALTH = new Set(["slow_brute_force", "slow_scan"]);

// ------------------------------------------------------------------ Rules vs ML
const DETECTORS = [
  { key: "rules", label: "Rules" },
  { key: "iforest", label: "Isolation Forest" },
  { key: "random_forest", label: "Random Forest" },
  { key: "ml", label: "ML (either)" },
  { key: "combined", label: "Rules + ML", strong: true },
];

function RateCell({ hit, total, strong }) {
  const r = total ? hit / total : 0;
  return (
    <td className="px-2 py-2.5">
      <div className="flex items-center gap-1.5" title={`${hit} of ${total} attack minutes detected`}>
        <div className="h-1.5 w-24 rounded-full bg-panel-2">
          <div className="h-1.5 rounded-full" style={{ width: `${r * 100}%`, background: strong ? "var(--color-ok)" : "var(--color-accent)", opacity: strong ? 1 : 0.75 }} />
        </div>
        <span className={`w-10 text-right font-mono text-xs ${r === 0 ? "text-critical" : strong ? "text-ink" : "text-muted"}`}>{pct(r)}</span>
      </div>
    </td>
  );
}

function RulesVsMl({ m }) {
  const rows = Object.entries(m.by_variant);
  return (
    <Panel
      title="Rules vs machine learning"
      subtitle="Share of attack minutes each detector caught, on test scenarios the models never saw"
      bodyClass="p-0"
    >
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
              <th className="py-2.5 pl-5 pr-3 font-medium">Attack</th>
              <th className="px-3 text-right font-medium">Minutes</th>
              {DETECTORS.map((d) => <th key={d.key} className={`px-2 font-medium ${d.strong ? "text-ok" : ""}`}>{d.label}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map(([variant, c]) => (
              <tr key={variant} className={`border-b border-line/50 ${STEALTH.has(variant) ? "bg-accent/[0.04]" : ""}`}>
                <td className="whitespace-nowrap py-2.5 pl-5 pr-3">
                  <span className="font-medium">{LABELS[variant] ?? variant}</span>
                  {STEALTH.has(variant) && <span className="ml-2"><Pill color="var(--color-accent)">stealthy</Pill></span>}
                </td>
                <td className="px-3 text-right font-mono text-xs text-muted">{c.windows}</td>
                {DETECTORS.map((d) => <RateCell key={d.key} hit={c[d.key] ?? 0} total={c.windows} strong={d.strong} />)}
              </tr>
            ))}
            <tr className="bg-panel-2/60">
              <td className="py-2.5 pl-5 pr-3 font-semibold">All attacks</td>
              <td className="px-3 text-right font-mono text-xs text-muted">{m.rules.tp + m.rules.fn}</td>
              <RateCell hit={m.rules.tp} total={m.rules.tp + m.rules.fn} />
              <RateCell hit={m.isolation_forest.tp} total={m.isolation_forest.tp + m.isolation_forest.fn} />
              <RateCell hit={m.random_forest_detector?.tp ?? 0} total={m.rules.tp + m.rules.fn} />
              <RateCell hit={m.ml_detector.tp} total={m.ml_detector.tp + m.ml_detector.fn} />
              <RateCell hit={m.combined.tp} total={m.combined.tp + m.combined.fn} strong />
            </tr>
          </tbody>
        </table>
      </div>
      <p className="border-t border-line px-5 py-3 text-xs text-muted">
        Rules are precise but only catch what they describe: the <span className="text-ink">stealthy</span> attacks stay under every threshold (0%).
        The Isolation Forest was never told what an attack looks like, yet flags most of them as unusual.
      </p>
    </Panel>
  );
}

// ------------------------------------------------------------------ Isolation Forest
function ScoreTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="rounded-lg border border-line bg-panel-2 px-3 py-2 text-xs shadow-xl">
      <div className="mb-1 font-mono text-muted">anomaly score ≈ {d.score}</div>
      <div className="flex justify-between gap-6"><span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-chart-normal" />Normal minutes</span><span className="font-mono">{fmtNumber(d.normal)}</span></div>
      <div className="flex justify-between gap-6"><span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-chart-attack" />Attack minutes</span><span className="font-mono">{fmtNumber(d.attack)}</span></div>
    </div>
  );
}

function IsolationForestPanel({ m }) {
  const f = m.isolation_forest;
  return (
    <Panel
      title="Isolation Forest · unsupervised"
      subtitle="Learns what normal looks like. Never sees attack labels, so it can flag attacks nobody wrote a rule for."
      action={
        <div className="flex gap-3 text-xs text-muted">
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-chart-normal" />Normal</span>
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-sm bg-chart-attack" />Attack</span>
        </div>
      }
    >
      <div className="grid grid-cols-4 gap-3">
        {[["Precision", pct(f.precision, 1)], ["Recall", pct(f.recall, 1)], ["F1", f.f1.toFixed(2)], ["False alarms", `${f.fp} / ${fmtNumber(f.fp + f.tn)}`]].map(([k, v]) => (
          <div key={k}><div className="text-[10px] uppercase tracking-wider text-faint">{k}</div><div className="font-mono text-lg">{v}</div></div>
        ))}
      </div>
      <div className="mt-4 text-[10px] uppercase tracking-wider text-faint">Anomaly scores of test minutes (√ scale) · alert above the dashed line</div>
      <ResponsiveContainer width="100%" height={220}>
        <AreaChart data={f.histogram} margin={{ top: 16, right: 12, left: -12, bottom: 0 }}>
          <CartesianGrid stroke="var(--color-line)" strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="score" type="number" domain={["dataMin", "dataMax"]} stroke="var(--color-faint)" fontSize={11} tickLine={false} axisLine={false} tickCount={6} />
          <YAxis scale="sqrt" stroke="var(--color-faint)" fontSize={11} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip content={<ScoreTooltip />} cursor={{ stroke: "var(--color-muted)", strokeDasharray: "3 3" }} />
          <Area type="stepAfter" dataKey="normal" stroke="var(--color-chart-normal)" strokeWidth={2} fill="var(--color-chart-normal)" fillOpacity={0.18} isAnimationActive={false} />
          <Area type="stepAfter" dataKey="attack" stroke="var(--color-chart-attack)" strokeWidth={2} fill="var(--color-chart-attack)" fillOpacity={0.22} isAnimationActive={false} />
          <ReferenceLine x={f.threshold} stroke="var(--color-ink)" strokeDasharray="4 3"
            label={{ value: `threshold ${f.threshold}`, position: "top", fill: "var(--color-muted)", fontSize: 11 }} />
        </AreaChart>
      </ResponsiveContainer>
      <p className="mt-2 text-xs text-muted">
        Threshold is set so at most {pct(f.false_alarm_budget, 2)} of normal minutes cross it. Trained on {f.features?.length ?? 10} behaviour
        features, log-scaled, with attacks at {pct(f.contamination, 1)} of training data (anomalies must be rare for this model to work).
      </p>
    </Panel>
  );
}

// ------------------------------------------------------------------ Random Forest
function ConfusionMatrix({ classes, matrix }) {
  const rowTotals = matrix.map((r) => r.reduce((a, b) => a + b, 0));
  return (
    <div className="overflow-x-auto">
      <table className="text-xs">
        <thead>
          <tr>
            <th className="pb-1 pr-2 text-left text-[10px] font-normal uppercase tracking-wider text-faint">actual ↓ / predicted →</th>
            {classes.map((c) => <th key={c} className="w-[74px] px-1 pb-1 text-center font-normal text-muted">{LABELS[c] ?? c}</th>)}
          </tr>
        </thead>
        <tbody>
          {matrix.map((row, i) => (
            <tr key={classes[i]}>
              <td className="whitespace-nowrap py-0.5 pr-2 text-muted">{LABELS[classes[i]] ?? classes[i]}</td>
              {row.map((n, j) => {
                const share = rowTotals[i] ? n / rowTotals[i] : 0;
                const correct = i === j;
                return (
                  <td key={j} className="p-0.5">
                    <div
                      title={`${n} ${LABELS[classes[i]]} minutes predicted as ${LABELS[classes[j]]} (${pct(share, 1)} of row)`}
                      className={`grid h-10 place-items-center rounded font-mono ${n ? "text-ink" : "text-faint"}`}
                      style={{
                        background: n ? `color-mix(in srgb, ${correct ? "var(--color-accent)" : "var(--color-critical)"} ${Math.round(12 + share * 60)}%, var(--color-panel))` : "var(--color-panel-2)",
                      }}
                    >
                      {fmtNumber(n)}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-2 text-[11px] text-faint">Diagonal (cyan) = correct. Off-diagonal (red) = mistakes. Shade = share of that row.</p>
    </div>
  );
}

function RandomForestPanel({ m }) {
  const r = m.random_forest;
  const maxImp = Math.max(...r.feature_importance.map((f) => f.importance));
  const desc = Object.fromEntries(m.features.map((f) => [f.name, f.description]));
  return (
    <Panel title="Random Forest · supervised" subtitle="Trained on labeled examples. Names the likely attack so the analyst knows where to start.">
      <div className="grid grid-cols-3 gap-3">
        {[["Accuracy", pct(r.accuracy, 1)], ["Macro F1", r.macro_f1.toFixed(2)], ["Alert if confidence ≥", pct(r.confidence_threshold)]].map(([k, v]) => (
          <div key={k}><div className="text-[10px] uppercase tracking-wider text-faint">{k}</div><div className="font-mono text-lg">{v}</div></div>
        ))}
      </div>
      <p className="mt-2 text-xs text-muted">Accuracy looks high because most minutes are normal. Macro F1 averages every class equally, so it's the honest number.</p>

      <div className="mt-5 grid gap-6 2xl:grid-cols-2">
        <div>
          <div className="mb-2 text-[10px] uppercase tracking-wider text-faint">Per class</div>
          <table className="w-full text-xs">
            <thead><tr className="text-left text-faint"><th className="pb-1 font-normal">Class</th><th className="pb-1 text-right font-normal">Precision</th><th className="pb-1 text-right font-normal">Recall</th><th className="pb-1 text-right font-normal">F1</th><th className="pb-1 text-right font-normal">Test minutes</th></tr></thead>
            <tbody>
              {r.per_class.map((c) => (
                <tr key={c.label} className="border-t border-line/50">
                  <td className="py-1.5">{LABELS[c.label] ?? c.label}</td>
                  <td className="text-right font-mono">{c.precision.toFixed(2)}</td>
                  <td className="text-right font-mono">{c.recall.toFixed(2)}</td>
                  <td className="text-right font-mono">{c.f1.toFixed(2)}</td>
                  <td className="text-right font-mono text-muted">{fmtNumber(c.support)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="mb-2 mt-5 text-[10px] uppercase tracking-wider text-faint">Confusion matrix</div>
          <ConfusionMatrix classes={r.classes} matrix={r.confusion_matrix} />
        </div>
        <div>
          <div className="mb-2 text-[10px] uppercase tracking-wider text-faint">Feature importance: what the forest relies on</div>
          <div className="space-y-2">
            {r.feature_importance.map((f) => (
              <div key={f.feature} title={desc[f.feature]}>
                <div className="mb-0.5 flex justify-between text-xs">
                  <span className="font-mono text-ink/90">{f.feature}</span>
                  <span className="font-mono text-muted">{(f.importance * 100).toFixed(1)}%</span>
                </div>
                <div className="h-1.5 rounded-full bg-panel-2">
                  <div className="h-1.5 rounded-full bg-accent" style={{ width: `${(f.importance / maxImp) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </Panel>
  );
}

// ------------------------------------------------------------------ live + features
function LivePanel({ live }) {
  return (
    <Panel title="In your lab right now" subtitle="Open alerts, by who caught them">
      <div className="grid grid-cols-3 gap-3 text-center">
        {[["Only ML", live.only_ml.length, "var(--color-accent)"], ["Both", live.both.length, "var(--color-ok)"], ["Only rules", live.only_rules.length, "var(--color-muted)"]].map(([k, v, c]) => (
          <div key={k} className="rounded-lg border border-line bg-panel-2 py-3">
            <div className="font-mono text-2xl" style={{ color: v ? c : "var(--color-faint)" }}>{v}</div>
            <div className="text-[11px] text-muted">{k}</div>
          </div>
        ))}
      </div>
      <div className="mt-4 text-[10px] uppercase tracking-wider text-faint">Entities only machine learning caught</div>
      <div className="mt-2 space-y-1">
        {live.only_ml.length === 0 && (
          <p className="text-xs text-muted">None yet. Run <span className="font-mono text-ink">python simulator\simulator.py --attacks slow_brute_force,slow_scan</span></p>
        )}
        {live.only_ml.slice(0, 8).map((e) => (
          <Link key={e.entity} to={`/alerts?status=open&q=${encodeURIComponent(e.entity)}`} className="flex items-center justify-between rounded-md px-2 py-1.5 text-sm hover:bg-panel-2">
            <span className="font-mono text-accent">{e.entity}</span>
            <span className="text-xs text-muted">{e.ml} ML alert{e.ml > 1 ? "s" : ""} · no rule fired</span>
          </Link>
        ))}
      </div>
    </Panel>
  );
}

function FeaturesPanel({ m }) {
  const used = new Set(m.isolation_forest.features ?? []);
  return (
    <Panel title="The 14 features" subtitle="Each minute of each IP's (or host's) activity becomes one row of these numbers">
      <div className="grid gap-x-6 gap-y-2 sm:grid-cols-2">
        {m.features.map((f) => (
          <div key={f.name} className="flex items-start gap-2 text-xs">
            <span className="mt-0.5 w-40 shrink-0 font-mono text-ink/90">{f.name}</span>
            <span className="text-muted">{f.description}{used.has(f.name) && <span className="text-faint"> · IF</span>}</span>
          </div>
        ))}
      </div>
      <p className="mt-3 text-[11px] text-faint">"IF" marks the 10 behaviour features the Isolation Forest uses. The Random Forest uses all 14.</p>
    </Panel>
  );
}

// ------------------------------------------------------------------ page
export default function Models() {
  const { data, error, refresh } = usePolling(() => api("/api/ml/status"), 5000);
  const [train, setTrain] = useState({ busy: false, error: null });

  const retrain = async () => {
    setTrain({ busy: true, error: null });
    try {
      await apiSend("/api/ml/train", "POST");
      setTrain({ busy: false, error: null });
    } catch (e) {
      setTrain({ busy: false, error: e.message });
    }
    refresh();
  };

  const m = data?.metrics;
  const busy = train.busy || data?.training;

  return (
    <div className="mx-auto max-w-[1400px] space-y-4">
      <ReadOnlyNote need="admin" what="retrain the models" />
      <ErrorBanner error={error} />

      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-panel px-5 py-4">
        <div className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-lg bg-accent/15 text-accent"><Brain size={20} /></div>
          <div>
            <div className="flex items-center gap-2 font-semibold">
              Detector ML-001
              {data && (data.enabled ? <Pill color="var(--color-ok)">enabled</Pill> : <Pill color="var(--color-muted)">disabled</Pill>)}
              {busy && <Pill color="var(--color-medium)">training…</Pill>}
            </div>
            <div className="text-xs text-muted">
              {m ? <>Trained {fmtAgo(m.trained_at)} in {m.duration_s}s on {fmtNumber(m.dataset.train_windows)} minutes of activity ({m.dataset.scenarios_train} scenarios{m.dataset.db_events ? ` + ${fmtNumber(m.dataset.db_events)} events from your database` : ""}). Tested on {m.dataset.scenarios_test} unseen scenarios.</>
                : data?.training ? "Training the first model, about 30 seconds…" : "No model yet."}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link to="/rules" className="text-xs text-accent hover:underline">Tune sensitivity →</Link>
          <Button need="admin" variant="primary" onClick={retrain} disabled={busy}>
            <RefreshCw size={14} className={busy ? "animate-spin" : ""} /> {busy ? "Training…" : "Retrain models"}
          </Button>
        </div>
      </div>
      {(train.error || data?.error) && <div className="rounded-lg border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-critical">{train.error || data.error}</div>}

      {m && (
        <>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatCard label="Rules alone catch" value={pct(m.rules.recall)} sub={`of attack minutes · ${m.rules.fp} false alarms`} icon={ShieldCheck} tone="var(--color-muted)" />
            <StatCard label="ML alone catches" value={pct(m.ml_detector.recall)} sub={`precision ${pct(m.ml_detector.precision, 1)}`} icon={Sparkles} tone="var(--color-accent)" />
            <StatCard label="Rules + ML catch" value={pct(m.combined.recall)} sub="defense in depth" icon={Crosshair} tone="var(--color-ok)" />
            <StatCard label="False alarm rate" value={pct(m.combined.false_positive_rate, 2)} sub={`${m.combined.fp} of ${fmtNumber(m.combined.fp + m.combined.tn)} normal minutes`} icon={m.combined.fp ? TriangleAlert : CheckCircle2} tone={m.combined.fp ? "var(--color-medium)" : "var(--color-ok)"} />
          </div>

          <RulesVsMl m={m} />

          <div className="grid items-start gap-4 xl:grid-cols-2">
            <div className="space-y-4">
              <IsolationForestPanel m={m} />
              {data && <LivePanel live={data.live} />}
            </div>
            <RandomForestPanel m={m} />
          </div>

          <FeaturesPanel m={m} />
        </>
      )}
    </div>
  );
}
