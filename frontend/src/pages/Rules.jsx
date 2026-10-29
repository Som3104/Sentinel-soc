import { useState } from "react";
import { Link } from "react-router-dom";
import { Activity, Brain, Cpu, KeyRound, Network, RotateCcw, Save } from "lucide-react";
import { api, apiSend } from "../lib/api";
import { usePolling } from "../lib/usePolling";
import { SEVERITY, TACTICS, fmtAgo, fmtNumber } from "../lib/format";
import { useCan } from "../lib/auth";
import { Button, ErrorBanner, MitreChip, Panel, Pill, ReadOnlyNote, SeverityBadge, Toggle } from "../components/ui";

const SOURCE_ICON = { auth: KeyRound, network: Network, process: Cpu, ml: Brain };

// The ATT&CK matrix as columns, one per tactic. Lit-up columns are where we have detections.
function CoverageMap({ rules }) {
  const byTactic = {};
  rules.filter((r) => r.enabled && r.source !== "ml").forEach((r) => {
    (byTactic[r.mitre_tactic] ??= new Map()).set(r.mitre_technique, r);
  });
  const covered = Object.keys(byTactic).length;
  const techniques = new Set(rules.filter((r) => r.enabled && r.source !== "ml").map((r) => r.mitre_technique)).size;

  return (
    <Panel
      title="MITRE ATT&CK coverage"
      subtitle={`${techniques} techniques across ${covered} of ${TACTICS.length} tactics. Gaps show where an attacker could act unseen.`}
      bodyClass="p-4"
    >
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
        {TACTICS.map((t) => {
          const techs = byTactic[t] ? [...byTactic[t].values()] : [];
          const hits = techs.reduce((s, r) => s + r.open_hits, 0);
          return (
            <div key={t} className={`min-h-[96px] rounded-lg border p-2.5 ${techs.length ? "border-accent/30 bg-accent/[0.06]" : "border-line border-dashed"}`}>
              <div className="flex items-start justify-between gap-1">
                <div className={`text-[11px] font-semibold leading-tight ${techs.length ? "text-ink" : "text-faint"}`}>{t}</div>
                {hits > 0 && <span className="rounded bg-critical/20 px-1 font-mono text-[10px] text-critical" title="open alerts">{hits}</span>}
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {techs.map((r) => <MitreChip key={r.mitre_technique} technique={r.mitre_technique} tactic={t} />)}
                {!techs.length && <span className="text-[10px] text-faint">no coverage</span>}
              </div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function ParamInput({ name, value, onChange }) {
  const isList = Array.isArray(value);
  return (
    <label className="block min-w-0">
      <span className="text-[10px] uppercase tracking-wider text-faint">{name.replaceAll("_", " ")}</span>
      <input
        value={isList ? value.join(", ") : value}
        onChange={(e) => onChange(isList ? e.target.value.split(",").map((s) => s.trim()) : e.target.value)}
        className={`mt-0.5 block h-8 rounded-md border border-line bg-bg px-2 font-mono text-xs outline-none focus:border-accent ${isList ? "w-full" : "w-[110px]"}`}
      />
    </label>
  );
}

function RuleCard({ rule, onSaved }) {
  const canEdit = useCan("admin");
  const [draft, setDraft] = useState(null);       // unsaved param edits
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const params = draft ?? rule.params;
  const dirty = draft !== null;
  const Icon = SOURCE_ICON[rule.source] ?? Activity;

  const save = async (body) => {
    setBusy(true);
    setError(null);
    try {
      await apiSend(`/api/rules/${rule.id}`, "PATCH", body);
      setDraft(null);
      onSaved();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className={`rounded-xl border bg-panel transition-opacity ${rule.enabled ? "border-line" : "border-line/60 opacity-60"}`}>
      <div className="flex items-start gap-4 px-5 pt-4">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-panel-2 text-muted"><Icon size={16} /></div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-faint">{rule.id}</span>
            <h3 className="font-semibold">{rule.name}</h3>
            {rule.source === "ml" ? (
              <Link to="/models"><Pill color="var(--color-accent)">Isolation Forest + Random Forest →</Pill></Link>
            ) : (
              <>
                <SeverityBadge severity={rule.severity} />
                <MitreChip technique={rule.mitre_technique} tactic={rule.mitre_tactic} showTactic />
              </>
            )}
            {rule.customized && <Pill color="var(--color-accent)">tuned</Pill>}
          </div>
          <p className="mt-1 text-sm text-muted">{rule.description}</p>
        </div>
        <Toggle need="admin" checked={rule.enabled} disabled={busy} onChange={(v) => save({ enabled: v })} />
      </div>

      <div className="mx-5 mt-3 rounded-lg border border-line bg-bg px-3 py-2 font-mono text-xs text-ink/85">{rule.logic}</div>

      <div className="flex flex-wrap items-end gap-3 px-5 py-4">
        {Object.entries(params).map(([k, v]) => (
          <div key={k} className={Array.isArray(v) ? "min-w-[220px] flex-1" : ""}>
            <ParamInput name={k} value={v} onChange={(nv) => setDraft({ ...params, [k]: nv })} />
          </div>
        ))}
        {rule.source !== "ml" && <label className="block">
          <span className="text-[10px] uppercase tracking-wider text-faint">severity</span>
          <select value={rule.severity} disabled={busy || !canEdit} onChange={(e) => save({ severity: e.target.value })}
            className="mt-0.5 block h-8 rounded-md border border-line bg-bg px-2 text-xs outline-none focus:border-accent">
            {Object.keys(SEVERITY).map((s) => <option key={s} value={s}>{SEVERITY[s].text}</option>)}
          </select>
        </label>}
        <div className="ml-auto flex gap-2">
          {dirty && <Button onClick={() => setDraft(null)} disabled={busy}>Cancel</Button>}
          {dirty && <Button need="admin" variant="primary" onClick={() => save({ params: draft })} disabled={busy}><Save size={14} /> Save</Button>}
          {!dirty && rule.customized && (
            <Button need="admin" onClick={() => save({ reset: true })} disabled={busy}><RotateCcw size={14} /> Reset to default</Button>
          )}
        </div>
      </div>
      {error && <div className="mx-5 mb-3 text-xs text-critical">{error}</div>}

      <div className="flex flex-wrap items-center gap-x-6 gap-y-1 border-t border-line px-5 py-2.5 text-xs text-muted">
        <span>Total alerts <span className="font-mono text-ink">{fmtNumber(rule.hits)}</span></span>
        <span>Open <span className={`font-mono ${rule.open_hits ? "text-critical" : "text-ink"}`}>{fmtNumber(rule.open_hits)}</span></span>
        <span>Last fired <span className="text-ink">{rule.last_fired ? fmtAgo(rule.last_fired) : "never"}</span></span>
        {rule.hits > 0 && <Link to={`/alerts?status=&rule_id=${rule.id}`} className="ml-auto text-accent hover:underline">View alerts →</Link>}
      </div>
    </div>
  );
}

export default function Rules() {
  const { data: rules, error, refresh } = usePolling(() => api("/api/rules"), 10000);
  const [source, setSource] = useState("");
  const shown = rules?.filter((r) => !source || r.source === source) ?? [];
  const enabled = rules?.filter((r) => r.enabled).length ?? 0;

  return (
    <div className="mx-auto max-w-[1400px] space-y-5">
      <ReadOnlyNote need="admin" what="enable, disable or tune rules" />
      <ErrorBanner error={error} />
      {rules && <CoverageMap rules={rules} />}

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted">
          <span className="font-mono text-ink">{enabled}</span> of {rules?.length ?? 0} rules enabled.
          Thresholds are editable; changes apply to new logs immediately (use <Link to="/alerts" className="text-accent hover:underline">Re-scan</Link> for old ones).
        </p>
        <div className="flex rounded-lg border border-line bg-panel p-0.5">
          {["", "auth", "network", "process", "ml"].map((s) => (
            <button key={s} onClick={() => setSource(s)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium capitalize ${source === s ? "bg-accent/15 text-accent" : "text-muted hover:text-ink"}`}>
              {s === "ml" ? "ML" : s || "All sources"}
            </button>
          ))}
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        {shown.map((r) => <RuleCard key={r.id} rule={r} onSaved={refresh} />)}
      </div>
    </div>
  );
}
