import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Search } from "lucide-react";
import { api } from "../lib/api";
import { usePolling } from "../lib/usePolling";
import { ACTION_LABEL, fmtDate, fmtTime } from "../lib/format";
import { ActionStatusBadge, ActorBadge, ErrorBanner, Panel, Pill } from "../components/ui";

const CATEGORIES = [
  { value: "", label: "Everything" },
  { value: "response", label: "Response", help: "blocks, quarantines, isolations, approvals" },
  { value: "case", label: "Case work", help: "alert and incident triage, notes" },
  { value: "config", label: "Configuration", help: "rule tuning, playbooks, ML retraining" },
  { value: "access", label: "Access", help: "sign-ins, failed sign-ins, lockouts, user changes" },
  { value: "system", label: "System", help: "expired blocks, lab resets" },
];
const CATEGORY_COLOR = {
  response: "var(--color-critical)", case: "var(--color-accent)", config: "var(--color-medium)", access: "var(--color-auth)", system: "var(--color-muted)",
};

export default function Audit() {
  const [params, setParams] = useSearchParams();
  const category = params.get("category") ?? "";
  const actor = params.get("actor") ?? "";
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

  const { data: summary } = usePolling(() => api("/api/audit/summary"), 10000);
  const { data: rows, error } = usePolling(
    () => api("/api/audit", { category, actor, q: params.get("q") }), 5000, [category, actor, params.get("q")],
  );

  return (
    <div className="mx-auto max-w-[1400px]">
      <ErrorBanner error={error} />
      <p className="mb-4 text-sm text-muted">
        Every action anyone (or anything) took in the SOC: who, what, when and the outcome. Entries are never edited or deleted.
        {summary && <span className="text-faint"> {summary.total} entries.</span>}
      </p>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search target, result or user…"
            className="h-9 w-64 rounded-lg border border-line bg-panel-2 pl-9 pr-3 text-sm outline-none placeholder:text-faint focus:border-accent" />
        </div>
        <div className="flex flex-wrap rounded-lg border border-line bg-panel p-0.5">
          {CATEGORIES.map((c) => (
            <button key={c.value} title={c.help} onClick={() => setParam("category", c.value)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium ${category === c.value ? "bg-accent/15 text-accent" : "text-muted hover:text-ink"}`}>
              {c.label}
              {summary && c.value && <span className="ml-1.5 font-mono text-faint">{summary.by_category[c.value] ?? 0}</span>}
            </button>
          ))}
        </div>
        <select value={actor} onChange={(e) => setParam("actor", e.target.value)}
          className="h-9 rounded-lg border border-line bg-panel-2 px-3 text-sm outline-none focus:border-accent">
          <option value="">Anyone</option>
          <option value="auto">Automation</option>
          <option value="analyst">People</option>
          <option value="system">System</option>
        </select>
      </div>

      <Panel title="Audit trail" subtitle="Newest first" bodyClass="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                <th className="py-2.5 pl-5 pr-4 font-medium">When</th>
                <th className="pr-4 font-medium">Who</th>
                <th className="pr-4 font-medium">Action</th>
                <th className="pr-4 font-medium">Target</th>
                <th className="pr-4 font-medium">Outcome</th>
                <th className="pr-5 font-medium">Context</th>
              </tr>
            </thead>
            <tbody>
              {rows?.map((r) => (
                <tr key={r.id} className="border-b border-line/50 align-top">
                  <td className="whitespace-nowrap py-2.5 pl-5 pr-4 font-mono text-xs">
                    {fmtTime(r.created_at)} <span className="text-faint">{fmtDate(r.created_at)}</span>
                  </td>
                  <td className="pr-4 pt-2">
                    <ActorBadge actor={r.actor} />
                    {r.username && <div className="mt-0.5 font-mono text-[11px] text-ink/80" title="Signed-in user">{r.username}</div>}
                  </td>
                  <td className="whitespace-nowrap pr-4 pt-2">
                    <span className="mr-2 inline-block h-2 w-2 rounded-full" style={{ background: CATEGORY_COLOR[r.category] }} title={r.category} />
                    {ACTION_LABEL[r.action] ?? r.action}
                  </td>
                  <td className="pr-4 pt-2 font-mono text-xs">{r.target}</td>
                  <td className="max-w-[420px] pr-4 pt-2">
                    <ActionStatusBadge status={r.status} />
                    <div className="mt-0.5 text-xs text-muted">{r.result}</div>
                  </td>
                  <td className="whitespace-nowrap pr-5 pt-2 text-xs">
                    {r.incident_id && <Link to={`/incidents/${r.incident_id}`} className="font-mono text-faint hover:text-accent">INC-{r.incident_id}</Link>}
                    {r.playbook_id && <span className="ml-2"><Pill color="var(--color-muted)">{r.playbook_id}</Pill></span>}
                  </td>
                </tr>
              ))}
              {rows?.length === 0 && (
                <tr><td colSpan={6} className="py-14 text-center text-sm text-muted">No entries match.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
