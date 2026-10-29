import { Lock } from "lucide-react";
import { useCan, useUser } from "../lib/auth";
import { ACTION_STATUS, ACTOR, INCIDENT_STATUS, LABEL_STYLES, SEVERITY, SOURCE_COLORS, STATUS, TACTICS, mitreUrl } from "../lib/format";

export function Panel({ title, subtitle, action, children, className = "", bodyClass = "p-5" }) {
  return (
    <section className={`rounded-xl border border-line bg-panel ${className}`}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-3.5">
          <div>
            <h2 className="text-sm font-semibold text-ink">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  );
}

export function StatCard({ label, value, sub, icon: Icon, tone = "var(--color-accent)", dim = false }) {
  return (
    <div className="relative overflow-hidden rounded-xl border border-line bg-panel px-4 py-4">
      <div className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, ${tone}, transparent)`, opacity: dim ? 0.25 : 0.7 }} />
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wider text-muted">{label}</span>
        {Icon && <Icon size={16} style={{ color: tone, opacity: dim ? 0.4 : 1 }} />}
      </div>
      <div className={`mt-2 font-mono text-2xl font-medium ${dim ? "text-faint" : "text-ink"}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-muted">{sub}</div>}
    </div>
  );
}

export function Pill({ color, children, solid = false }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-2 py-0.5 text-[11px] font-medium"
      style={{
        color: solid ? "#070b14" : color,
        background: solid ? color : `color-mix(in srgb, ${color} 14%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 30%, transparent)`,
      }}
    >
      {children}
    </span>
  );
}

export function SourceBadge({ source }) {
  return (
    <Pill color={SOURCE_COLORS[source] ?? "var(--color-muted)"}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: SOURCE_COLORS[source] }} />
      {source}
    </Pill>
  );
}

export function LabelBadge({ label }) {
  const s = LABEL_STYLES[label] ?? { text: label ?? "—", color: "var(--color-muted)" };
  return <Pill color={s.color}>{s.text}</Pill>;
}

export function Select({ value, onChange, options, placeholder }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-9 rounded-lg border border-line bg-panel-2 px-3 text-sm text-ink outline-none focus:border-accent"
    >
      {placeholder !== undefined && <option value="">{placeholder}</option>}
      {options.map((o) => {
        const { value: v, label } = typeof o === "object" ? o : { value: o, label: o };
        return <option key={v} value={v}>{label}</option>;
      })}
    </select>
  );
}

export function ErrorBanner({ error }) {
  if (!error) return null;
  return (
    <div className="mb-5 rounded-lg border border-critical/40 bg-critical/10 px-4 py-3 text-sm text-critical">
      Can't reach the backend ({error}). Is <span className="font-mono">docker compose up</span> running?
    </div>
  );
}

export function SeverityBadge({ severity, score }) {
  const s = SEVERITY[severity] ?? { text: severity, color: "var(--color-muted)" };
  return (
    <span className="inline-flex items-center gap-1.5">
      <Pill color={s.color} solid={severity === "critical"}>{s.text}</Pill>
      {score !== undefined && <span className="font-mono text-xs text-muted">{Math.round(score)}</span>}
    </span>
  );
}

export function StatusBadge({ status }) {
  const s = STATUS[status] ?? STATUS.new;
  return (
    <Pill color={s.color}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.color }} />
      {s.text}
    </Pill>
  );
}

export function MitreChip({ technique, tactic, showTactic = false, asLink = true }) {
  if (!technique) return null;
  if (!asLink) {
    // Used inside other links (a link can't contain a link).
    return (
      <span className="inline-flex items-center rounded-md border border-line bg-panel-2 px-1.5 py-0.5 font-mono text-[11px] text-ink/80">
        {technique}
      </span>
    );
  }
  return (
    <a
      href={mitreUrl(technique)}
      target="_blank"
      rel="noreferrer"
      onClick={(e) => e.stopPropagation()}
      title={`MITRE ATT&CK ${technique}${tactic ? ` · ${tactic}` : ""}`}
      className="inline-flex items-center gap-1 rounded-md border border-line bg-panel-2 px-1.5 py-0.5 font-mono text-[11px] text-ink/80 hover:border-accent hover:text-accent"
    >
      {technique}
      {showTactic && tactic && <span className="font-sans text-faint">· {tactic}</span>}
    </a>
  );
}

export function Toggle({ checked, onChange, disabled, need }) {
  const allowed = useCan(need);
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled || !allowed}
      title={allowed ? undefined : `Needs the ${need} role`}
      onClick={() => onChange(!checked)}
      className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${checked ? "bg-accent" : "bg-line"} disabled:opacity-50`}
    >
      <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${checked ? "left-[18px]" : "left-0.5"}`} />
    </button>
  );
}

// `need`: the minimum role for this action ("analyst" | "admin"). Below it, the button is
// disabled with a tooltip. (Only a convenience: the API enforces the same rules.)
export function Button({ children, onClick, variant = "default", disabled, className = "", type = "button", need, title }) {
  const allowed = useCan(need);
  const styles = {
    default: "border-line bg-panel-2 text-ink hover:border-accent",
    primary: "border-accent/50 bg-accent/15 text-accent hover:bg-accent/25",
    danger: "border-critical/40 bg-critical/10 text-critical hover:bg-critical/20",
  };
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || !allowed}
      title={allowed ? title : `Needs the ${need} role`}
      className={`inline-flex h-9 items-center gap-1.5 rounded-lg border px-3 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${styles[variant]} ${className}`}
    >
      {!allowed && <Lock size={12} />}
      {children}
    </button>
  );
}

export const ROLE_COLOR = { admin: "var(--color-critical)", analyst: "var(--color-accent)", viewer: "var(--color-muted)" };

export function RoleBadge({ role }) {
  return <Pill color={ROLE_COLOR[role] ?? "var(--color-muted)"}>{role}</Pill>;
}

/** A one-line notice at the top of a page when the signed-in role can't change things there. */
export function ReadOnlyNote({ need, what }) {
  const user = useUser();
  const allowed = useCan(need);
  if (allowed || !user) return null;
  return (
    <div className="mb-4 flex items-center gap-2 rounded-lg border border-line bg-panel-2/70 px-4 py-2.5 text-xs text-muted">
      <Lock size={13} className="shrink-0 text-faint" />
      <span>
        You're signed in as <span className="font-medium text-ink">{user.role}</span>, so you can view this page
        but not {what} (needs <span className="font-medium text-ink">{need}</span>).
      </span>
    </div>
  );
}

export function IncidentStatusBadge({ status }) {
  const s = INCIDENT_STATUS[status] ?? INCIDENT_STATUS.open;
  return (
    <Pill color={s.color}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: s.color }} />
      {s.text}
    </Pill>
  );
}

// 14 tiny squares, one per ATT&CK tactic in kill-chain order: lit = this incident reached it.
export function KillChainStrip({ tactics = [], size = "sm" }) {
  const reached = new Set(tactics);
  const box = size === "sm" ? "h-2.5 w-2.5" : "h-3.5 w-3.5";
  return (
    <div className="flex gap-0.5" title={tactics.length ? `ATT&CK tactics: ${tactics.join(" → ")}` : "No ATT&CK tactics"}>
      {TACTICS.map((t) => (
        <span key={t} className={`${box} rounded-[2px] ${reached.has(t) ? "bg-accent" : "bg-panel-2 ring-1 ring-inset ring-line"}`} />
      ))}
    </div>
  );
}

export function ActorBadge({ actor }) {
  const a = ACTOR[actor] ?? ACTOR.system;
  return <Pill color={a.color}>{a.text}</Pill>;
}

export function ActionStatusBadge({ status }) {
  const s = ACTION_STATUS[status] ?? ACTION_STATUS.success;
  return <Pill color={s.color}>{s.text}</Pill>;
}
