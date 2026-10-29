export const SOURCE_COLORS = {
  auth: "var(--color-auth)",
  process: "var(--color-process)",
  network: "var(--color-network)",
};

export const LABEL_STYLES = {
  normal: { text: "Normal", color: "var(--color-ok)" },
  brute_force: { text: "Brute force", color: "var(--color-critical)" },
  port_scan: { text: "Port scan", color: "var(--color-high)" },
  suspicious_process: { text: "Suspicious process", color: "var(--color-high)" },
  exfiltration: { text: "Exfiltration", color: "var(--color-critical)" },
};

export function fmtNumber(n) {
  if (n === null || n === undefined) return "—";
  return new Intl.NumberFormat("en-IN").format(n);
}

export function fmtBytes(b) {
  if (b === null || b === undefined) return "";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = b;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

// Backend timestamps are UTC. SQLite may drop the "+00:00", so add it back.
export function parseTs(ts) {
  if (!ts) return null;
  return new Date(/[zZ]|[+-]\d\d:\d\d$/.test(ts) ? ts : `${ts}Z`);
}

export function fmtTime(ts) {
  const d = parseTs(ts);
  return d ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) : "";
}

export function fmtDate(ts) {
  const d = parseTs(ts);
  return d ? d.toLocaleDateString([], { day: "2-digit", month: "short" }) : "";
}

export function eventSummary(e) {
  if (e.source === "auth") return `${e.event_type === "login_failed" ? "Failed" : "Successful"} login as ${e.user ?? "?"}`;
  if (e.source === "process") return `${e.process_path ?? e.process_name} (parent: ${e.parent_process ?? "?"}) · ${e.cpu_percent ?? 0}% CPU`;
  if (e.source === "network") return `→ ${e.dst_ip}:${e.dst_port} · ${fmtBytes(e.bytes_sent)}`;
  return e.event_type;
}

// ---------------------------------------------------------------- Phase 3: alerts
export const SEVERITY = {
  critical: { text: "Critical", color: "var(--color-critical)", rank: 4 },
  high: { text: "High", color: "var(--color-high)", rank: 3 },
  medium: { text: "Medium", color: "var(--color-medium)", rank: 2 },
  low: { text: "Low", color: "var(--color-low)", rank: 1 },
};

export const STATUS = {
  new: { text: "New", color: "var(--color-accent)" },
  investigating: { text: "Investigating", color: "var(--color-medium)" },
  resolved: { text: "Resolved", color: "var(--color-ok)" },
  false_positive: { text: "False positive", color: "var(--color-muted)" },
};

// MITRE ATT&CK Enterprise tactics, in kill-chain order.
export const TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
  "Collection", "Command and Control", "Exfiltration", "Impact",
];

export function mitreUrl(technique) {
  if (!technique) return null;
  const [base, sub] = technique.split(".");
  return `https://attack.mitre.org/techniques/${base}/${sub ? `${sub}/` : ""}`;
}

export function fmtAgo(ts) {
  const d = parseTs(ts);
  if (!d) return "—";
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function fmtDuration(fromTs, toTs) {
  const a = parseTs(fromTs);
  const b = parseTs(toTs);
  if (!a || !b) return "—";
  const s = Math.max(0, Math.round((b - a) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

// ---------------------------------------------------------------- Phase 5: incidents
export const INCIDENT_STATUS = {
  open: { text: "Open", color: "var(--color-accent)" },
  investigating: { text: "Investigating", color: "var(--color-medium)" },
  contained: { text: "Contained", color: "var(--color-high)" },
  resolved: { text: "Resolved", color: "var(--color-ok)" },
  false_positive: { text: "False positive", color: "var(--color-muted)" },
};

export const CRITICALITY = {
  critical: "var(--color-critical)",
  high: "var(--color-high)",
  medium: "var(--color-medium)",
  low: "var(--color-low)",
};

// ---------------------------------------------------------------- Phase 6: response
export const ACTION_LABEL = {
  block_ip: "Block IP", unblock_ip: "Unblock IP",
  quarantine_process: "Quarantine process", release_process: "Release process",
  isolate_host: "Isolate host", release_host: "Release host",
  alert_status: "Alert status", alert_note: "Alert note",
  incident_status: "Incident status", incident_note: "Incident note",
  rule_updated: "Rule changed", playbook_updated: "Playbook changed", ml_retrained: "ML retrained",
  lab_reset: "Lab reset",
  login: "Signed in", login_failed: "Failed sign-in", account_locked: "Account locked",
  password_changed: "Password changed", user_created: "User created", user_updated: "User changed",
};

export const ACTION_STATUS = {
  success: { text: "Done", color: "var(--color-ok)" },
  pending_approval: { text: "Awaiting approval", color: "var(--color-medium)" },
  rejected: { text: "Rejected", color: "var(--color-muted)" },
  skipped: { text: "Skipped", color: "var(--color-muted)" },
  blocked_by_guardrail: { text: "Stopped by guardrail", color: "var(--color-high)" },
  failed: { text: "Failed", color: "var(--color-critical)" },
};

export const ACTOR = {
  auto: { text: "Automation", color: "var(--color-accent)" },
  analyst: { text: "Person", color: "var(--color-auth)" },
  system: { text: "System", color: "var(--color-muted)" },
};

export const CONTAINMENT_KIND = {
  ip: { text: "Blocked IP" },
  process: { text: "Quarantined process" },
  host: { text: "Isolated host" },
};

export function fmtSeconds(s) {
  if (s === null || s === undefined) return "—";
  if (s < 1) return "<1s";
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}
