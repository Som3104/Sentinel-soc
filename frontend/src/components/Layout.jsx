import { useEffect, useRef, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import {
  Activity, Brain, FlaskConical, KeyRound, LayoutDashboard, ListChecks, LogOut, ScrollText,
  ShieldAlert, ShieldBan, Siren, Users as UsersIcon,
} from "lucide-react";
import { api, apiSend } from "../lib/api";
import { clearSession, roleAllows, useUser } from "../lib/auth";
import { RoleBadge } from "./ui";
import { usePolling, useRealtimeStatus } from "../lib/usePolling";
import Toasts from "./Toasts";

// `phase` marks pages that aren't built yet - they show a small tag in the sidebar (none left!).
export const NAV = [
  { group: "Monitor", items: [
    { to: "/", label: "Overview", icon: LayoutDashboard },
    { to: "/events", label: "Live Events", icon: Activity },
  ]},
  { group: "Detect", items: [
    { to: "/alerts", label: "Alerts", icon: ShieldAlert, badge: "alerts" },
    { to: "/rules", label: "Detection Rules", icon: ListChecks },
    { to: "/models", label: "ML Models", icon: Brain },
  ]},
  { group: "Respond", items: [
    { to: "/incidents", label: "Incidents", icon: Siren, badge: "incidents" },
    { to: "/response", label: "Response Center", icon: ShieldBan, badge: "approvals" },
    { to: "/audit", label: "Audit Log", icon: ScrollText },
  ]},
  { group: "Lab", items: [
    { to: "/simulator", label: "Attack Simulator", icon: FlaskConical, badge: "live" },
  ]},
  { group: "Admin", need: "admin", items: [
    { to: "/users", label: "Users & Access", icon: UsersIcon },
  ]},
];

const ALL_ITEMS = NAV.flatMap((g) => g.items);

// Backend health + how the dashboard is getting its data:
//   Live    - WebSocket connected, changes are pushed instantly
//   Polling - backend up but WebSocket not connected yet (pages poll every few seconds)
//   Offline - backend unreachable
function ApiStatus() {
  const [ok, setOk] = useState(null);
  const ws = useRealtimeStatus();
  useEffect(() => {
    const check = () => api("/health").then(() => setOk(true)).catch(() => setOk(false));
    check();
    const id = setInterval(check, 5000);
    return () => clearInterval(id);
  }, []);
  const state = ok === null ? "connecting" : !ok ? "offline" : ws === "live" ? "live" : "polling";
  const { color, text, title } = {
    connecting: { color: "var(--color-muted)", text: "Connecting…", title: "" },
    offline: { color: "var(--color-critical)", text: "Backend offline", title: "Can't reach the API on port 8000" },
    polling: { color: "var(--color-medium)", text: "Online · polling", title: "Real-time channel not connected; refreshing every few seconds" },
    live: { color: "var(--color-ok)", text: "Live", title: "Connected over WebSocket: changes appear instantly" },
  }[state];
  return (
    <div title={title} className="flex items-center gap-2 rounded-full border border-line bg-panel px-3 py-1.5 text-xs text-muted">
      <span className="pulse-dot h-2 w-2 rounded-full" style={{ background: color }} />
      {text}
    </div>
  );
}

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="hidden font-mono text-xs text-muted md:block">
      {now.toLocaleTimeString([], { hour12: false })}{" "}
      <span className="text-faint">local</span>{" · "}
      {now.toISOString().slice(11, 19)} <span className="text-faint">UTC</span>
    </div>
  );
}

function UserMenu() {
  const user = useUser();
  const [open, setOpen] = useState(false);
  const [pw, setPw] = useState({ current_password: "", new_password: "" });
  const [msg, setMsg] = useState(null);
  const ref = useRef(null);

  useEffect(() => {
    const close = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  if (!user) return null;
  const initials = (user.display_name.replace(/\(.*\)/, "").match(/\b[A-Za-z]/g) ?? [user.username[0]]).slice(0, 2).join("").toUpperCase();
  const changePassword = async (e) => {
    e.preventDefault();
    try {
      await apiSend("/api/auth/password", "POST", pw);
      setMsg({ ok: true, text: "Password changed." });
      setPw({ current_password: "", new_password: "" });
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    }
  };
  const input = "h-8 w-full rounded-md border border-line bg-bg px-2.5 text-xs outline-none focus:border-accent";

  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-2 rounded-full border border-line bg-panel py-1 pl-1 pr-3 text-xs hover:border-accent">
        <span className="grid h-6 w-6 place-items-center rounded-full bg-accent/15 font-semibold text-accent">{initials}</span>
        <span className="hidden text-ink sm:inline">{user.username}</span>
        <RoleBadge role={user.role} />
      </button>
      {open && (
        <div className="absolute right-0 z-40 mt-2 w-72 rounded-xl border border-line bg-panel p-3 shadow-2xl shadow-black/40">
          <div className="px-1">
            <div className="text-sm font-medium">{user.display_name}</div>
            <div className="font-mono text-xs text-muted">{user.username} · {user.role}</div>
          </div>
          <form onSubmit={changePassword} className="mt-3 space-y-2 border-t border-line pt-3">
            <div className="flex items-center gap-1.5 text-xs font-medium text-muted"><KeyRound size={12} /> Change password</div>
            <input type="password" placeholder="Current password" value={pw.current_password} autoComplete="current-password"
              onChange={(e) => setPw({ ...pw, current_password: e.target.value })} className={input} />
            <input type="password" placeholder="New password (8+ characters)" value={pw.new_password} autoComplete="new-password"
              onChange={(e) => setPw({ ...pw, new_password: e.target.value })} className={input} />
            <button type="submit" disabled={!pw.current_password || pw.new_password.length < 8}
              className="h-8 w-full rounded-md border border-line bg-panel-2 text-xs font-medium hover:border-accent disabled:opacity-40">Update password</button>
            {msg && <div className={`text-[11px] ${msg.ok ? "text-ok" : "text-critical"}`}>{msg.text}</div>}
          </form>
          <button onClick={clearSession}
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-md border border-critical/30 bg-critical/10 py-2 text-xs font-medium text-critical hover:bg-critical/20">
            <LogOut size={13} /> Sign out
          </button>
        </div>
      )}
    </div>
  );
}

function useSummary(path) {
  return usePolling(() => api(path), 5000).data;
}

export default function Layout({ children }) {
  const { pathname } = useLocation();
  const user = useUser();
  const nav = NAV.filter((g) => !g.need || roleAllows(user?.role, g.need));
  const alertSummary = useSummary("/api/alerts/summary");
  const incidentSummary = useSummary("/api/incidents/summary");
  const critIncidents = incidentSummary?.active_by_severity?.critical ?? 0;
  const responseSummary = useSummary("/api/response/summary");
  const approvals = responseSummary?.pending_approvals ?? 0;
  const critical = alertSummary?.open_by_severity?.critical ?? 0;
  const labStatus = useSummary("/api/lab/status");
  const liveTraffic = labStatus?.live?.running;
  const current = ALL_ITEMS.find((i) => i.to === pathname)
    ?? ALL_ITEMS.find((i) => i.to !== "/" && pathname.startsWith(`${i.to}/`)) ?? ALL_ITEMS[0];

  return (
    <div className="flex h-full">
      <aside className="flex w-60 shrink-0 flex-col border-r border-line bg-panel/60">
        <div className="flex items-center gap-2.5 px-5 py-5">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-accent/15 ring-1 ring-accent/40">
            <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="var(--color-accent)" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <div>
            <div className="text-sm font-semibold tracking-wide">Sentinel SOC</div>
            <div className="text-[11px] text-muted">Threat Detection Lab</div>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 pb-4">
          {nav.map((group) => (
            <div key={group.group} className="mt-4">
              <div className="px-2 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-faint">{group.group}</div>
              {group.items.map(({ to, label, icon: Icon, phase, badge }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === "/"}
                  className={({ isActive }) =>
                    `group mb-0.5 flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition-colors ${
                      isActive ? "bg-accent/10 text-ink ring-1 ring-accent/25" : "text-muted hover:bg-panel-2 hover:text-ink"
                    }`
                  }
                >
                  {({ isActive }) => (
                    <>
                      <Icon size={16} className={isActive ? "text-accent" : ""} />
                      <span className="flex-1">{label}</span>
                      {badge === "alerts" && alertSummary?.open > 0 && (
                        <span
                          title={`${alertSummary.open} open alerts, ${critical} critical`}
                          className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] font-semibold ${critical ? "bg-critical text-bg" : "bg-high/20 text-high"}`}
                        >
                          {alertSummary.open}
                        </span>
                      )}
                      {badge === "incidents" && incidentSummary?.active > 0 && (
                        <span
                          title={`${incidentSummary.active} active incidents, ${critIncidents} critical`}
                          className={`rounded-full px-1.5 py-0.5 font-mono text-[10px] font-semibold ${critIncidents ? "bg-critical text-bg" : "bg-high/20 text-high"}`}
                        >
                          {incidentSummary.active}
                        </span>
                      )}
                      {badge === "approvals" && approvals > 0 && (
                        <span title={`${approvals} actions waiting for your approval`}
                          className="rounded-full bg-medium/20 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-medium">
                          {approvals}
                        </span>
                      )}
                      {badge === "live" && liveTraffic && (
                        <span title="Live traffic generator is running"
                          className="flex items-center gap-1 rounded-full bg-ok/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-ok">
                          <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-ok" />LIVE
                        </span>
                      )}
                      {phase && <span className="rounded bg-panel-2 px-1.5 py-0.5 font-mono text-[10px] text-faint">P{phase}</span>}
                    </>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        <div className="border-t border-line px-5 py-3 text-[11px] text-faint">
          Lab environment · simulated traffic only
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center justify-between border-b border-line px-6">
          <h1 className="text-base font-semibold">{current.label}</h1>
          <div className="flex items-center gap-4">
            <Clock />
            <ApiStatus />
            <UserMenu />
          </div>
        </header>
        <main className="bg-grid flex-1 overflow-y-auto px-6 py-6">{children}</main>
      </div>
      <Toasts />
    </div>
  );
}
