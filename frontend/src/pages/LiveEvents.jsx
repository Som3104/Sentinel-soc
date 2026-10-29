import { Fragment, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ChevronRight, Pause, Play, Search, X } from "lucide-react";
import { api } from "../lib/api";
import { usePolling, useRealtimeStatus } from "../lib/usePolling";
import { eventSummary, fmtDate, fmtNumber, fmtTime } from "../lib/format";
import { ErrorBanner, LabelBadge, Panel, Select, SourceBadge } from "../components/ui";

const FILTER_KEYS = ["source", "event_type", "host", "label", "src_ip", "q"];

function EventDetail({ event }) {
  const fields = Object.entries(event).filter(([k, v]) => v !== null && v !== undefined && k !== "raw");
  return (
    <div className="grid grid-cols-2 gap-x-8 gap-y-1.5 px-12 py-4 md:grid-cols-3 xl:grid-cols-4">
      {fields.map(([k, v]) => (
        <div key={k} className="min-w-0">
          <div className="text-[10px] uppercase tracking-wider text-faint">{k}</div>
          <div className="truncate font-mono text-xs text-ink/90" title={String(v)}>{String(v)}</div>
        </div>
      ))}
    </div>
  );
}

export default function LiveEvents() {
  const [params, setParams] = useSearchParams();
  const filters = Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) ?? ""]));
  const [search, setSearch] = useState(filters.q);
  const [paused, setPaused] = useState(false);
  const [expanded, setExpanded] = useState(null);
  const seen = useRef(new Set());
  const [fresh, setFresh] = useState(new Set());

  // Filters live in the URL (?src_ip=...), so links from the Overview page land pre-filtered.
  const setFilter = (key, value) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value) next.set(key, value);
      else next.delete(key);
      return next;
    }, { replace: true });
  };

  // Debounce the search box so we don't hit the API on every keystroke.
  useEffect(() => {
    const id = setTimeout(() => setFilter("q", search.trim()), 350);
    return () => clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  const ws = useRealtimeStatus();
  const { data: options } = usePolling(() => api("/api/events/filters"), 30000);
  const { data: events, error, lastUpdated } = usePolling(
    () => api("/api/events", { ...filters, limit: 200 }),
    3000,
    [params.toString()],
    { paused },
  );

  // When the filters change, everything on screen is "old" - only flash truly new arrivals.
  useEffect(() => { seen.current = new Set(); }, [params.toString()]);
  useEffect(() => {
    if (!events) return;
    const firstLoad = seen.current.size === 0;
    const newIds = new Set();
    events.forEach((e) => {
      if (!seen.current.has(e.id)) {
        if (!firstLoad) newIds.add(e.id);
        seen.current.add(e.id);
      }
    });
    setFresh(newIds);
  }, [events]);

  const activeFilters = FILTER_KEYS.filter((k) => filters[k] && k !== "q");

  return (
    <div className="mx-auto max-w-[1400px]">
      <ErrorBanner error={error} />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="relative">
          <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-faint" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search user, IP, process, host…"
            className="h-9 w-72 rounded-lg border border-line bg-panel-2 pl-9 pr-3 text-sm outline-none placeholder:text-faint focus:border-accent"
          />
        </div>
        <Select value={filters.source} onChange={(v) => setFilter("source", v)} options={options?.sources ?? []} placeholder="All sources" />
        <Select value={filters.event_type} onChange={(v) => setFilter("event_type", v)} options={options?.event_types ?? []} placeholder="All event types" />
        <Select value={filters.host} onChange={(v) => setFilter("host", v)} options={options?.hosts ?? []} placeholder="All hosts" />
        <Select value={filters.label} onChange={(v) => setFilter("label", v)} options={options?.labels ?? []} placeholder="All labels" />

        <div className="ml-auto flex items-center gap-3">
          <span className="flex items-center gap-2 text-xs text-muted">
            <span className={`h-2 w-2 rounded-full ${paused ? "bg-faint" : "pulse-dot bg-ok"}`} />
            {paused ? "Paused" : ws === "live" ? "Live · pushed instantly" : "Polling · every 3s"}
            {lastUpdated && <span className="font-mono text-faint">{lastUpdated.toLocaleTimeString([], { hour12: false })}</span>}
          </span>
          <button
            onClick={() => setPaused((p) => !p)}
            className="flex h-9 items-center gap-1.5 rounded-lg border border-line bg-panel-2 px-3 text-sm hover:border-accent"
          >
            {paused ? <Play size={14} /> : <Pause size={14} />}
            {paused ? "Resume" : "Pause"}
          </button>
        </div>
      </div>

      {(activeFilters.length > 0) && (
        <div className="mb-3 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-faint">Filtered by</span>
          {activeFilters.map((k) => (
            <button key={k} onClick={() => setFilter(k, "")} className="flex items-center gap-1 rounded-md border border-accent/30 bg-accent/10 px-2 py-1 text-accent">
              <span className="text-accent/70">{k}:</span><span className="font-mono">{filters[k]}</span><X size={12} />
            </button>
          ))}
        </div>
      )}

      <Panel
        title="Event stream"
        subtitle={`Showing the latest ${fmtNumber(events?.length ?? 0)} matching events · click a row for full details`}
        bodyClass="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                <th className="w-8" />
                <th className="py-2.5 pr-4 font-medium">Time</th>
                <th className="pr-4 font-medium">Source</th>
                <th className="pr-4 font-medium">Event</th>
                <th className="pr-4 font-medium">Host</th>
                <th className="pr-4 font-medium">Source IP</th>
                <th className="pr-4 font-medium">Details</th>
                <th className="pr-5 font-medium">Truth</th>
              </tr>
            </thead>
            <tbody>
              {events?.map((e) => {
                const open = expanded === e.id;
                return (
                  <Fragment key={e.id}>
                    <tr
                      onClick={() => setExpanded(open ? null : e.id)}
                      className={`cursor-pointer border-b border-line/50 hover:bg-panel-2 ${fresh.has(e.id) ? "row-new" : ""} ${open ? "bg-panel-2" : ""}`}
                    >
                      <td className="pl-3 text-faint"><ChevronRight size={14} className={`transition-transform ${open ? "rotate-90" : ""}`} /></td>
                      <td className="whitespace-nowrap py-2 pr-4 font-mono text-xs">
                        {fmtTime(e.timestamp)} <span className="text-faint">{fmtDate(e.timestamp)}</span>
                      </td>
                      <td className="pr-4"><SourceBadge source={e.source} /></td>
                      <td className="whitespace-nowrap pr-4 font-mono text-xs">{e.event_type}</td>
                      <td className="whitespace-nowrap pr-4 font-mono text-xs text-muted">{e.host}</td>
                      <td className="whitespace-nowrap pr-4">
                        {e.src_ip ? (
                          <button onClick={(ev) => { ev.stopPropagation(); setFilter("src_ip", e.src_ip); }} className="font-mono text-xs text-accent hover:underline">
                            {e.src_ip}
                          </button>
                        ) : <span className="text-faint">—</span>}
                      </td>
                      <td className="max-w-md truncate pr-4 text-xs text-ink/80">{eventSummary(e)}</td>
                      <td className="pr-5"><LabelBadge label={e.label} /></td>
                    </tr>
                    {open && (
                      <tr className="border-b border-line bg-panel-2/60"><td colSpan={8}><EventDetail event={e} /></td></tr>
                    )}
                  </Fragment>
                );
              })}
              {events?.length === 0 && (
                <tr><td colSpan={8} className="py-16 text-center text-sm text-muted">
                  No events match. Try clearing filters, or run the simulator.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
