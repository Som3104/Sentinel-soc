import { useCallback, useEffect, useRef, useState } from "react";
import { isLive, onMessage, onStatus } from "./realtime";

const LIVE_FALLBACK_MS = 30000;   // with WebSockets up, a slow safety-net poll is enough
const DEBOUNCE_MS = 250;          // a burst of pushes (e.g. a 6-batch demo) -> one re-fetch

/**
 * Calls `fetcher` now, again whenever the backend pushes an update over the WebSocket,
 * and on a timer as a fallback. While the socket is connected the timer slows to 30s;
 * if it drops, we go back to polling every `intervalMs` until it reconnects.
 * (Phase 1-6 pages used plain polling; they all became real-time by changing only this hook.)
 */
export function usePolling(fetcher, intervalMs, deps = [], { paused = false } = {}) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [live, setLive] = useState(isLive());
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const refresh = useCallback(async () => {
    try {
      const result = await fetcherRef.current();
      setData(result);
      setError(null);
      setLastUpdated(new Date());
    } catch (e) {
      setError(e.message || String(e));
    }
  }, []);

  useEffect(() => onStatus((s) => setLive(s === "live")), []);

  // Push: re-fetch shortly after the backend says something changed.
  useEffect(() => {
    if (paused) return undefined;
    let t = null;
    const off = onMessage((msg) => {
      if (msg.type !== "update" && msg.type !== "lab") return;
      clearTimeout(t);
      t = setTimeout(refresh, DEBOUNCE_MS);
    });
    return () => { off(); clearTimeout(t); };
  }, [paused, refresh]);

  // Pull: initial load + fallback timer.
  useEffect(() => {
    refresh();
    if (paused) return undefined;
    const id = setInterval(refresh, live ? Math.max(intervalMs, LIVE_FALLBACK_MS) : intervalMs);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, paused, live, refresh, ...deps]);

  return { data, error, lastUpdated, refresh };
}

/** "connecting" | "live" | "offline" - the WebSocket connection state, for status indicators. */
export function useRealtimeStatus() {
  const [status, setStatus] = useState("connecting");
  useEffect(() => onStatus(setStatus), []);
  return status;
}
