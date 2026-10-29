// One WebSocket for the whole app (Phase 7).
//
// The backend pushes small messages the moment something changes:
//   {type: "update", source: "ingest" | "lab" | "live" | "api" | "reset", feed: [...]}
//   {type: "lab", live: {...}}            (live traffic generator status)
// Pages subscribe and re-fetch what they show. If the socket drops (backend restarting),
// we reconnect with backoff and pages fall back to polling meanwhile.
import { API_URL } from "./api";
import { getToken, onSessionChange } from "./auth";

// Browsers can't add an Authorization header to a WebSocket, so the token goes in the URL.
const wsUrl = () => `${API_URL.replace(/^http/, "ws")}/ws?token=${encodeURIComponent(getToken() ?? "")}`;
const listeners = new Set();
const FEED_MAX = 60;
let recentFeed = [];             // last pushed feed items, kept across page changes
const statusListeners = new Set();
let socket = null;
let status = "connecting";       // connecting | live | offline
let retry = 0;
let timer = null;

function setStatus(s) {
  status = s;
  statusListeners.forEach((fn) => fn(s));
}

function connect() {
  clearTimeout(timer);
  timer = null;
  if (!getToken()) { setStatus("offline"); return; }     // signed out: nothing to connect
  setStatus(retry ? "offline" : "connecting");
  try {
    socket = new WebSocket(wsUrl());
  } catch {
    scheduleReconnect();
    return;
  }
  socket.onopen = () => {
    const wasDown = retry > 0;
    retry = 0;
    setStatus("live");
    // Anything could have changed while we were disconnected: tell pages to refresh.
    if (wasDown) listeners.forEach((fn) => fn({ type: "update", source: "reconnect", feed: [] }));
  };
  socket.onmessage = (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    remember(msg);
    listeners.forEach((fn) => fn(msg));
  };
  socket.onclose = () => scheduleReconnect();
  socket.onerror = () => socket?.close();
}

function remember(msg) {
  if (msg.type !== "update") return;
  if (msg.source === "reset") { recentFeed = []; return; }
  if (!msg.feed?.length) return;
  const time = new Date(msg.at ?? Date.now()).toLocaleTimeString([], { hour12: false });
  const items = msg.feed.map((f) => ({ ...f, source: msg.source, time, key: `${f.kind}-${f.id}-${msg.at}` }));
  recentFeed = [...items, ...recentFeed].slice(0, FEED_MAX);
}

/** Feed items pushed since this tab opened (newest first). */
export const getFeed = () => recentFeed;

function scheduleReconnect() {
  socket = null;
  if (!getToken()) { setStatus("offline"); return; }
  setStatus("offline");
  retry += 1;
  timer = setTimeout(connect, Math.min(10000, 500 * 2 ** Math.min(retry, 5)));
}

function ensureStarted() {
  if (!socket && !timer && typeof WebSocket !== "undefined") connect();
}

// Sign-in / sign-out: drop the old connection and open one with the new token (or none).
onSessionChange(() => {
  const old = socket;
  socket = null;
  retry = 0;
  if (old) { old.onclose = null; old.close(); }
  recentFeed = [];
  if (typeof WebSocket !== "undefined") connect();
});

/** Subscribe to every server message. Returns an unsubscribe function. */
export function onMessage(fn) {
  ensureStarted();
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** Subscribe to connection status changes ("connecting" | "live" | "offline"). */
export function onStatus(fn) {
  ensureStarted();
  statusListeners.add(fn);
  fn(status);
  return () => statusListeners.delete(fn);
}

export const isLive = () => status === "live";
