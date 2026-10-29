// The signed-in session (Phase 8).
//
// The token from POST /api/auth/login is kept in localStorage, so a page refresh doesn't log
// you out, and sent as "Authorization: Bearer <token>" on every API call. The server checks
// it on every request; the UI only uses the role to hide or disable buttons for convenience.
// Real enforcement is always on the server (auth/permissions.py).
import { useSyncExternalStore } from "react";

const KEY = "sentinel-soc-session";
const RANK = { viewer: 0, analyst: 1, admin: 2 };
const listeners = new Set();

function load() {
  try {
    const s = JSON.parse(localStorage.getItem(KEY) || "null");
    return s && s.expires_at * 1000 > Date.now() ? s : null;
  } catch {
    return null;
  }
}

let session = load();     // { access_token, expires_at, user }

function emit() { listeners.forEach((fn) => fn()); }

export function setSession(s) {
  session = s;
  try {
    if (s) localStorage.setItem(KEY, JSON.stringify(s));
    else localStorage.removeItem(KEY);
  } catch { /* private window: session lasts until the tab closes */ }
  emit();
}

export const clearSession = () => setSession(null);
export const getToken = () => session?.access_token ?? null;
export const getUser = () => session?.user ?? null;

export function updateUser(user) {
  if (session) setSession({ ...session, user });
}

export function onSessionChange(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// Log out automatically when the token expires (8 h, one shift).
setInterval(() => { if (session && session.expires_at * 1000 <= Date.now()) clearSession(); }, 30000);

/** The signed-in user, re-rendering on login/logout. */
export function useUser() {
  return useSyncExternalStore(onSessionChange, getUser);
}

export const roleAllows = (role, needed) => (RANK[role] ?? -1) >= RANK[needed];

/** true if the signed-in user's role is at least `needed` ("viewer" | "analyst" | "admin"). */
export function useCan(needed) {
  const user = useUser();
  return !needed || roleAllows(user?.role, needed);
}
