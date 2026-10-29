// All calls to the FastAPI backend go through here.
import { clearSession, getToken } from "./auth";

export const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

export async function api(path, params = {}) {
  const url = new URL(path, API_URL);
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
  });
  const res = await fetch(url, { headers: authHeaders() });
  if (res.status === 401) expired();
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} on ${path}`);
  return res.json();
}

// For POST / PATCH calls (triage, rule tuning, running detection).
export async function apiSend(path, method = "POST", body = undefined, params = {}) {
  const url = new URL(path, API_URL);
  Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  const res = await fetch(url, {
    method,
    headers: { ...authHeaders(), ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !path.startsWith("/api/auth/")) expired();
  if (!res.ok) throw new Error(data.detail || `${res.status} ${res.statusText}`);
  return data;
}

function authHeaders() {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

// The server said our token is no longer valid (expired, account disabled): back to sign-in.
function expired() {
  if (getToken()) clearSession();
}
