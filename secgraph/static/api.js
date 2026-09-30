// Thin API client for the console. Credentials live in sessionStorage for the tab's lifetime only.
const KEY = "secgraph.auth";

export class ApiError extends Error {
  constructor(status, code, message, detail) {
    super(message);
    this.status = status;
    this.code = code;
    this.detail = detail || {};
  }
}

export const session = {
  get() {
    try { return JSON.parse(sessionStorage.getItem(KEY) || "null"); } catch { return null; }
  },
  set(value) {
    try { sessionStorage.setItem(KEY, JSON.stringify(value)); } catch { /* storage unavailable: stay signed in for this page only */ }
    this.current = value;
  },
  clear() {
    try { sessionStorage.removeItem(KEY); } catch { /* ignore */ }
    this.current = null;
  },
  current: null,
};
session.current = session.get();

let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

function authHeaders() {
  const auth = session.current;
  if (!auth) return {};
  return auth.kind === "key" ? { "X-API-Key": auth.value } : { Authorization: `Bearer ${auth.value}` };
}

export async function api(method, path, { query, body, raw, headers } = {}) {
  let url = path;
  if (query) {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(query)) {
      if (value !== undefined && value !== null && value !== "") params.set(key, value);
    }
    const text = params.toString();
    if (text) url += `?${text}`;
  }
  const init = { method, headers: { Accept: "application/json", ...authHeaders(), ...(headers || {}) } };
  if (raw !== undefined) {
    init.body = raw;
  } else if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(url, init);
  } catch {
    throw new ApiError(0, "network", "The server could not be reached.");
  }
  if (response.status === 204) return null;
  let data = null;
  const text = await response.text();
  if (text) {
    try { data = JSON.parse(text); } catch { data = null; }
  }
  if (!response.ok) {
    const error = (data && data.error) || {};
    if (response.status === 401 && session.current && !path.endsWith("/auth/token")) onUnauthorized();
    throw new ApiError(response.status, error.code || "error", error.message || `Request failed (${response.status})`, error.detail);
  }
  return data;
}

export const get = (path, query) => api("GET", path, { query });
export const post = (path, body, query) => api("POST", path, { body, query });
export const patch = (path, body) => api("PATCH", path, { body });
export const del = (path) => api("DELETE", path);
