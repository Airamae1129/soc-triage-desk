// Client for the SOC Triage Playbook API (same origin, session cookie).
// Every state-changing request carries X-Requested-With, which the server requires (CSRF guard).

const API = "/api";

export class ApiError extends Error {
  constructor(status, code, message, details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

// Listeners for "the server is unreachable" and "your session ended" (App shows a banner / login).
const listeners = { offline: new Set(), unauthorized: new Set() };
export const onApiEvent = (kind, fn) => { listeners[kind].add(fn); return () => listeners[kind].delete(fn); };
const emit = (kind, v) => listeners[kind].forEach((f) => f(v));

export async function api(path, { method = "GET", body, signal } = {}) {
  let res;
  try {
    res = await fetch(`${API}${path}`, {
      method,
      credentials: "same-origin",
      signal,
      headers: { Accept: "application/json", "X-Requested-With": "XMLHttpRequest", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    if (e?.name === "AbortError") throw e;
    emit("offline", true);
    throw new ApiError(0, "offline", "Can't reach the SOC Triage Playbook server. Check that it is running and your network connection.");
  }
  emit("offline", false);
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = json?.error || {};
    if (res.status === 401 && !path.startsWith("/auth/")) emit("unauthorized", true);
    throw new ApiError(res.status, err.code || "error", err.message || `Request failed (HTTP ${res.status})`, err.details);
  }
  return json;
}

const enc = encodeURIComponent;

// ---- auth / users / audit ----
export const login = (username, password) => api("/auth/login", { method: "POST", body: { username, password } });
export const logout = () => api("/auth/logout", { method: "POST" });
export const getMe = () => api("/auth/me");
export const listUsers = () => api("/users");
export const createUser = (u) => api("/users", { method: "POST", body: u });
export const updateUser = (id, patch) => api(`/users/${id}`, { method: "PATCH", body: patch });
export const getAudit = (limit = 200) => api(`/audit?limit=${limit}`);

// ---- assessments ----
export const listAssessments = (limit = 300) => api(`/assessments?limit=${limit}`);
export const saveAssessment = (form, snapshot) => api("/assessments", { method: "POST", body: { form, snapshot } });
export const updateAssessment = (id, form, snapshot) => api(`/assessments/${id}`, { method: "PUT", body: { form, ...(snapshot ? { snapshot } : {}) } });
export const escalate = (id, noteText) => api(`/assessments/${id}/escalate`, { method: "POST", body: { noteText } });
export const unescalate = (id) => api(`/assessments/${id}/escalate`, { method: "DELETE" });
export const setStatus = (id, status) => api(`/assessments/${id}/status`, { method: "PATCH", body: { status } });
export const getNotes = (id) => api(`/assessments/${id}/notes`);
export const addNote = (id, note) => api(`/assessments/${id}/notes`, { method: "POST", body: note });
export const deleteNote = (noteId) => api(`/notes/${noteId}`, { method: "DELETE" });
export const getChecklist = (id) => api(`/assessments/${id}/checklist`);
export const setChecklistItem = (id, item, done) => api(`/assessments/${id}/checklist`, { method: "PUT", body: { item, done } });
export const getAssessmentOsint = (id) => api(`/assessments/${id}/osint`);
export const attachOsint = (id, indicator, verdict, note) => api(`/assessments/${id}/osint/${enc(indicator)}`, { method: "PUT", body: { verdict, note } });

// ---- playbooks ----
export const listPlaybooks = () => api("/playbooks");
export const savePlaybook = (client, pb) => api(`/playbooks/${enc(client)}`, { method: "PUT", body: pb });

// ---- OSINT ----
export const getProviders = () => api("/osint/providers");
export const osintLookup = (indicator, { type, force, providers } = {}) => api("/osint/lookup", { method: "POST", body: { indicator, ...(type ? { type } : {}), ...(force ? { force } : {}), ...(providers ? { providers } : {}) } });
export const getWorkspace = () => api("/osint/workspace");
export const addToWorkspace = (indicators) => api("/osint/workspace", { method: "POST", body: { indicators } });
export const patchWorkspace = (indicator, patch) => api(`/osint/workspace/${enc(indicator)}`, { method: "PATCH", body: patch });
export const removeFromWorkspace = (indicator) => api(`/osint/workspace/${enc(indicator)}`, { method: "DELETE" });
export const clearWorkspace = () => api("/osint/workspace", { method: "DELETE" });
export const takeScreenshot = (url) => api("/osint/screenshot", { method: "POST", body: { url, confirmed: true } });
export const deleteScreenshot = (id) => api(`/osint/screenshot/${id}`, { method: "DELETE" });
export const urlscanScan = (url) => api("/osint/urlscan/scan", { method: "POST", body: { url, confirmed: true } });

// ---- AI ----
export const aiStatus = () => api("/ai/status");
export const aiDraftReport = (assessmentId, signal) => api("/ai/draft-report", { method: "POST", body: { assessmentId }, signal });
export const aiExplainLine = (line, assessmentId, signal) => api("/ai/explain-line", { method: "POST", body: { line, ...(assessmentId ? { assessmentId } : {}) }, signal });
export const aiReadScreenshot = (image, note, assessmentId, signal) => api("/ai/read-screenshot", { method: "POST", body: { image, ...(note ? { note } : {}), ...(assessmentId ? { assessmentId } : {}) }, signal });
export const aiChat = (assessmentId, messages, signal, pasted) => api("/ai/chat", { method: "POST", body: { ...(assessmentId ? { assessmentId } : {}), ...(pasted ? { pasted } : {}), messages }, signal });
export const aiDraftPasted = (pasted, signal) => api("/ai/draft-report", { method: "POST", body: { pasted }, signal });

export const cleanAi = (s) => String(s || "").replace(/\*\*(.+?)\*\*/g, "$1").replace(/^#{1,6}\s+/gm, "");
