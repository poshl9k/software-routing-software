export type MasterErrorBody = { error?: { code?: string; message?: string }; code?: string; message?: string };
export class MasterApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = "MasterApiError";
  }
}

let redirecting = false;
export function resetRedirectForTests() { redirecting = false; }

export async function masterRequest<T>(path: `/api/${string}`, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: "include",
      headers: { ...(init.body ? { "Content-Type": "application/json" } : {}), ...init.headers },
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new MasterApiError(0, "network.unavailable", "Нет связи с мастер-порталом");
  }
  const body: unknown = response.status === 204 ? undefined : await response.json().catch(() => undefined);
  if (!response.ok) {
    const payload = body as MasterErrorBody | undefined;
    const code = payload?.error?.code ?? payload?.code ?? `http.${response.status}`;
    if (response.status === 401 && !path.startsWith("/api/portal/") && location.pathname !== "/login" && !redirecting) {
      redirecting = true;
      location.assign("/login");
    }
    throw new MasterApiError(response.status, code, payload?.error?.message ?? payload?.message ?? "Ошибка запроса");
  }
  if (response.status !== 204 && body === undefined) throw new MasterApiError(response.status, "response.invalid", "Некорректный ответ сервера");
  return body as T;
}

export type MasterNode = {
  id: number; name: string; bridge_url: string; capacity: number; enabled: boolean;
  state: "ok" | "stale" | "down"; active_peers: number; last_seen: string | null;
  role: "entry" | "egress" | "both"; public_entry: string | null;
};
export type MasterRuleSet = {
  id: number; kind: "domain" | "ipcidr"; source: string | null; version: string;
  entries: number; sha256: string; created_at: string;
};
export type MasterRuleSets = {
  rulesets: MasterRuleSet[];
  current: Record<string, { kind: string; version: string; entries: number; sha256: string } | null>;
  slots: Record<string, { kind: string; target: string; version: string | null }>;
};
export type MasterRuleSetSource = {
  id: number; name: string; kind: "domain" | "ipcidr"; url: string; interval_seconds: number;
  version: string | null; last_checked_at: string | null; last_error: string | null;
};
export type MasterTariff = {
  id: number; name: string; device_limit: number; term_days: number;
  price_amount: number | null; created_at: string;
};
export type MasterTelegramSettings = { configured: boolean; public_url: string | null };
export type MasterSubscriber = {
  id: number; display_name: string; telegram_chat_id: string; status: string;
  subscription: { tariff_id: number; tariff_name: string; expires_at: string; status: string } | null;
  device_count: number;
};
export type MasterDevice = {
  id: number; label: string; name: string | null; node_name: string;
  status: string; allowed_ips: string[];
};

export type PortalAccount = { id: number; display_name: string };
export type PortalMe = {
  account: PortalAccount;
  subscription: { status: "active" | "expired"; expires_at: string;
    tariff: { name: string; device_limit: number; term_days: number } | null } | null;
};
export type PortalDevice = {
  id: number; name: string | null; label: string; status: "active" | "inactive" | "pending" | "removed";
  allowed_ips: string[]; applied: boolean; last_handshake: number | null;
  pending_op?: string;
};
export type PortalDevices = { devices: PortalDevice[] };
export type PortalOperation = { status: "applied" | "pending"; operation_id: number; device_id: number };
export type PortalSubscription = { active: boolean; created_at: string | null; last_used_at: string | null;
  url: string | null; qr: string | null; clash_url: string | null };

export type PortalExportFormat = "conf" | "qr" | "amnezia" | "amnezia-qr" | "mihomo" | "vless";

async function exportPortal(id: number, format: PortalExportFormat): Promise<Response> {
  const response = await fetch(`/api/portal/devices/${id}/export?format=${format}`, {
    credentials: "include", cache: "no-store",
  });
  if (!response.ok) {
    const body = await response.json().catch(() => undefined) as MasterErrorBody | undefined;
    const code = body?.error?.code ?? body?.code ?? `http.${response.status}`;
    throw new MasterApiError(response.status, code,
      body?.error?.message ?? body?.message ?? "Не удалось экспортировать конфигурацию");
  }
  return response;
}

async function exportPortalDevice(id: number, format: PortalExportFormat): Promise<Blob> {
  return (await exportPortal(id, format)).blob();
}

// The Amnezia container is a text URI, so it is read as text rather than a blob:
// jsdom's Blob has no .text() and the client only needs the string.
async function exportPortalText(id: number, format: PortalExportFormat): Promise<string> {
  return (await exportPortal(id, format)).text();
}

export const portalApi = {
  loginLink: (token: string) => masterRequest<PortalAccount>("/api/portal/login/link", {
    method: "POST", body: JSON.stringify({ token }),
  }),
  rotateLoginLink: () => masterRequest<void>("/api/portal/link/rotate", { method: "POST" }),
  magic: (token: string) => masterRequest<PortalAccount>("/api/portal/login/magic", {
    method: "POST", body: JSON.stringify({ token }),
  }),
  me: () => masterRequest<PortalMe>("/api/portal/me"),
  devices: () => masterRequest<PortalDevices>("/api/portal/devices"),
  createDevice: (label: string) => masterRequest<PortalOperation>(
    "/api/portal/devices", { method: "POST", body: JSON.stringify({ label }) }),
  removeDevice: (id: number) => masterRequest<PortalOperation>(`/api/portal/devices/${id}`, { method: "DELETE" }),
  setDeviceActive: (id: number, active: boolean) => masterRequest<PortalOperation>(
    `/api/portal/devices/${id}/${active ? "activate" : "deactivate"}`, { method: "POST" }),
  exportDevice: exportPortalDevice,
  amneziaUri: (id: number) => exportPortalText(id, "amnezia"),
  subscriptionState: (id: number) => masterRequest<PortalSubscription>(
    `/api/portal/devices/${id}/subscription`),
  issueSubscription: (id: number) => masterRequest<{ created: boolean; url: string | null;
    created_at: string; qr: string | null; clash_url: string | null }>(
    `/api/portal/devices/${id}/subscription`, { method: "POST" }),
  rotateSubscription: (id: number) => masterRequest<{ created: boolean; url: string | null;
    created_at: string; qr: string | null; clash_url: string | null }>(
    `/api/portal/devices/${id}/subscription/rotate`, { method: "POST" }),
  revokeSubscription: (id: number) => masterRequest<void>(
    `/api/portal/devices/${id}/subscription`, { method: "DELETE" }),
  logout: () => masterRequest<void>("/api/portal/logout", { method: "POST" }),
};

export const masterApi = {
  rulesets: () => masterRequest<MasterRuleSets>("/api/master-admin/rulesets"),
  publishRuleSet: (body: { kind: "domain" | "ipcidr"; version: string; content: string;
    source?: string | null }) =>
    masterRequest<MasterRuleSet>("/api/master-admin/rulesets",
      { method: "POST", body: JSON.stringify(body) }),
  importRuleSet: (body: { kind: "domain" | "ipcidr"; version: string; url: string }) =>
    masterRequest<MasterRuleSet>("/api/master-admin/rulesets/import",
      { method: "POST", body: JSON.stringify(body) }),
  ruleSetSources: () => masterRequest<MasterRuleSetSource[]>("/api/master-admin/rulesets/sources"),
  addRuleSetSource: (body: { name: string; kind: "domain" | "ipcidr"; url: string;
    interval_seconds?: number }) =>
    masterRequest<MasterRuleSetSource>("/api/master-admin/rulesets/sources",
      { method: "POST", body: JSON.stringify(body) }),
  deleteRuleSetSource: (id: number) => masterRequest<void>(
    `/api/master-admin/rulesets/sources/${id}`, { method: "DELETE" }),
  refreshRuleSetSource: (id: number) => masterRequest<{ version: string | null; published: boolean }>(
    `/api/master-admin/rulesets/sources/${id}/refresh`, { method: "POST" }),
  setup: (password: string) => masterRequest<void>("/api/admin/setup", { method: "POST", body: JSON.stringify({ password }) }),
  login: (password: string) => masterRequest<void>("/api/admin/login", { method: "POST", body: JSON.stringify({ password }) }),
  logout: () => masterRequest<void>("/api/admin/logout", { method: "POST" }),
  telegramSettings: () => masterRequest<MasterTelegramSettings>("/api/master-admin/settings/telegram"),
  configureTelegram: (body: { bot_token: string; public_url: string }) =>
    masterRequest<MasterTelegramSettings>("/api/master-admin/settings/telegram",
      { method: "PUT", body: JSON.stringify(body) }),
  nodes: () => masterRequest<MasterNode[]>("/api/master-admin/nodes"),
  addNode: (body: { name: string; bridge_url: string; capacity: number;
    role?: "entry" | "egress" | "both"; public_entry?: string | null }) =>
    masterRequest<MasterNode & { token: string }>("/api/master-admin/nodes", { method: "POST", body: JSON.stringify(body) }),
  updateNode: (id: number, body: { bridge_url?: string; capacity?: number; enabled?: boolean;
    role?: "entry" | "egress" | "both"; public_entry?: string }) =>
    masterRequest<MasterNode>(`/api/master-admin/nodes/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  removeNode: (id: number) => masterRequest<void>(`/api/master-admin/nodes/${id}`, { method: "DELETE" }),
  reissueNodeToken: (id: number) =>
    masterRequest<{ token: string }>(`/api/master-admin/nodes/${id}/reissue-token`, { method: "POST" }),
  rotateNodeToken: (id: number) =>
    masterRequest<{ rotated: boolean }>(`/api/master-admin/nodes/${id}/rotate-token`, { method: "POST" }),
  tariffs: () => masterRequest<MasterTariff[]>("/api/master-admin/tariffs"),
  saveTariff: (body: Partial<MasterTariff> & { name?: string }) =>
    masterRequest<MasterTariff>(`/api/master-admin/tariffs${body.id ? `/${body.id}` : ""}`,
      { method: body.id ? "PUT" : "POST", body: JSON.stringify({ name: body.name,
        device_limit: body.device_limit, term_days: body.term_days, price_amount: body.price_amount ?? null }) }),
  removeTariff: (id: number) => masterRequest<void>(`/api/master-admin/tariffs/${id}`, { method: "DELETE" }),
  subscribers: () => masterRequest<MasterSubscriber[]>("/api/master-admin/subscribers"),
  createSubscriber: (body: { display_name: string; telegram_chat_id: string }) =>
    masterRequest<MasterSubscriber>("/api/master-admin/subscribers",
      { method: "POST", body: JSON.stringify(body) }),
  subscriber: (id: number) => masterRequest<MasterSubscriber & { devices: MasterDevice[] }>(`/api/master-admin/subscribers/${id}`),
  assignSubscription: (id: number, body: { tariff_id: number; days?: number }) =>
    masterRequest<NonNullable<MasterSubscriber["subscription"]>>(`/api/master-admin/subscribers/${id}/subscription`,
      { method: "PUT", body: JSON.stringify(body) }),
};
