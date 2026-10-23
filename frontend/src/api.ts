import type {
  HostInterface,
  HostManagement,
  HostProfile,
  ApplyRequest,
  ApplyResult,
  ApplyMarker,
  Configuration,
  ConfigurationVersion,
  DiffResponse,
  Credentials,
  ErrorBody,
  User,
  TProxyPreview,
  Alias, DHCPLease, ImportPreview, PingResult,
  RuleSetStatus, RuleSetUpdate, CatalogResponse,
  UpdateStatus, UpdateStart, ServiceStatusResponse,
  ProxySubscription, SubscriptionPreview, SubscriptionRefresh, SubscriptionMember,
  RuntimeEngine, RuntimeConnections, RuntimeLogEntry, RuntimeProxies, RuntimeProxyDelay,
  Tariff, Subscription,
} from "./types";
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details: unknown[] = [],
  ) {
    super(message);
    this.name = "ApiError";
  }
}
export async function request<T>(
  path: `/api/${string}`,
  init: RequestInit = {},
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: "include",
      headers: {
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...init.headers,
      },
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError")
      throw error;
    throw new ApiError(0, "network.unavailable", "Нет связи с панелью");
  }
  const body: unknown =
    response.status === 204
      ? undefined
      : await response.json().catch(() => undefined);
  if (!response.ok) {
    const error = body as Partial<ErrorBody> | undefined;
    throw new ApiError(
      response.status,
      error?.code ?? `http.${response.status}`,
      error?.message ?? "Ошибка запроса",
      Array.isArray(error?.details) ? error.details : [],
    );
  }
  if (response.status !== 204 && body === undefined)
    throw new ApiError(
      response.status,
      "response.invalid",
      "Некорректный ответ сервера",
    );
  return body as T;
}
const post = <T>(path: `/api/${string}`, body: unknown) =>
  request<T>(path, { method: "POST", body: JSON.stringify(body) });
const put = <T>(path: `/api/${string}`, body: unknown) =>
  request<T>(path, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
export const api = {
  hostInterfaces: () => request<HostInterface[]>("/api/host/interfaces"),
  hostManagement: () => request<HostManagement | null>("/api/host/management"),
  hostProfile: () => request<HostProfile>("/api/host/profile"),
  /** Publish the panel under an operator-supplied domain (ADR-0025); null clears it. */
  setPanelDomain: (hostname: string | null) =>
    request<HostManagement>("/api/host/panel-domain", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hostname }),
    }),
  hostAddresses: () => request<Record<string, string[]>>("/api/host/addresses"),
  serviceStatus: (signal?: AbortSignal) => request<ServiceStatusResponse>("/api/status/services", { signal }),
  keygenTunnel: (protocol: "wg" | "awg") => post<{
    private_key: string; public_key: string; obfuscation?: Record<string, number | string>;
    header_protection_key?: string; random_trailers?: boolean; disable_cookies?: boolean;
    listen_port?: number;
  }>("/api/keygen/tunnel", { protocol }),
  keygenPeer: () => post<{ preshared_key: string }>("/api/keygen/peer", {}),
  keygenPeerKeypair: () => post<{ private_key: string; public_key: string }>("/api/keygen/peer-keypair", {}),
  versions: (signal?: AbortSignal) =>
    request<ConfigurationVersion[]>("/api/versions", { signal }),
  previewTproxy: () => request<TProxyPreview>("/api/draft/tproxy/preview"),
  setup: (body: Credentials) => post<User>("/api/setup", body),
  login: (body: Credentials) => post<User>("/api/auth/login", body),
  me: () => request<User>("/api/auth/me"),
  logout: () => post<void>("/api/auth/logout", {}),
  createDraft: (body: Configuration) =>
    post<ConfigurationVersion>("/api/draft", body),
  updateDraft: (body: Configuration) =>
    request<ConfigurationVersion>("/api/draft", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
  deleteDraft: () => request<void>("/api/draft", { method: "DELETE" }),
  apply: (body: ApplyRequest) => post<ApplyResult>("/api/apply", body),
  applyStatus: (signal?: AbortSignal) =>
    request<ApplyMarker | null>("/api/apply/status", { signal }),
  confirm: (version_id: number) =>
    post<ApplyResult>("/api/confirm", { version_id }),
  rollback: () => post<ApplyResult>("/api/rollback", {}),
  diff: (before: number, after: number): Promise<DiffResponse> =>
    request<DiffResponse>(`/api/diff/${before}/${after}`),
  exportAliases: async (format: "json" | "txt" | "csv", names: string[] | null) => {
    const response = await fetch("/api/aliases/export", { method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ format, names }) });
    if (!response.ok) throw await responseError(response);
    return response.blob();
  },
  previewAliases: (body: { aliases: Alias[] } | { data: string }) => post<ImportPreview>("/api/aliases/import-preview", body),
  importAliases: (aliases: Alias[], mode: "replace" | "skip") => post<{ imported: number }>("/api/aliases/import", { aliases, mode }),
  dhcpLeases: (subnet?: string) => request<DHCPLease[]>(`/api/dhcp/leases${subnet ? `?subnet=${encodeURIComponent(subnet)}` : ""}`),
  searchLeases: (q: string) => request<DHCPLease[]>(`/api/dhcp/leases/search?q=${encodeURIComponent(q)}`),
  peerQr: async (name: string, peer: string) => {
    const response = await fetch(`/api/tunnels/${encodeURIComponent(name)}/peer/${encodeURIComponent(peer)}/qr`, { credentials: "include" });
    if (!response.ok) throw await responseError(response);
    return response.blob();
  },
  peerConf: async (name: string, peer: string) => {
    const response = await fetch(`/api/tunnels/${encodeURIComponent(name)}/peer/${encodeURIComponent(peer)}/conf`, { credentials: "include" });
    if (!response.ok) throw await responseError(response);
    return response.blob();
  },
  /** Amnezia `vpn://` document the app imports natively (AWG tunnels only). */
  peerAmnezia: async (name: string, peer: string) => {
    const response = await fetch(`/api/tunnels/${encodeURIComponent(name)}/peer/${encodeURIComponent(peer)}/amnezia`, { credentials: "include" });
    if (!response.ok) throw await responseError(response);
    return response.blob();
  },
  tunnelActivity: (signal?: AbortSignal) => request<Record<string, Record<string, number | null>>>("/api/tunnels/activity", { signal }),
  backupExport: (include_secrets: boolean, password?: string) => post<{ schema_version: number; versions: unknown[]; users: unknown[] }>("/api/backup/export", { include_secrets, ...(password ? { password } : {}) }),
  backupRestore: (body: { schema_version: number; versions: unknown[]; password?: string; allow_partial: boolean }) => post<{ restored: number; skipped: number }>("/api/backup/restore", body),
  ping: (body: { host: string; count: number; source_interface?: string }) => post<PingResult>("/api/diag/ping", body),
  traceroute: (host: string) => post<string[]>("/api/diag/traceroute", { host }),
  rulesCounters: () => request<Record<string, { packets: number; bytes: number }>>("/api/diag/rules-counters"),
  // Service catalog is panel metadata only; rule-set URLs are never fetched here.
  presetCatalog: () => request<CatalogResponse>("/api/presets/catalog"),
  rulesets: () => request<RuleSetStatus[]>("/api/rulesets"),
  updateRuleset: (body: RuleSetUpdate) =>
    post<Record<string, unknown>>("/api/rulesets/update", {
      kind: "rule_set", format: "auto", authorized: true,
      max_bytes: 5_000_000, timeout: 20, ...body,
    }),
  // Subscription runtime: explicit fetch authorization; results are draft proposals only.
  subscriptionPreview: (subscription: ProxySubscription) =>
    post<SubscriptionPreview>("/api/proxy/subscriptions/preview", { subscription, authorized: true }),
  previewSubscription: (subscription: ProxySubscription) =>
    post<SubscriptionPreview>("/api/proxy/subscriptions/preview", { subscription, authorized: true }),
  refreshSubscription: (name: string) =>
    post<SubscriptionRefresh>(`/api/proxy/subscriptions/${encodeURIComponent(name)}/refresh`, { authorized: true }),
  subscriptionMembers: (name: string) =>
    request<SubscriptionMember[]>(`/api/proxy/subscriptions/${encodeURIComponent(name)}/members`),
  patchSubscription: (name: string, changes: Partial<ProxySubscription>) =>
    request<Partial<ProxySubscription>>(`/api/proxy/subscriptions/${encodeURIComponent(name)}`, {
      method: "PATCH", body: JSON.stringify(changes),
    }),
  updateStatus: () => request<UpdateStatus>("/api/update"),
  applyUpdate: (release: string) => post<UpdateStart>("/api/update", { release }),
  // Runtime API — keep additive: subscriptions use this client independently.
  runtimeEngine: () => request<RuntimeEngine>("/api/runtime/engine"),
  runtimeEngineControl: (action: "start" | "stop" | "restart") =>
    post<RuntimeEngine>(`/api/runtime/engine/${action}`, {}),
  runtimeConnections: () => request<RuntimeConnections>("/api/runtime/connections"),
  runtimeCloseConnection: (id: string) =>
    post<unknown>(`/api/runtime/connections/${encodeURIComponent(id)}/close`, {}),
  runtimeLogs: (level: "debug" | "info" | "warning" | "error" = "info", limit = 50) =>
    request<RuntimeLogEntry[]>(`/api/runtime/logs?level=${level}&limit=${limit}`),
  runtimeProxies: () => request<RuntimeProxies>("/api/runtime/proxies"),
  runtimeSelectProxy: (group: string, name: string) =>
    post<unknown>(`/api/runtime/proxies/${encodeURIComponent(group)}/select`, { name }),
  runtimeProxyDelay: (tag: string, url: string, timeout_ms = 3000) =>
    request<RuntimeProxyDelay>(`/api/runtime/proxies/${encodeURIComponent(tag)}/delay?url=${encodeURIComponent(url)}&timeout_ms=${timeout_ms}`),
};

export const portalAdminApi = {
  listTariffs: () => request<Tariff[]>("/api/portal-admin/tariffs"),
  createTariff: (body: { name: string; device_limit: number; term_days: number; price_amount?: number | null }) =>
    post<Tariff>("/api/portal-admin/tariffs", body),
  updateTariff: (tariff_id: number, body: { name: string; device_limit: number; term_days: number; price_amount?: number | null }) =>
    put<Tariff>(`/api/portal-admin/tariffs/${tariff_id}`, body),
  deleteTariff: (tariff_id: number) =>
    request<void>(`/api/portal-admin/tariffs/${tariff_id}`, { method: "DELETE" }),
  deleteSubscriber: (name: string) =>
    request<void>(`/api/portal-admin/subscribers/${encodeURIComponent(name)}`, { method: "DELETE" }),
  createInvite: (name: string, body: { tariff_id: number; activate?: boolean }) =>
    post<{ token: string; subscriber_name: string; expires_at: string; invite_path?: string; invite_url?: string; password?: string }>(
      `/api/portal-admin/subscribers/${encodeURIComponent(name)}/invite`, body,
    ),
  revokeInvite: (token: string) =>
    request<void>(`/api/portal-admin/invites/${encodeURIComponent(token)}`, { method: "DELETE" }),
  readSubscription: (name: string) =>
    request<Subscription>(`/api/portal-admin/subscribers/${encodeURIComponent(name)}/subscription`),
  updateSubscription: (name: string, body: { tariff_id?: number; renew?: boolean }) =>
    request<Subscription>(`/api/portal-admin/subscribers/${encodeURIComponent(name)}/subscription`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    }),
};

async function responseError(response: Response): Promise<ApiError> {
  const body = await response.json().catch(() => undefined) as Partial<ErrorBody> | undefined;
  return new ApiError(response.status, body?.code ?? `http.${response.status}`, body?.message ?? "Ошибка запроса", Array.isArray(body?.details) ? body.details : []);
}
