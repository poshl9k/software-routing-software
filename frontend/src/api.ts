import type {
  HostInterface,
  ApplyRequest,
  ApplyResult,
  Configuration,
  ConfigurationVersion,
  Credentials,
  ErrorBody,
  User,
  Alias, DHCPLease, ImportPreview, PingResult,
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
export const api = {
  hostInterfaces: () => request<HostInterface[]>("/api/host/interfaces"),
  keygenTunnel: (protocol: "wg" | "awg") => post<{ private_key: string; public_key: string; obfuscation?: Record<string, number> }>("/api/keygen/tunnel", { protocol }),
  keygenPeer: () => post<{ preshared_key: string }>("/api/keygen/peer", {}),
  keygenPeerKeypair: () => post<{ private_key: string; public_key: string }>("/api/keygen/peer-keypair", {}),
  versions: (signal?: AbortSignal) =>
    request<ConfigurationVersion[]>("/api/versions", { signal }),
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
  confirm: (version_id: number) =>
    post<ApplyResult>("/api/confirm", { version_id }),
  rollback: () => post<ApplyResult>("/api/rollback", {}),
  diff: (before: number, after: number) =>
    request<unknown[]>(`/api/diff/${before}/${after}`),
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
  backupExport: (include_secrets: boolean, password?: string) => request<{ schema_version: number; versions: unknown[]; users: unknown[] }>(`/api/backup/export?include_secrets=${include_secrets}${password ? `&password=${encodeURIComponent(password)}` : ""}`),
  backupRestore: (body: { schema_version: number; versions: unknown[]; password?: string }) => post<{ restored: number }>("/api/backup/restore", body),
  ping: (body: { host: string; count: number; source_interface?: string }) => post<PingResult>("/api/diag/ping", body),
  traceroute: (host: string) => post<string[]>("/api/diag/traceroute", { host }),
  rulesCounters: () => request<Record<string, { packets: number; bytes: number }>>("/api/diag/rules-counters"),
};

async function responseError(response: Response): Promise<ApiError> {
  const body = await response.json().catch(() => undefined) as Partial<ErrorBody> | undefined;
  return new ApiError(response.status, body?.code ?? `http.${response.status}`, body?.message ?? "Ошибка запроса", Array.isArray(body?.details) ? body.details : []);
}
