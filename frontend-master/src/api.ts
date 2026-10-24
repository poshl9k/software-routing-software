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
    if (response.status === 401 && location.pathname !== "/login" && !redirecting) {
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
};
export type MasterTariff = {
  id: number; name: string; device_limit: number; term_days: number;
  price_amount: number | null; created_at: string;
};
export type MasterSubscriber = {
  id: number; display_name: string; telegram_chat_id: string; status: string;
  subscription: { tariff_id: number; tariff_name: string; expires_at: string; status: string } | null;
  device_count: number;
};
export type MasterDevice = {
  id: number; label: string; name: string | null; node_name: string;
  status: string; allowed_ips: string[];
};

export const masterApi = {
  setup: (password: string) => masterRequest<void>("/api/admin/setup", { method: "POST", body: JSON.stringify({ password }) }),
  login: (password: string) => masterRequest<void>("/api/admin/login", { method: "POST", body: JSON.stringify({ password }) }),
  logout: () => masterRequest<void>("/api/admin/logout", { method: "POST" }),
  nodes: () => masterRequest<{ nodes: MasterNode[] }>("/api/master-admin/nodes"),
  addNode: (body: { name: string; bridge_url: string; capacity: number }) =>
    masterRequest<{ node: MasterNode; token: string }>("/api/master-admin/nodes", { method: "POST", body: JSON.stringify(body) }),
  updateNode: (id: number, body: { bridge_url?: string; capacity?: number; enabled?: boolean }) =>
    masterRequest<{ node: MasterNode }>(`/api/master-admin/nodes/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  removeNode: (id: number) => masterRequest<void>(`/api/master-admin/nodes/${id}`, { method: "DELETE" }),
  rotateNodeToken: (id: number) =>
    masterRequest<{ rotated: boolean; token?: string }>(`/api/master-admin/nodes/${id}/rotate-token`, { method: "POST" }),
  tariffs: () => masterRequest<{ tariffs: MasterTariff[] }>("/api/master-admin/tariffs"),
  saveTariff: (body: Partial<MasterTariff> & { name?: string }) =>
    masterRequest<{ tariff: MasterTariff }>(`/api/master-admin/tariffs${body.id ? `/${body.id}` : ""}`,
      { method: body.id ? "PUT" : "POST", body: JSON.stringify(body) }),
  removeTariff: (id: number) => masterRequest<void>(`/api/master-admin/tariffs/${id}`, { method: "DELETE" }),
  subscribers: () => masterRequest<{ subscribers: MasterSubscriber[] }>("/api/master-admin/subscribers"),
  subscriber: (id: number) => masterRequest<{ subscriber: MasterSubscriber; devices: MasterDevice[] }>(`/api/master-admin/subscribers/${id}`),
  assignSubscription: (id: number, body: { tariff_id: number; days?: number }) =>
    masterRequest<{ subscription: MasterSubscriber["subscription"] }>(`/api/master-admin/subscribers/${id}/subscription`,
      { method: "PUT", body: JSON.stringify(body) }),
};
