export type PortalErrorBody = { error?: { code?: string; message?: string }; code?: string; message?: string };
export class PortalApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
    this.name = "PortalApiError";
  }
}

let redirecting = false;
let loginRedirect = (path: string) => location.assign(path);
export function setLoginRedirectForTests(redirect: (path: string) => void) { loginRedirect = redirect; }
export function resetRedirectForTests() { redirecting = false; loginRedirect = (path: string) => location.assign(path); }

export async function portalRequest<T>(path: `/api/portal/${string}`, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      credentials: "include",
      headers: { ...(init.body ? { "Content-Type": "application/json" } : {}), ...init.headers },
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") throw error;
    throw new PortalApiError(0, "network.unavailable", "Нет связи с порталом");
  }
  const body: unknown = response.status === 204 ? undefined : await response.json().catch(() => undefined);
  if (!response.ok) {
    const payload = body as PortalErrorBody | undefined;
    const code = payload?.error?.code ?? payload?.code ?? `http.${response.status}`;
    if (response.status === 401 && location.pathname !== "/login" && !redirecting) {
      redirecting = true;
      loginRedirect("/login");
    }
    const friendly: Record<string, string> = {
      "portal.device_limit": "Лимит устройств по вашему тарифу достигнут.",
      "portal.subscription_expired": "Подписка истекла. Обратитесь к администратору для продления.",
    };
    throw new PortalApiError(response.status, code, friendly[code] ?? payload?.error?.message ?? payload?.message ?? "Ошибка запроса");
  }
  if (response.status !== 204 && body === undefined) throw new PortalApiError(response.status, "response.invalid", "Некорректный ответ сервера");
  return body as T;
}

const json = (method: string, data?: unknown): RequestInit => ({ method, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
export type PortalMe = {
  username: string;
  subscription?: { tariff_name?: string; status: "active" | "expired"; expires_at?: string; days_remaining?: number; device_limit: number };
  badges?: string[];
};
export type PortalDevice = { name: string; label: string; status: "active" | "inactive" | "removed"; last_handshake?: string | null; applied: boolean };
export type DeviceOperation = { status: "applied" | "pending"; device?: PortalDevice };
export const portalApi = {
  activateInvite: (data: { token: string; password: string; email?: string }) => portalRequest<void>("/api/portal/invite/activate", json("POST", data)),
  login: (data: { username: string; password: string }) => portalRequest<void>("/api/portal/login", json("POST", data)),
  logout: () => portalRequest<void>("/api/portal/logout", json("POST", {})),
  me: () => portalRequest<PortalMe>("/api/portal/me"),
  devices: () => portalRequest<PortalDevice[]>("/api/portal/devices"),
  addDevice: (label: string) => portalRequest<DeviceOperation>("/api/portal/devices", json("POST", { label })),
  removeDevice: (name: string) => portalRequest<DeviceOperation>(`/api/portal/devices/${encodeURIComponent(name)}`, { method: "DELETE", credentials: "include" }),
  setDeviceActive: (name: string, active: boolean) => portalRequest<DeviceOperation>(`/api/portal/devices/${encodeURIComponent(name)}/${active ? "activate" : "deactivate"}`, json("POST", {})),
  exportDevice: async (name: string, format: "conf" | "qr" | "amnezia") => {
    const response = await fetch(`/api/portal/devices/${encodeURIComponent(name)}/export?format=${format}`, { credentials: "include" });
    if (!response.ok) {
      const body = await response.json().catch(() => undefined) as PortalErrorBody | undefined;
      const code = body?.error?.code ?? body?.code ?? `http.${response.status}`;
      throw new PortalApiError(response.status, code, response.status === 501 ? "Эта функция появится позже." : body?.error?.message ?? body?.message ?? "Не удалось экспортировать конфигурацию");
    }
    return response.blob();
  },
};
