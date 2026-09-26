import type {
  ApplyRequest,
  ApplyResult,
  Configuration,
  ConfigurationVersion,
  Credentials,
  ErrorBody,
  User,
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
  versions: (signal?: AbortSignal) =>
    request<ConfigurationVersion[]>("/api/versions", { signal }),
  setup: (body: Credentials) => post<User>("/api/setup", body),
  login: (body: Credentials) => post<User>("/api/auth/login", body),
  me: () => request<User>("/api/auth/me"),
  logout: () => post<void>("/api/auth/logout", {}),
  createDraft: (body: Configuration) =>
    post<ConfigurationVersion>("/api/draft", body),
  apply: (body: ApplyRequest) => post<ApplyResult>("/api/apply", body),
  confirm: (version_id: number) =>
    post<ApplyResult>("/api/confirm", { version_id }),
  rollback: () => post<ApplyResult>("/api/rollback", {}),
  diff: (before: number, after: number) =>
    request<unknown[]>(`/api/diff/${before}/${after}`),
};
