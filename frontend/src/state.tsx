import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
  type Dispatch,
  type SetStateAction,
} from "react";
import { api, ApiError } from "./api";
import type {
  ApplyMarker,
  ApplyRequest,
  ApplyResult,
  Configuration,
  ConfigurationVersion,
} from "./types";
import { emptyConfiguration } from "./fixtures";
import { readPreferences, savePreferences, type Preferences } from "./preferences";
import type { User } from "./types";

export function fmtUser(value: unknown): User | null {
  return value && typeof (value as User).username === "string"
    ? (value as User)
    : null;
}
export interface ApplyObservation {
  result: ApplyResult;
  deadline: number | null;
  approximate: boolean;
}
export function observation(
  result: ApplyResult,
  params?: ApplyRequest,
  startedAt = Date.now(),
): ApplyObservation {
  const marker = result as Partial<ApplyMarker>;
  const authoritative = typeof marker.deadline === "number";
  return {
    result,
    deadline: authoritative
      ? marker.deadline! * 1000
      : result.status === "pending" && params
        ? startedAt + params.confirmation_timeout * 1000
        : null,
    approximate: !authoritative,
  };
}
interface RouterState {
  versions: ConfigurationVersion[];
  loading: boolean;
  error: unknown;
  refresh: () => Promise<void>;
  applyState: ApplyObservation | null;
  setApplyState: Dispatch<SetStateAction<ApplyObservation | null>>;
  applyError: unknown;
  setApplyError: (value: unknown) => void;
  notice: string | null;
  setNotice: (value: string | null) => void;
  user: User | null;
  loadUser: () => Promise<void>;
  signOut: () => Promise<void>;
  uncertain: boolean;
  draftDirty: boolean;
  saveDraft: (configuration: Configuration) => Promise<ConfigurationVersion>;
  discardDraft: () => Promise<void>;
  saveConfirmed: () => void;
  setUncertain: (value: boolean) => void;
  busy: boolean;
  setBusy: (value: boolean) => void;
}
const Context = createContext<RouterState | null>(null);
export function RouterProvider({ children }: { children: ReactNode }) {
  const [versions, setVersions] = useState<ConfigurationVersion[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [applyState, setApplyState] = useState<ApplyObservation | null>(null);
  const [applyError, setApplyError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const [draftDirty, setDraftDirty] = useState(false);
  const saveDraft = useCallback(async (configuration: Configuration) => {
    const existing = versions.find((v) => v.status === "draft");
    const saved = existing
      ? await api.updateDraft(configuration)
      : await api.createDraft(configuration);
    setVersions((old) => [...old.filter((v) => v.id !== saved.id), saved]);
    setDraftDirty(true);
    return saved;
  }, [versions]);
  const discardDraft = useCallback(async () => {
    await api.deleteDraft();
    setVersions((old) => old.filter((v) => v.status !== "draft"));
    setDraftDirty(false);
  }, []);
  const saveConfirmed = useCallback(() => {
    setVersions((old) =>
      old.map((v) => (v.status === "draft" ? { ...v, status: "confirmed" } : v)),
    );
    setDraftDirty(false);
  }, []);
  const controller = useRef<AbortController | null>(null);
  const clearSession = useCallback(() => {
    controller.current?.abort();
    setUser(null);
    setVersions([]);
    setLoading(false);
    setError(null);
    setApplyState(null);
    setApplyError(null);
    setUncertain(false);
    setDraftDirty(false);
    setNotice(null);
  }, []);
  const refresh = useCallback(async () => {
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    try {
      const data = await api.versions(current.signal);
      if (!current.signal.aborted) {
        setVersions(data);
        setError(null);
      }
    } catch (err) {
      if (!current.signal.aborted) {
        if (err instanceof ApiError && err.status === 401) clearSession();
        else {
          setError(err);
          setVersions([]);
        }
      }
    } finally {
      if (!current.signal.aborted) setLoading(false);
    }
  }, [clearSession]);
  useEffect(() => {
    void refresh();
    return () => controller.current?.abort();
  }, [refresh]);
  const loadUser = useCallback(async () => {
    try {
      setUser(fmtUser(await api.me()));
    } catch {
      clearSession();
    }
  }, [clearSession]);
  const signOut = useCallback(async () => {
    await api.logout();
    clearSession();
  }, [clearSession]);
  return (
    <Context.Provider
      value={{
        versions,
        loading,
        error,
        refresh,
        applyState,
        setApplyState,
        applyError,
        setApplyError,
        notice,
        setNotice,
        user,
        loadUser,
        signOut,
        uncertain,
        setUncertain,
        busy,
        setBusy,
        draftDirty,
        saveDraft,
        discardDraft,
        saveConfirmed,
      }}
    >
      {children}
    </Context.Provider>
  );
}
export function useRouterState() {
  const state = useContext(Context);
  if (!state) throw new Error("RouterProvider required");
  return state;
}
export function useConfiguration() {
  const state = useRouterState();
  const version = [...state.versions].sort((a, b) => b.id - a.id)[0];
  return {
    ...state,
    configuration: version?.configuration ?? emptyConfiguration,
    demo: !version,
    version,
  };
}
export function useCountdown(deadline: number | null) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    setNow(Date.now());
    const timer = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(timer);
  }, [deadline]);
  return deadline === null
    ? null
    : Math.max(0, Math.ceil((deadline - now) / 1000));
}
export const statusLabels: Record<ApplyResult["status"], string> = {
  applying: "Применяется",
  pending: "Неподтверждённые изменения",
  confirmed: "Подтверждено",
  rolling_back: "Откат выполняется",
  rolled_back: "Откачено",
  failed: "Ошибка применения",
  rollback_failed: "Ошибка отката",
};

export interface ApplyCommands {
  drafts: ConfigurationVersion[];
  draft: ConfigurationVersion | undefined;
  confirmed: ConfigurationVersion | undefined;
  preferences: Preferences;
  setPreferences: (update: (old: Preferences) => Preferences) => void;
  seconds: number | null;
  state: ApplyResult | undefined;
  pending: boolean;
  active: boolean;
  timeoutValid: boolean;
  error: unknown;
  command: (kind: "apply" | "confirm" | "rollback", draftId?: number | "") => Promise<void>;
}

/**
 * Apply/confirm/rollback commands shared by the Apply screen and the topbar
 * button. The state is per-instance, except busy/uncertain/applyState which
 * live in the router context: two instances cannot double-fire (busy gates),
 * and the pending observation is visible from both.
 */
export function useApplyCommands(
  draftIdOverride?: number | "",
): ApplyCommands {
  const {
    versions,
    refresh,
    applyState,
    setApplyState,
    applyError,
    setApplyError,
    uncertain,
    setUncertain,
    busy,
    setBusy,
  } = useRouterState();
  const [preferences, setPreferencesState] =
    useState<Preferences>(readPreferences);
  const requestLock = useRef(false);
  const drafts = versions.filter((v) => v.status === "draft");
  const draft =
    drafts.find((v) => v.id === draftIdOverride) ?? drafts[0];
  const confirmed = versions
    .filter((v) => v.status === "confirmed")
    .sort((a, b) => b.id - a.id)[0];
  const seconds = useCountdown(applyState?.deadline ?? null);
  const state = applyState?.result;
  const pending = state?.status === "pending";
  const active =
    !!state &&
    ["pending", "applying", "rolling_back", "rollback_failed"].includes(
      state.status,
    );
  const timeoutValid =
    Number.isInteger(preferences.timeout) &&
    preferences.timeout >= 60 &&
    preferences.timeout <= 600;
  function setPreferences(
    update: (old: Preferences) => Preferences,
  ) {
    setPreferencesState(update);
  }
  async function command(
    kind: "apply" | "confirm" | "rollback",
    draftId?: number | "",
  ) {
    if (requestLock.current || busy) return;
    requestLock.current = true;
    setBusy(true);
    setApplyError(null);
    const started = Date.now();
    const target =
      draftId === undefined || draftId === ""
        ? draft
        : drafts.find((v) => v.id === draftId) ?? draft;
    try {
      let result: ApplyResult;
      if (kind === "apply") {
        if (!target) return;
        const params = {
          version_id: target.id,
          safe_mode: confirmed ? preferences.safe : false,
          confirmation_timeout: preferences.timeout,
        };
        savePreferences(preferences);
        result = await api.apply(params);
        setApplyState(observation(result, params, started));
      } else {
        if (kind === "confirm" && !state) return;
        result =
          kind === "confirm"
            ? await api.confirm(state!.version_id)
            : await api.rollback();
        setApplyState(observation(result));
      }
      setUncertain(false);
      if (result.error)
        setApplyError(
          new Error(`${result.error.message} · ${result.error.code}`),
        );
      await refresh();
    } catch (err) {
      setApplyError(err);
      setUncertain(true);
    } finally {
      requestLock.current = false;
      setBusy(false);
    }
  }
  return {
    drafts,
    draft,
    confirmed,
    preferences,
    setPreferences,
    seconds,
    state,
    pending,
    active,
    timeoutValid,
    error: applyError,
    command,
  };
}
