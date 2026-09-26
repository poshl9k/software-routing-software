import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { api } from "./api";
import type {
  ApplyMarker,
  ApplyRequest,
  ApplyResult,
  ConfigurationVersion,
} from "./types";
import { demoConfiguration } from "./fixtures";
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
  setApplyState: (value: ApplyObservation | null) => void;
  uncertain: boolean;
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
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const controller = useRef<AbortController | null>(null);
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
        setError(err);
        setVersions([]);
      }
    } finally {
      if (!current.signal.aborted) setLoading(false);
    }
  }, []);
  useEffect(() => {
    void refresh();
    return () => controller.current?.abort();
  }, [refresh]);
  return (
    <Context.Provider
      value={{
        versions,
        loading,
        error,
        refresh,
        applyState,
        setApplyState,
        uncertain,
        setUncertain,
        busy,
        setBusy,
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
    configuration: version?.configuration ?? demoConfiguration,
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
