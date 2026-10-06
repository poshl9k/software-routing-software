import { useEffect, useState } from "react";
import { api } from "../api";
import { observation, useRouterState } from "../state";

/**
 * The single read of the host-owned apply marker, shared by the topbar button
 * and the Apply screen.
 *
 * Deliberately imperative, not a TanStack Query: the status RPC checks the
 * confirmation deadline and may perform an already-due rollback, so caching,
 * deduping or background refetching it would change its side effects.
 *
 * `enabled=false` parks the reader (the Apply screen owns the read while it is
 * open); `refreshToken` forces a re-read for the screen's «Обновить состояние».
 */
export function useApplyStatus({
  enabled = true,
  refreshToken = 0,
  clearErrorOnRefresh = false,
}: {
  enabled?: boolean;
  refreshToken?: number;
  clearErrorOnRefresh?: boolean;
} = {}): { loading: boolean } {
  const { user, busy, setApplyState, setApplyError, setUncertain } =
    useRouterState();
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    if (!enabled) {
      setLoading(true);
      return;
    }
    if (user?.role !== "admin" || busy) return;
    const controller = new AbortController();
    setLoading(true);
    api
      .applyStatus(controller.signal)
      .then((marker) => {
        if (controller.signal.aborted) return;
        setApplyState((previous) =>
          marker
            ? observation(marker)
            : previous &&
                ["confirmed", "rolled_back", "failed"].includes(
                  previous.result.status,
                )
              ? previous
              : null,
        );
        setUncertain(false);
        if (clearErrorOnRefresh && refreshToken > 0) setApplyError(null);
        setLoading(false);
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        setApplyError(error);
        setUncertain(true);
        setLoading(false);
      });
    return () => controller.abort();
  }, [
    enabled,
    refreshToken,
    clearErrorOnRefresh,
    user?.role,
    busy,
    setApplyState,
    setApplyError,
    setUncertain,
  ]);
  return { loading };
}