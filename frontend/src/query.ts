import { QueryClient } from "@tanstack/react-query";

/**
 * Server-state client. Created per provider tree (not a module singleton) so a
 * fresh render — each app mount and each test — starts with an empty cache.
 */
export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: 1,
        // A control panel should not silently refetch on tab focus.
        refetchOnWindowFocus: false,
        staleTime: 30_000,
      },
    },
  });
}

/** Central query-key factory; keeps keys collision-free as reads migrate. */
export const queryKeys = {
  dhcpLeases: (term: string) => ["dhcp", "leases", term] as const,
  rulesCounters: () => ["diag", "rules-counters"] as const,
  diff: (before: number | null, after: number | null) =>
    ["diff", before, after] as const,
  hostInterfaces: () => ["host", "interfaces"] as const,
  hostManagement: () => ["host", "management"] as const,
  hostProfile: () => ["host", "profile"] as const,
  hostAddresses: () => ["host", "addresses"] as const,
  serviceStatus: () => ["status", "services"] as const,
  tunnelActivity: () => ["tunnels", "activity"] as const,
  tunnelAvailability: () => ["tunnels", "availability"] as const,
  compositeRuntime: () => ["routing", "composite-runtime"] as const,
  tproxyPreview: (versionId: number | null) =>
    ["tproxy", "preview", versionId] as const,
  presetCatalog: () => ["presets", "catalog"] as const,
  rulesets: () => ["rulesets"] as const,
  portalTariffs: () => ["portal", "tariffs"] as const,
  portalSubscription: (name: string) => ["portal", "subscription", name] as const,
  portalSettings: () => ["portal", "settings"] as const,
};