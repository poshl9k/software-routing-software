import { matchRoutes } from "react-router-dom";
import type { HostProfile } from "./types";

/** Host facts gate screens, not product names: legacy hosts still use capabilities. */
export const hostScreenGates = [
  { fact: "dhcp", unavailable: false, screens: ["/dhcp"] },
  { fact: "profile", unavailable: "router", screens: ["/subscribers"] },
] as const satisfies readonly {
  fact: keyof HostProfile;
  unavailable: HostProfile[keyof HostProfile];
  screens: readonly string[];
}[];

/** Missing or unread facts keep screens reachable for older hosts. */
export function isHostScreenAvailable(path: string, host: HostProfile | undefined): boolean {
  // Use the router's own matching, including encoded paths, case and trailing slashes.
  return !hostScreenGates.some((gate) =>
    host?.[gate.fact] === gate.unavailable &&
    matchRoutes(gate.screens.map((path) => ({ path })), path) !== null);
}
