import type { Secret } from "../types";

/**
 * One home for every field validator. Two name rules exist on purpose and are
 * NOT interchangeable:
 *  - `nameValid`       — rule / alias / site / tunnel names (no dots, up to 31).
 *  - `ifaceNameValid`  — network interface names (dots allowed, up to 15).
 */

export const nameValid = (v: string) => /^[a-zA-Z][a-zA-Z0-9_]{0,30}$/.test(v);

export const ifaceNameValid = (v: string) =>
  /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/.test(v);

export const domainValid = (v: string) => /^[a-zA-Z0-9_.-]+$/.test(v);

export const portValid = (v: number) =>
  Number.isInteger(v) && v >= 1 && v <= 65535;

export const macValid = (v: string) =>
  /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(v);

export const hostValid = (v: string, wildcard = false) =>
  (wildcard ? /^[a-zA-Z0-9*.-]+$/ : /^[a-zA-Z0-9.-]+$/).test(v);

export const secretValid = (v: Secret | null) =>
  !!v && (!("plaintext" in v) || !!v.plaintext.trim());

export const listValid = (v: string[], check: (s: string) => boolean) =>
  v.filter(Boolean).every(check);

export const lines = (v: string) =>
  v
    .split(/\n|,/)
    .map((s) => s.trim())
    .filter(Boolean);

export const split = (v: string) => v.split(",");

export const normalize = (v: string[]) => v.map((s) => s.trim()).filter(Boolean);

export function ipValid(value: string): boolean {
  if (value.includes(":")) {
    if (!/^[0-9a-fA-F:.]+$/.test(value)) return false;
    try {
      return new URL(`http://[${value}]/`).hostname.length > 0;
    } catch {
      return false;
    }
  }
  return (
    /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value) &&
    value.split(".").every((p) => Number(p) <= 255)
  );
}

export function addressValid(value: string): boolean {
  const parts = value.split("/");
  return (
    parts.length <= 2 &&
    ipValid(parts[0]) &&
    (parts.length === 1 ||
      (/^\d+$/.test(parts[1]) &&
        Number(parts[1]) <= (parts[0].includes(":") ? 128 : 32)))
  );
}

export const addressElementValid = (v: string) =>
  addressValid(v) || (v.split("-").length === 2 && v.split("-").every(ipValid));

export const portElementValid = (v: string) => {
  const match = /^(?:tcp|udp)\/(\d+)(?:-(\d+))?$/.exec(v);
  return (
    !!match &&
    portValid(Number(match[1])) &&
    (!match[2] ||
      (portValid(Number(match[2])) && Number(match[2]) >= Number(match[1])))
  );
};

export const endpointValid = (v: string) =>
  v === "any" ||
  (v.startsWith("@")
    ? nameValid(v.slice(1))
    : v.startsWith("zone:")
      ? nameValid(v.slice(5))
      : addressElementValid(v));