import { Alert } from "@mui/material";
import type { ReactNode } from "react";

/**
 * Informational note. Replaces the old `Todo` banner: the same honest
 * "not wired yet" signal is kept, but in product language rather than an
 * internal `TODO-API ·` prefix.
 */
export function InfoNote({
  children,
  severity = "info",
}: {
  children: ReactNode;
  severity?: "info" | "warning";
}) {
  return <Alert severity={severity}>{children}</Alert>;
}