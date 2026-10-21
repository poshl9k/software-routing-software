import { Box } from "@mui/material";
import type { ReactNode } from "react";
import { tokens } from "../theme";

/** Scope routing layout without changing shared cards or wizard progress. */
export function RoutingSurface({ children }: { children: ReactNode }) {
  return <Box className="routing-surface" sx={{
    "& .card": { bgcolor: tokens.surface },
    "& nav ol": { bgcolor: tokens.panel, border: `1px solid ${tokens.border}`, borderRadius: 1.5 },
    "& nav li[aria-current=step]": { bgcolor: "var(--vs-accent-soft)", boxShadow: `inset 0 -2px ${tokens.accent}` },
  }}>{children}</Box>;
}

/** Quiet inset surface for static summaries, not a second card hierarchy. */
export function SummaryPanel({ children }: { children: ReactNode }) {
  return <Box className="routing-summary" sx={{ bgcolor: tokens.panel, border: `1px solid ${tokens.border}`, borderRadius: 1.25 }}>{children}</Box>;
}
