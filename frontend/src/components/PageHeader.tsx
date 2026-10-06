import { Typography } from "@mui/material";
import type { ReactNode } from "react";

/** The single `h1` page-title contract every route renders exactly once. */
export function PageHeader({ children }: { children: ReactNode }) {
  return (
    <Typography component="h1" variant="h1" className="page-title">
      {children}
    </Typography>
  );
}