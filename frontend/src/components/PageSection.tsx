import { Box, Typography } from "@mui/material";
import type { ReactNode } from "react";

export interface PageSectionProps {
  title: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
}

/** A section within a page; PageHeader alone owns the h1. */
export function PageSection({ title, subtitle, action, children }: PageSectionProps) {
  return (
    <Box component="section" sx={{ mb: 3 }}>
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 2, flexWrap: "wrap", mb: 2 }}>
        <Box>
          <Typography component="h2" variant="h2">{title}</Typography>
          {subtitle && <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>{subtitle}</Typography>}
        </Box>
        {action}
      </Box>
      {children}
    </Box>
  );
}
