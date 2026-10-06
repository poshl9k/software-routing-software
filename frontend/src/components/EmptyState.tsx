import { Box, Typography } from "@mui/material";
import type { ReactNode } from "react";

/** Neutral placeholder for an empty list or a feature without data yet. */
export function EmptyState({
  title,
  children,
  action,
}: {
  title?: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <Box sx={{ py: 3, textAlign: "center", color: "text.secondary" }}>
      {title && (
        <Typography variant="body2" sx={{ fontWeight: 600, color: "text.primary" }}>
          {title}
        </Typography>
      )}
      {children && (
        <Typography variant="body2" sx={{ mt: title ? 0.5 : 0 }}>
          {children}
        </Typography>
      )}
      {action && <Box sx={{ mt: 1.5 }}>{action}</Box>}
    </Box>
  );
}