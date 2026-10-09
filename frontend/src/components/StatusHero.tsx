import { Box, Paper, Typography } from "@mui/material";
import type { ReactNode } from "react";
import { tokens } from "../theme";
import { InlineStatus, type StatusTone } from "./InlineStatus";

export interface StatusHeroProps {
  title: string;
  tone: StatusTone;
  primary: string | number | null | undefined;
  facts?: readonly { label: string; value: string | number }[];
  action?: ReactNode;
  asOf?: string;
}

export function StatusHero({ title, tone, primary, facts, action, asOf }: StatusHeroProps) {
  return (
    <Paper component="section" elevation={0} aria-label={title} sx={{ p: 3, mb: 2, bgcolor: tokens.surface, border: `1px solid ${tokens.border}`, borderRadius: 2 }}>
      <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", flexWrap: "wrap", gap: 2 }}>
        <Box>
          <Typography component="h2" variant="h2" sx={{ mb: 1 }}>{title}</Typography>
          <InlineStatus tone={primary == null ? "unknown" : tone} text={primary == null ? "Нет данных" : String(primary)} asOf={asOf} />
        </Box>
        {action}
      </Box>
      {facts && facts.length > 0 && (
        <Box component="dl" sx={{ display: "flex", flexWrap: "wrap", gap: 3, mt: 2, mb: 0 }}>
          {facts.map(({ label, value }) => (
            <Box key={label}>
              <Typography component="dt" variant="caption" color="text.secondary">{label}</Typography>
              <Typography component="dd" variant="body2" sx={{ m: 0 }}>{value}</Typography>
            </Box>
          ))}
        </Box>
      )}
    </Paper>
  );
}
