import { Paper, Typography } from "@mui/material";
import { tokens } from "../theme";
import { statusColours, type StatusTone } from "./InlineStatus";

export interface StatTileProps {
  label: string;
  value: string | number | null | undefined;
  hint?: string;
  tone?: StatusTone;
  asOf?: string;
}

export function StatTile({ label, value, hint, tone = "neutral", asOf }: StatTileProps) {
  const unknown = value === null || value === undefined;
  return (
    <Paper elevation={0} sx={{ p: 2, border: `1px solid ${tokens.border}`, borderRadius: 2, bgcolor: unknown ? tokens.statusUnknownSoft : tokens.surface, minWidth: 0 }}>
      <Typography variant="body2" color="text.secondary">{label}</Typography>
      <Typography component="p" sx={{ my: 0.5, fontSize: 24, fontWeight: 600, color: unknown ? tokens.statusUnknown : statusColours[tone], overflowWrap: "anywhere" }}>
        {unknown ? "Нет данных" : value}
      </Typography>
      {hint && <Typography variant="caption" color="text.secondary" display="block">{hint}</Typography>}
      {asOf && <Typography variant="caption" color="text.secondary">Данные на <time dateTime={asOf}>{asOf}</time></Typography>}
    </Paper>
  );
}
