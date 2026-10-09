import { Box, Typography } from "@mui/material";
import { tokens } from "../theme";

export type StatusTone = "green" | "amber" | "red" | "blue" | "neutral" | "unknown";
export interface InlineStatusProps {
  tone: StatusTone;
  text: string;
  asOf?: string;
}

export const statusColours: Record<StatusTone, string> = {
  green: tokens.success,
  amber: tokens.warning,
  red: tokens.error,
  blue: tokens.badgeBlue,
  neutral: tokens.textTertiary,
  unknown: tokens.statusUnknown,
};

/** The dot is decorative; text always names the state. */
export function InlineStatus({ tone, text, asOf }: InlineStatusProps) {
  return (
    <Box sx={{ display: "inline-flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
      <Box aria-hidden="true" sx={{ width: 8, height: 8, borderRadius: "50%", flexShrink: 0, bgcolor: statusColours[tone] }} />
      <Typography component="span" variant="body2">{text}</Typography>
      {asOf && <Typography component="span" variant="caption" sx={{ color: tokens.textTertiary }}>Данные на <time dateTime={asOf}>{asOf}</time></Typography>}
    </Box>
  );
}
