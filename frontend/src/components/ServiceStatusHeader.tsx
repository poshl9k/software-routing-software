import { Box, Link as MuiLink, Typography } from "@mui/material";
import { tokens } from "../theme";
import { InlineStatus, type StatusTone } from "./InlineStatus";

export type ServiceState = "running" | "stopped" | "unknown" | "error";
export interface ServiceStatusHeaderProps {
  name: string;
  state: ServiceState;
  asOf?: string;
  metrics?: readonly { label: string; value: string | number }[];
  lastErrorLink?: { href: string; label?: string };
}

const stateView: Record<ServiceState, { tone: StatusTone; text: string }> = {
  running: { tone: "green", text: "Работает" },
  stopped: { tone: "amber", text: "Остановлена" },
  unknown: { tone: "unknown", text: "Состояние неизвестно" },
  error: { tone: "red", text: "Ошибка службы" },
};

export function ServiceStatusHeader({ name, state, asOf, metrics, lastErrorLink }: ServiceStatusHeaderProps) {
  const view = stateView[state];
  return (
    <Box component="section" aria-label={`Служба ${name}`} sx={{ borderBottom: `1px solid ${tokens.border}`, py: 1.5, mb: 2, display: "flex", flexWrap: "wrap", alignItems: "center", gap: 2 }}>
      <Typography component="h2" variant="h2">{name}</Typography>
      <InlineStatus tone={view.tone} text={view.text} asOf={asOf} />
      {metrics?.slice(0, 2).map(({ label, value }) => <Typography key={label} variant="body2">{label}: {value}</Typography>)}
      {lastErrorLink && <MuiLink href={lastErrorLink.href} sx={{ ml: "auto" }}>{lastErrorLink.label ?? "Последняя ошибка"}</MuiLink>}
    </Box>
  );
}
