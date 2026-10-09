import { Box, Button, Paper, Typography } from "@mui/material";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { tokens } from "../theme";
import { InlineStatus, type StatusTone } from "./InlineStatus";

export type ApplyStatusRailProps = (
  | { state: "draft"; draftVersion: string | number; stableVersion?: string | number }
  | { state: "pending"; seconds: number | null }
  | { state: "running" | "uncertain" }
  | { state: "applied"; confirmedVersion: string | number; confirmedAt?: string }
  | { state: "error"; message?: string }
) & { action?: ReactNode };

function phase(props: ApplyStatusRailProps): { tone: StatusTone; text: string; detail?: string } {
  switch (props.state) {
    case "draft": return { tone: "amber", text: `Черновик v${props.draftVersion} не применён`, detail: props.stableVersion == null ? "Стабильная версия неизвестна" : `Стабильная v${props.stableVersion}` };
    case "pending": return { tone: "amber", text: "Ожидается подтверждение", detail: props.seconds == null ? "Время до подтверждения недоступно" : `Осталось ${Math.floor(Math.max(0, props.seconds) / 60).toString().padStart(2, "0")}:${Math.floor(Math.max(0, props.seconds) % 60).toString().padStart(2, "0")}` };
    case "running": return { tone: "blue", text: "Применение выполняется" };
    case "uncertain": return { tone: "unknown", text: "Состояние агента неизвестно" };
    case "applied": return { tone: "green", text: `Подтверждена v${props.confirmedVersion}`, detail: props.confirmedAt ? `Подтверждена: ${props.confirmedAt}` : "Время подтверждения недоступно" };
    case "error": return { tone: "red", text: "Ошибка применения", detail: props.message };
  }
}

/** Pure presentation: caller owns status reads and countdown. */
export function ApplyStatusRail(props: ApplyStatusRailProps) {
  const { tone, text, detail } = phase(props);
  return (
    <Paper component="aside" elevation={0} aria-label="Состояние конфигурации" sx={{ p: 2, bgcolor: tokens.surface, border: `1px solid ${tokens.border}`, borderRadius: 2, display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
      <Box sx={{ flex: 1, minWidth: 180 }}>
        {/* Stable across countdown ticks: only the phase text is in the live region. */}
        <Box aria-live="polite" aria-atomic="true"><InlineStatus tone={tone} text={text} /></Box>
        {detail && <Typography variant="caption" display="block" sx={{ color: tokens.textTertiary, mt: 0.5 }}>{detail}</Typography>}
      </Box>
      {props.action ?? <Button component={Link} to="/apply" variant="outlined">Проверить изменения</Button>}
    </Paper>
  );
}
