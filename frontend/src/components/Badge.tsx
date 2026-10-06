import { Chip } from "@mui/material";
import type { ReactNode } from "react";
import { tokens } from "../theme";

export type Tone = "blue" | "green" | "amber" | "red" | "purple";

const tones: Record<Tone, { fg: string; bg: string }> = {
  blue: { fg: "#9b9bff", bg: "rgba(113,112,255,0.14)" },
  green: { fg: "#4ade80", bg: tokens.successSoft },
  amber: { fg: tokens.warning, bg: tokens.warningSoft },
  red: { fg: "#f87171", bg: tokens.errorSoft },
  purple: { fg: tokens.purple, bg: tokens.purpleSoft },
};

/** Small status chip. One implementation for every colour-coded state. */
export function Badge({
  children,
  tone = "blue",
}: {
  children: ReactNode;
  tone?: Tone;
}) {
  const { fg, bg } = tones[tone];
  return (
    <Chip
      size="small"
      label={children}
      sx={{
        height: 22,
        fontSize: 11.5,
        fontWeight: 600,
        color: fg,
        backgroundColor: bg,
        border: "none",
        borderRadius: 1,
        "& .MuiChip-label": { px: 1 },
      }}
    />
  );
}