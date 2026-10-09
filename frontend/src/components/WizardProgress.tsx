import { Box, Typography } from "@mui/material";
import { tokens } from "../theme";

export interface WizardProgressProps {
  steps: readonly string[];
  /** Zero-based current step. */
  current: number;
}

export function WizardProgress({ steps, current }: WizardProgressProps) {
  const index = Math.max(0, Math.min(current, steps.length - 1));
  return (
    <Box component="nav" aria-label="Этапы настройки" sx={{ mb: 3 }}>
      <Typography variant="body2">Сейчас: {steps[index] ?? "Шаг не выбран"}</Typography>
      {steps[index + 1] && <Typography variant="caption" color="text.secondary">Далее: {steps[index + 1]}</Typography>}
      <Box component="ol" sx={{ display: "flex", flexWrap: "wrap", gap: 2, pl: 2.5, mt: 1.5, mb: 0 }}>
        {steps.map((step, i) => (
          <Typography component="li" key={`${i}-${step}`} variant="body2" aria-current={i === index ? "step" : undefined} sx={{ color: i === index ? tokens.text : tokens.textTertiary, fontWeight: i === index ? 600 : 400 }}>
            {step}{i < index ? " — завершено" : ""}
          </Typography>
        ))}
      </Box>
    </Box>
  );
}
