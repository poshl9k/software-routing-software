import { Box, Typography } from "@mui/material";
import { tokens } from "../theme";

export interface WizardProgressProps {
  steps: readonly string[];
  /** Zero-based current step. */
  current: number;
}

/**
 * Step indicator for a wizard.
 *
 * The list is a real `<ol>` of `<li>` (the steps are announced as a list),
 * but the native decimal marker is replaced by a CSS counter: a marker of the
 * next step is painted outside its own item box, so it lands in the gap of the
 * previous one and the row reads as «Кому2. Что». The counter keeps the
 * number visible without putting it into the item's own text.
 */
export function WizardProgress({ steps, current }: WizardProgressProps) {
  const index = Math.max(0, Math.min(current, steps.length - 1));
  return (
    <Box component="nav" aria-label="Этапы настройки" sx={{ mb: 3 }}>
      <Typography variant="body2">Сейчас: {steps[index] ?? "Шаг не выбран"}</Typography>
      {steps[index + 1] && <Typography variant="caption" color="text.secondary">Далее: {steps[index + 1]}</Typography>}
      <Box
        component="ol"
        sx={{
          display: "flex",
          flexWrap: "wrap",
          alignItems: "baseline",
          gap: 2.5,
          pl: 0,
          mt: 1.5,
          mb: 0,
          listStyle: "none",
          counterReset: "wizard-step",
        }}
      >
        {steps.map((step, i) => (
          <Typography
            component="li"
            key={`${i}-${step}`}
            variant="body2"
            aria-current={i === index ? "step" : undefined}
            sx={{
              color: i === index ? tokens.text : tokens.textTertiary,
              fontWeight: i === index ? 600 : 400,
              counterIncrement: "wizard-step",
              "&::before": {
                content: 'counter(wizard-step) ". "',
                color: tokens.textTertiary,
                marginRight: 0.5,
              },
            }}
          >
            {step}{i < index ? " — завершено" : ""}
          </Typography>
        ))}
      </Box>
    </Box>
  );
}
