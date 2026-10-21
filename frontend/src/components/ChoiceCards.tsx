import { useId } from "react";
import { Box, ButtonBase, Typography } from "@mui/material";
import { tokens } from "../theme";
import { Badge } from "./Badge";
import { Icon, type IconName } from "./Icon";

export interface CardChoice {
  value: string;
  label: string;
  description: string;
  icon?: IconName;
  disabled?: boolean;
}

/** One keyboard-accessible choice surface, with cards, rows and preset tiles.
 *
 * `value` is the current selection. With `multiple` the caller receives the
 * whole new selection, so one primitive serves both one-of-N and any-of-N
 * instead of two components doing the same job.
 */
export function ChoiceCards({ label, options, value, onChange, layout = "cards", disabled = false, multiple = false }: {
  label: string;
  options: readonly CardChoice[];
  value: readonly string[];
  onChange: (value: string, selected: string[]) => void;
  layout?: "cards" | "rows" | "presets";
  disabled?: boolean;
  multiple?: boolean;
}) {
  const id = useId();
  return <div role="group" aria-label={label} className={`choice-grid choice-grid--${layout}`}>
    {options.map((option, index) => {
      const selected = value.includes(option.value);
      const unavailable = disabled || option.disabled;
      return <ButtonBase key={option.value} component="button" type="button"
        disabled={unavailable} aria-pressed={selected}
        aria-labelledby={`${id}-${index}-label`} aria-describedby={`${id}-${index}-hint`}
        className={`choice-card choice-card--${layout}`}
        onClick={() => onChange(option.value, multiple
          ? (selected ? value.filter((item) => item !== option.value) : [...value, option.value])
          : [option.value])}
        sx={{ border: `1px solid ${selected ? tokens.accent : tokens.border}`,
          bgcolor: selected ? "var(--vs-accent-soft)" : tokens.panel,
          color: tokens.text, borderRadius: 1.25,
          "&:hover": { borderColor: tokens.accent },
          "&.Mui-focusVisible": { outline: `2px solid ${tokens.accent}`, outlineOffset: 3 },
          "&.Mui-disabled": { opacity: 0.55, color: tokens.textSecondary } }}>
        {option.icon && <Icon name={option.icon} />}
        <Box className="choice-copy">
          <Typography component="span" id={`${id}-${index}-label`} className="choice-title">{option.label}</Typography>
          <Typography component="span" id={`${id}-${index}-hint`} variant="caption" color="text.secondary">{option.description}</Typography>
        </Box>
        {layout === "rows" && <Badge tone={selected ? "blue" : "purple"}>{selected ? "выбрано" : "выбрать"}</Badge>}
      </ButtonBase>;
    })}
  </div>;
}
