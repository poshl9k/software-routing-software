import { FormControlLabel, Switch } from "@mui/material";

/** Labelled switch, one implementation for every boolean field. */
export function Toggle({
  label,
  value,
  onChange,
  disabled = false,
}: {
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <FormControlLabel
      label={label}
      disabled={disabled}
      control={
        <Switch
          checked={value}
          disabled={disabled}
          onChange={(_, v) => onChange(v)}
        />
      }
    />
  );
}