import { TextField } from "@mui/material";

/** Flat text field: label floats, error/hint shown inline, no outlined box. */
export function Field({
  label,
  value,
  onChange,
  valid = true,
  hint,
  placeholder,
  multiline = false,
  type = "text",
  disabled = false,
  maxLength,
  ariaLabel,
  fullWidth = true,
}: {
  label?: string;
  value: string | number;
  onChange: (v: string) => void;
  valid?: boolean;
  hint?: string;
  placeholder?: string;
  multiline?: boolean;
  type?: string;
  disabled?: boolean;
  maxLength?: number;
  /** Accessible name when the field has no visible label (e.g. a table cell). */
  ariaLabel?: string;
  fullWidth?: boolean;
}) {
  return (
    <TextField
      size="small"
      fullWidth={fullWidth}
      label={label}
      value={value}
      type={type}
      placeholder={placeholder}
      multiline={multiline}
      disabled={disabled}
      minRows={multiline ? 2 : undefined}
      // A label with a placeholder and an empty value does not float and would
      // overlap the placeholder — float it whenever both are present.
      slotProps={{
        htmlInput: {
          ...(maxLength ? { maxLength } : {}),
          ...(ariaLabel ? { "aria-label": ariaLabel } : {}),
        },
        ...(label && placeholder ? { inputLabel: { shrink: true } } : {}),
      }}
      error={!valid}
      helperText={!valid ? (hint ?? "Некорректное значение") : (hint ?? " ")}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}