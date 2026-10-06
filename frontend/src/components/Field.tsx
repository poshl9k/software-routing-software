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
}) {
  return (
    <TextField
      size="small"
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
        ...(maxLength ? { htmlInput: { maxLength } } : {}),
        ...(label && placeholder ? { inputLabel: { shrink: true } } : {}),
      }}
      error={!valid}
      helperText={!valid ? (hint ?? "Некорректное значение") : hint}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}