import { TextField, type SxProps, type Theme } from "@mui/material";

/** Everything a `Field` needs regardless of whether it is editable. */
type FieldCommon = {
  label?: string;
  value: string | number;
  valid?: boolean;
  hint?: string;
  placeholder?: string;
  multiline?: boolean;
  type?: string;
  disabled?: boolean;
  maxLength?: number;
  /** Accessible name when the field has no visible label (e.g. a table cell). */
  ariaLabel?: string;
  /** Browser autofill hint (login/secret fields). */
  autoComplete?: string;
  /** Marks the field as required (native `required` + the MUI asterisk). */
  required?: boolean;
  /** Extra attributes merged onto the native input (min/max/step/inputMode…). */
  inputProps?: Record<string, unknown>;
  className?: string;
  sx?: SxProps<Theme>;
  fullWidth?: boolean;
};

/**
 * A read-only field carries no `onChange`; every editable field must pass one,
 * so a controlled input that silently ignores typing cannot be created by
 * mistake.
 */
type FieldProps = FieldCommon &
  (
    | { readOnly: true; onChange?: (v: string) => void }
    | { readOnly?: false; onChange: (v: string) => void }
  );

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
  autoComplete,
  readOnly = false,
  required = false,
  inputProps,
  className,
  sx,
  fullWidth = true,
}: FieldProps) {
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
      required={required}
      className={className}
      sx={sx}
      minRows={multiline ? 2 : undefined}
      // A label with a placeholder and an empty value does not float and would
      // overlap the placeholder — float it whenever both are present.
      slotProps={{
        htmlInput: {
          ...(maxLength ? { maxLength } : {}),
          ...(ariaLabel ? { "aria-label": ariaLabel } : {}),
          ...(autoComplete ? { autoComplete } : {}),
          ...(readOnly ? { readOnly: true } : {}),
          ...inputProps,
        },
        ...(label && placeholder ? { inputLabel: { shrink: true } } : {}),
      }}
      error={!valid}
      helperText={!valid ? (hint ?? "Некорректное значение") : (hint ?? " ")}
      onChange={(e) => onChange?.(e.target.value)}
    />
  );
}
