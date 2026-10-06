import { TextField, type SxProps, type Theme } from "@mui/material";
import type { Interface } from "../types";

/** Option text: name, plus the operator description when set. */
export function interfaceLabel(
  name: string,
  interfaces: readonly Pick<Interface, "name" | "description">[],
): string {
  const description = interfaces
    .find((i) => i.name === name)
    ?.description?.trim();
  return description ? `${name} — ${description}` : name;
}

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

/**
 * The ONE native select. Every dropdown in the panel goes through this so the
 * label is always shrunk (an empty value does not float it and would overlap
 * the placeholder option) and the option markup stays consistent.
 */
export function Select({
  label,
  value,
  options,
  onChange,
  disabled = false,
  error,
  helperText,
  placeholder,
  ariaLabel,
  fullWidth = true,
  sx,
}: {
  label?: string;
  value: string;
  options: readonly SelectOption[];
  onChange: (v: string) => void;
  disabled?: boolean;
  error?: boolean;
  helperText?: string;
  placeholder?: { label: string; disabled?: boolean };
  /** Distinct accessible name when several selects share a visible label. */
  ariaLabel?: string;
  fullWidth?: boolean;
  sx?: SxProps<Theme>;
}) {
  return (
    <TextField
      select
      size="small"
      fullWidth={fullWidth}
      label={label}
      value={value}
      disabled={disabled}
      error={error}
      helperText={helperText ?? " "}
      SelectProps={{ native: true }}
      slotProps={{
        inputLabel: { shrink: true },
        ...(ariaLabel ? { htmlInput: { "aria-label": ariaLabel } } : {}),
      }}
      sx={sx}
      onChange={(e) => onChange(e.target.value)}
    >
      {placeholder && (
        <option value="" disabled={placeholder.disabled}>
          {placeholder.label}
        </option>
      )}
      {options.map((o) => (
        <option key={o.value} value={o.value} disabled={o.disabled}>
          {o.label}
        </option>
      ))}
    </TextField>
  );
}

/** Enum select built on top of `Select` (value === label). */
export function SelectField<T extends string>({
  label,
  value,
  options,
  onChange,
  disabled,
  required = false,
  ariaLabel,
}: {
  label?: string;
  value: T;
  options: readonly T[];
  onChange: (v: T) => void;
  disabled?: boolean;
  /** Opt-in: only mark an empty value as an error when the field is required. */
  required?: boolean;
  ariaLabel?: string;
}) {
  return (
    <Select
      label={label}
      ariaLabel={ariaLabel}
      value={value}
      disabled={disabled}
      error={required && !value}
      helperText={required && !value ? "Выберите значение" : undefined}
      placeholder={{ label: "Выберите", disabled: true }}
      options={options.map((o) => ({ value: o, label: o }))}
      onChange={(v) => onChange(v as T)}
    />
  );
}

/** Single interface picker used everywhere a network interface is chosen. */
export function InterfaceSelect({
  label,
  value,
  interfaces,
  onChange,
  emptyLabel,
  disabled = false,
  error,
  helperText,
  sx,
}: {
  label: string;
  value: string;
  interfaces: readonly Interface[];
  onChange: (v: string) => void;
  emptyLabel?: string;
  disabled?: boolean;
  error?: boolean;
  helperText?: string;
  sx?: SxProps<Theme>;
}) {
  const names = interfaces.map((i) => i.name);
  const options = value && !names.includes(value) ? [value, ...names] : names;
  return (
    <Select
      label={label}
      value={value}
      disabled={disabled}
      error={error}
      helperText={helperText}
      sx={sx}
      placeholder={
        emptyLabel !== undefined ? { label: emptyLabel, disabled: false } : undefined
      }
      options={options.map((name) => ({
        value: name,
        label: interfaceLabel(name, interfaces),
      }))}
      onChange={onChange}
    />
  );
}