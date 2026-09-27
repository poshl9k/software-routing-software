import { Button, FormControlLabel, Switch, TextField } from "@mui/material";

export const nameValid = (v: string) => /^[a-zA-Z][a-zA-Z0-9_]{0,30}$/.test(v);
export const domainValid = (v: string) => /^[a-zA-Z0-9_.-]+$/.test(v);
export const portValid = (v: number) =>
  Number.isInteger(v) && v >= 1 && v <= 65535;
export const lines = (v: string) =>
  v
    .split(/\n|,/)
    .map((s) => s.trim())
    .filter(Boolean);
export function ipValid(value: string): boolean {
  if (value.includes(":")) {
    if (!/^[0-9a-fA-F:.]+$/.test(value)) return false;
    try {
      return new URL(`http://[${value}]/`).hostname.length > 0;
    } catch {
      return false;
    }
  }
  return (
    /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value) &&
    value.split(".").every((p) => Number(p) <= 255)
  );
}
export function addressValid(value: string): boolean {
  const parts = value.split("/");
  return (
    parts.length <= 2 &&
    ipValid(parts[0]) &&
    (parts.length === 1 ||
      (/^\d+$/.test(parts[1]) &&
        Number(parts[1]) <= (parts[0].includes(":") ? 128 : 32)))
  );
}
export const endpointValid = (v: string) =>
  v === "any" ||
  (v.startsWith("@")
    ? nameValid(v.slice(1))
    : v.startsWith("zone:")
      ? nameValid(v.slice(5))
      : addressElementValid(v));
export const addressElementValid = (v: string) =>
  addressValid(v) || (v.split("-").length === 2 && v.split("-").every(ipValid));
export const portElementValid = (v: string) => {
  const match = /^(?:tcp|udp)\/(\d+)(?:-(\d+))?$/.exec(v);
  return (
    !!match &&
    portValid(Number(match[1])) &&
    (!match[2] ||
      (portValid(Number(match[2])) && Number(match[2]) >= Number(match[1])))
  );
};
export function Field({
  label,
  value,
  onChange,
  valid = true,
  hint,
  placeholder,
  multiline = false,
  type = "text",
}: {
  label: string;
  value: string | number;
  onChange: (v: string) => void;
  valid?: boolean;
  hint?: string;
  placeholder?: string;
  multiline?: boolean;
  type?: string;
}) {
  return (
    <TextField
      size="small"
      label={label}
      value={value}
      type={type}
      placeholder={placeholder}
      multiline={multiline}
      minRows={multiline ? 2 : undefined}
      error={!valid}
      helperText={!valid ? (hint ?? "Некорректное значение") : hint}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}
export function SelectField<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: readonly T[];
  onChange: (v: T) => void;
}) {
  return (
    <TextField
      select
      size="small"
      label={label}
      value={value}
      error={!value}
      helperText={!value ? "Выберите значение" : undefined}
      SelectProps={{ native: true }}
      onChange={(e) => onChange(e.target.value as T)}
    >
      <option value="" disabled>
        Выберите
      </option>
      {Array.from(new Set([...(value ? [value] : []), ...options])).map((v) => (
        <option key={v} value={v}>
          {v}
        </option>
      ))}
    </TextField>
  );
}
export function Toggle({
  label,
  value,
  onChange,
}: {
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <FormControlLabel
      label={label}
      control={<Switch checked={value} onChange={(_, v) => onChange(v)} />}
    />
  );
}
export function EditorFooter({
  saving,
  valid,
  cancel,
  save,
}: {
  saving: boolean;
  valid: boolean;
  cancel: () => void;
  save: () => void;
}) {
  return (
    <div className="footer-actions">
      <span className="spacer" />
      <Button disabled={saving} onClick={cancel}>
        Отмена
      </Button>
      <Button variant="contained" disabled={saving || !valid} onClick={save}>
        {saving ? "Сохранение…" : "Сохранить черновик"}
      </Button>
    </div>
  );
}
