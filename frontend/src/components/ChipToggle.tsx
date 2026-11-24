import { Chip } from "@mui/material";

/**
 * Small toggleable tag. Use for choosing from a fixed set of named items when
 * a checkbox list would be too wide (for example, members of a rule group).
 * The label is the human-facing name; `title` carries the technical detail.
 */
export function ChipToggle({ label, selected, title, onClick }: {
  label: string;
  selected: boolean;
  title?: string;
  onClick: () => void;
}) {
  return <Chip
    label={label}
    title={title}
    clickable
    size="small"
    color={selected ? "primary" : "default"}
    variant={selected ? "filled" : "outlined"}
    aria-pressed={selected}
    onClick={onClick}
    sx={{ maxWidth: "100%", "& .MuiChip-label": { overflowWrap: "anywhere" } }}
  />;
}
