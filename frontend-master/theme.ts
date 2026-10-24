import { createTheme } from "@mui/material/styles";

export const tokens = {
  bg: "#08090a", panel: "#0f1011", surface: "#191a1b", surfaceHover: "#28282c",
  text: "#f7f8f8", textSecondary: "#d0d6e0", textTertiary: "#8a8f98",
  brand: "#5e6ad2", accent: "#7170ff", accentHover: "#828fff",
  success: "#10b981", warning: "#f2c94c", error: "#f25656",
  border: "rgba(255,255,255,0.08)", borderSubtle: "rgba(255,255,255,0.05)",
} as const;

export const globalStyles = { ":root": {
  "--vs-bg": tokens.bg, "--vs-panel": tokens.panel, "--vs-surface": tokens.surface,
  "--vs-surface-hover": tokens.surfaceHover, "--vs-text": tokens.text,
  "--vs-text-secondary": tokens.textSecondary, "--vs-text-tertiary": tokens.textTertiary,
  "--vs-brand": tokens.brand, "--vs-accent": tokens.accent,
  "--vs-accent-hover": tokens.accentHover, "--vs-success": tokens.success,
  "--vs-warning": tokens.warning, "--vs-error": tokens.error,
  "--vs-border": tokens.border, "--vs-border-subtle": tokens.borderSubtle,
} } as const;

export const theme = createTheme({
  palette: {
    mode: "dark", primary: { main: tokens.accent }, secondary: { main: tokens.brand },
    success: { main: tokens.success }, warning: { main: tokens.warning }, error: { main: tokens.error },
    background: { default: tokens.bg, paper: tokens.panel },
    text: { primary: tokens.text, secondary: tokens.textSecondary }, divider: tokens.border,
  },
  typography: { fontFamily: 'Inter, system-ui, -apple-system, "Segoe UI", sans-serif', button: { textTransform: "none" } },
  shape: { borderRadius: 8 },
});
