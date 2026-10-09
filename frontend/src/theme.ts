import { createTheme } from "@mui/material/styles";

/**
 * Linear-inspired dark design system.
 * Darkness is the native medium: content emerges from near-black via
 * calibrated luminance steps and whisper-thin semi-transparent white borders.
 */
export const tokens = {
  // Surfaces — deeper = darker
  bg: "#08090a",
  panel: "#0f1011",
  surface: "#191a1b",
  surfaceHover: "#28282c",

  // Text — never pure white
  text: "#f7f8f8",
  textSecondary: "#d0d6e0",
  textTertiary: "#8a8f98",
  textQuaternary: "#62666d",

  // Brand (the only chromatic accent)
  brand: "#5e6ad2",
  accent: "#7170ff",
  accentHover: "#828fff",

  // Status
  success: "#10b981",
  successSoft: "rgba(16,185,129,0.14)",
  warning: "#f2c94c",
  warningSoft: "rgba(242,201,76,0.14)",
  error: "#f25656",
  errorSoft: "rgba(242,86,86,0.14)",
  purple: "#a78bfa",
  purpleSoft: "rgba(167,139,250,0.14)",
  badgeBlue: "#9b9bff",
  badgeBlueSoft: "rgba(113,112,255,0.14)",
  badgeGreen: "#4ade80",
  badgeRed: "#f87171",
  statusUnknown: "#8a8f98",
  statusUnknownSoft: "rgba(138,143,152,0.12)",

  // Borders — always semi-transparent white
  border: "rgba(255,255,255,0.08)",
  borderSubtle: "rgba(255,255,255,0.05)",
  borderStrong: "rgba(255,255,255,0.12)",

  tableHeader: "#141516",
  shadow: "rgba(0, 0, 0, 0.4) 0px 2px 4px",
  transparent: "transparent",
};

/**
 * Colour tokens are owned here and exposed to the layout stylesheet as CSS
 * variables, so `styles.css` carries layout only — never a hard-coded colour.
 * Injected once in `App` via MUI `<GlobalStyles>`.
 */
export const globalStyles = {
  ":root": {
    "--vs-bg": tokens.bg,
    "--vs-panel": tokens.panel,
    "--vs-surface": tokens.surface,
    "--vs-surface-hover": tokens.surfaceHover,
    "--vs-text": tokens.text,
    "--vs-text-secondary": tokens.textSecondary,
    "--vs-text-tertiary": tokens.textTertiary,
    "--vs-brand": tokens.brand,
    "--vs-accent": tokens.accent,
    "--vs-accent-hover": tokens.accentHover,
    "--vs-accent-soft": "rgba(113,112,255,0.10)",
    "--vs-success": tokens.success,
    "--vs-badge-blue": tokens.badgeBlue,
    "--vs-badge-blue-soft": tokens.badgeBlueSoft,
    "--vs-badge-green": tokens.badgeGreen,
    "--vs-badge-red": tokens.badgeRed,
    "--vs-status-unknown": tokens.statusUnknown,
    "--vs-status-unknown-soft": tokens.statusUnknownSoft,
    "--vs-warning": tokens.warning,
    "--vs-warning-soft": "rgba(242,201,76,0.10)",
    "--vs-warning-border": "rgba(242,201,76,0.25)",
    "--vs-error": tokens.error,
    "--vs-border": tokens.border,
    "--vs-border-subtle": tokens.borderSubtle,
    "--vs-border-strong": tokens.borderStrong,
    "--vs-wash": "rgba(255,255,255,0.02)",
    "--vs-wash-hover": "rgba(255,255,255,0.04)",
    "--vs-track": "rgba(255,255,255,0.08)",
    "--vs-scrollbar": "rgba(255,255,255,0.14)",
    "--vs-scrollbar-hover": "rgba(255,255,255,0.24)",
    "--vs-shadow": tokens.shadow,
    "--vs-transparent": tokens.transparent,
  },
} as const;

export const theme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: tokens.accent },
    secondary: { main: tokens.brand },
    success: { main: tokens.success },
    warning: { main: tokens.warning },
    error: { main: tokens.error },
    info: { main: tokens.accent },
    background: { default: tokens.bg, paper: tokens.panel },
    text: { primary: tokens.text, secondary: tokens.textSecondary },
    divider: tokens.border,
  },
  typography: {
    fontFamily:
      'Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
    fontSize: 14,
    h1: { fontSize: 22, fontWeight: 600, letterSpacing: "-0.01em" },
    h2: { fontSize: 15, fontWeight: 600, letterSpacing: "-0.005em" },
    button: { textTransform: "none", fontWeight: 500 },
  },
  shape: { borderRadius: 8 },
  components: {
    MuiButton: {
      defaultProps: { size: "small", disableElevation: true },
      styleOverrides: {
        root: {
          borderRadius: 6,
          fontSize: 13,
          padding: "7px 16px",
          textTransform: "none",
        },
        containedPrimary: {
          backgroundColor: tokens.brand,
          color: "#ffffff",
          "&:hover": { backgroundColor: tokens.accentHover },
        },
        contained: { boxShadow: "none" },
        outlined: {
          borderColor: tokens.borderStrong,
          color: tokens.textSecondary,
          "&:hover": {
            borderColor: tokens.accent,
            backgroundColor: "rgba(255,255,255,0.04)",
          },
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          backgroundColor: tokens.panel,
        },
      },
    },
    MuiTable: { defaultProps: { size: "small" } },
    MuiTableCell: {
      styleOverrides: {
        root: {
          padding: "9px 12px",
          fontSize: 13,
          verticalAlign: "top",
          borderBottom: `1px solid ${tokens.borderSubtle}`,
          color: tokens.textSecondary,
          overflowWrap: "anywhere",
          wordBreak: "break-word",
        },
        head: {
          padding: "9px 12px",
          fontSize: 11.5,
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: "0.4px",
          backgroundColor: tokens.tableHeader,
          color: tokens.textTertiary,
        },
      },
    },
    MuiTextField: { defaultProps: { size: "small", variant: "standard" } },
    MuiSelect: { defaultProps: { variant: "standard" } },
    MuiInputBase: {
      styleOverrides: {
        root: {
          backgroundColor: "transparent",
          borderRadius: 6,
        },
      },
    },
    // Flat fields: no outlined box. A whisper-thin bottom rule is the only
    // affordance and it lifts to the accent colour on hover/focus.
    MuiInput: {
      styleOverrides: {
        root: {
          "&:before": { borderBottomColor: tokens.borderStrong },
          "&:hover:not(.Mui-disabled):before": {
            borderBottomColor: tokens.accent,
          },
          "&.Mui-focused:after": { borderBottomColor: tokens.accent },
          "&.Mui-error:after": { borderBottomColor: tokens.error },
        },
      },
    },
    MuiSwitch: {
      styleOverrides: {
        root: { color: tokens.textTertiary },
        switchBase: {
          "&.Mui-checked": { color: tokens.accent },
        },
        track: { backgroundColor: "rgba(255,255,255,0.12)" },
      },
    },
    MuiTab: {
      styleOverrides: {
        root: {
          minHeight: 40,
          textTransform: "none",
          fontSize: 13.5,
          fontWeight: 500,
          padding: "8px 16px",
          color: tokens.textTertiary,
          "&.Mui-selected": { color: tokens.text },
        },
      },
    },
    MuiTabs: {
      styleOverrides: {
        root: {
          minHeight: 40,
          marginBottom: 14,
          borderBottom: `1px solid ${tokens.border}`,
        },
        indicator: { backgroundColor: tokens.accent },
      },
    },
    MuiAlert: {
      styleOverrides: {
        root: {
          marginBottom: 16,
          borderRadius: 8,
          backgroundColor: "rgba(255,255,255,0.04)",
          border: `1px solid ${tokens.border}`,
        },
        standardInfo: {
          backgroundColor: "rgba(113,112,255,0.10)",
          borderColor: "rgba(113,112,255,0.25)",
          color: tokens.text,
        },
        standardSuccess: {
          backgroundColor: tokens.successSoft,
          borderColor: "rgba(16,185,129,0.25)",
          color: tokens.text,
        },
        standardWarning: {
          backgroundColor: tokens.warningSoft,
          borderColor: "rgba(242,201,76,0.25)",
          color: tokens.text,
        },
        standardError: {
          backgroundColor: tokens.errorSoft,
          borderColor: "rgba(242,86,86,0.25)",
          color: tokens.text,
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          backgroundColor: tokens.surface,
          backgroundImage: "none",
          border: `1px solid ${tokens.border}`,
          borderRadius: 12,
        },
      },
    },
  },
});
