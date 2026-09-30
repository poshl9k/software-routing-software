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

  // Borders — always semi-transparent white
  border: "rgba(255,255,255,0.08)",
  borderSubtle: "rgba(255,255,255,0.05)",
  borderStrong: "rgba(255,255,255,0.12)",

  tableHeader: "#141516",
};

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
    MuiTextField: { defaultProps: { size: "small" } },
    MuiInputBase: {
      styleOverrides: {
        root: {
          backgroundColor: "rgba(255,255,255,0.02)",
          borderRadius: 6,
        },
      },
    },
    MuiOutlinedInput: {
      styleOverrides: {
        notchedOutline: { borderColor: tokens.borderStrong },
        root: {
          "&:hover .MuiOutlinedInput-notchedOutline": {
            borderColor: tokens.accent,
          },
          "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
            borderColor: tokens.accent,
          },
        },
      },
    },
    MuiSelect: {
      styleOverrides: {
        select: { backgroundColor: "rgba(255,255,255,0.02)" },
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
