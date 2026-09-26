import { createTheme } from "@mui/material/styles";
export const tokens = {
  sidebar: "#1a2332",
  sidebarText: "#b8c2d0",
  blue: "#2f81f7",
  blueSoft: "#e8f1fe",
  workspace: "#f4f6fa",
  card: "#ffffff",
  border: "#e3e8f0",
  text: "#1c2433",
  secondary: "#6b7686",
  green: "#1a9e55",
  greenSoft: "#e2f6ec",
  amber: "#c77c0a",
  amberSoft: "#fdf3e0",
  red: "#d43c3c",
  redSoft: "#fdeaea",
  purple: "#7048c8",
  purpleSoft: "#f0eafc",
  tableHeader: "#f8fafc",
};
export const theme = createTheme({
  palette: {
    primary: { main: tokens.blue },
    secondary: { main: tokens.purple },
    success: { main: tokens.green },
    warning: { main: tokens.amber },
    error: { main: tokens.red },
    background: { default: tokens.workspace, paper: tokens.card },
    text: { primary: tokens.text, secondary: tokens.secondary },
    divider: tokens.border,
  },
  typography: {
    fontFamily:
      '-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif',
    fontSize: 14,
    h1: { fontSize: 22, fontWeight: 700 },
    h2: { fontSize: 15, fontWeight: 700 },
    button: { textTransform: "none", fontWeight: 600 },
  },
  shape: { borderRadius: 10 },
  components: {
    MuiButton: {
      defaultProps: { size: "small", disableElevation: true },
      styleOverrides: {
        root: { borderRadius: 8, fontSize: 13, padding: "7px 16px" },
      },
    },
    MuiTable: { defaultProps: { size: "small" } },
    MuiTableCell: {
      styleOverrides: {
        root: {
          padding: "9px 10px",
          fontSize: 13,
          borderBottom: "1px solid #eef1f6",
        },
        head: {
          padding: "8px 10px",
          fontSize: 11.5,
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: ".4px",
          background: tokens.tableHeader,
          color: tokens.secondary,
        },
      },
    },
    MuiTextField: { defaultProps: { size: "small" } },
    MuiTab: {
      styleOverrides: {
        root: {
          minHeight: 40,
          textTransform: "none",
          fontSize: 13.5,
          padding: "8px 16px",
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
      },
    },
    MuiAlert: { styleOverrides: { root: { marginBottom: 16 } } },
  },
});
