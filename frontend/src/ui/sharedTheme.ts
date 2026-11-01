import { createTheme } from "@mui/material/styles";

/** i3alumba UI contract v1: keep this module identical across standalone apps. */
export const theme = createTheme({
  cssVariables: { colorSchemeSelector: "class" },
  colorSchemes: {
    light: {
      palette: {
        primary: { main: "#2563eb" },
        secondary: { main: "#0f766e" },
        background: { default: "#f4f7fb", paper: "#ffffff" },
        text: { primary: "#16243a", secondary: "#53647b" },
        divider: "#dce5f1",
      },
    },
    dark: {
      palette: {
        primary: { main: "#60a5fa" },
        secondary: { main: "#5eead4" },
        background: { default: "#0b1220", paper: "#121e30" },
        text: { primary: "#e6edf7", secondary: "#a8b6cb" },
        divider: "#29394f",
      },
    },
  },
  shape: { borderRadius: 12 },
  typography: {
    fontFamily:
      'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    h5: { fontWeight: 700, letterSpacing: "-0.025em" },
    h6: { fontWeight: 700, letterSpacing: "-0.02em" },
    button: { textTransform: "none", fontWeight: 600 },
  },
  components: {
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: { root: { borderRadius: 10, minHeight: 40 } },
    },
    MuiIconButton: { styleOverrides: { root: { borderRadius: 10 } } },
    MuiTextField: { defaultProps: { size: "small", variant: "outlined" } },
    MuiAppBar: {
      defaultProps: { elevation: 0 },
      styleOverrides: {
        root: {
          backgroundImage: "none",
          backgroundColor: "var(--mui-palette-background-paper)",
          color: "var(--mui-palette-text-primary)",
          borderBottom: "1px solid var(--mui-palette-divider)",
        },
      },
    },
    MuiPaper: {
      defaultProps: { elevation: 0 },
      styleOverrides: { root: { backgroundImage: "none" } },
    },
    MuiCard: {
      styleOverrides: {
        root: { border: "1px solid var(--mui-palette-divider)" },
      },
    },
  },
});
