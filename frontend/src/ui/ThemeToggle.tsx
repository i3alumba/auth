import { IconButton, SvgIcon } from "@mui/material";
import { useColorScheme } from "@mui/material/styles";

/** Shared accessible control; SVG attributes work with the monitor's strict CSP. */
export function ThemeToggle() {
  const { mode, systemMode, setMode } = useColorScheme();
  const resolved = mode === "system" ? systemMode : mode;
  if (!resolved) return null;
  const dark = resolved === "dark";
  const label = dark ? "Switch to light theme" : "Switch to dark theme";
  return (
    <IconButton
      type="button"
      color="inherit"
      aria-label={label}
      title={label}
      sx={{ width: 44, height: 44 }}
      onClick={() => setMode(dark ? "light" : "dark")}
    >
      <SvgIcon aria-hidden="true" focusable="false" viewBox="0 0 24 24">
        <g
          fill="none"
          stroke="currentColor"
          strokeWidth="1.8"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          {dark ? (
            <>
              <circle cx="12" cy="12" r="4" />
              <path d="M12 2v2m0 16v2M2 12h2m16 0h2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
            </>
          ) : (
            <path d="M20.4 14.8A8.6 8.6 0 0 1 9.2 3.6a8.6 8.6 0 1 0 11.2 11.2Z" />
          )}
        </g>
      </SvgIcon>
    </IconButton>
  );
}
