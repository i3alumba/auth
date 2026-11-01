import { useLayoutEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import { createPortal } from "react-dom";
import {
  AppBar,
  Box,
  Button,
  Card,
  Container,
  CssBaseline,
  Link,
  Toolbar,
  Typography,
} from "@mui/material";
import { ThemeProvider } from "@mui/material/styles";
import { theme } from "./ui/sharedTheme";
import { MODE_STORAGE_KEY, createThemeStorageManager } from "./ui/themeStorage";
import { ThemeToggle } from "./ui/ThemeToggle";
import "./native.css";

const nativePage = document.getElementById("native-login");
const submitSlot = document.getElementById("login-submit");
const root = document.getElementById("login-ui");
const storageManager = createThemeStorageManager();

function LoginShell({
  page,
  submit,
}: {
  page: HTMLElement;
  submit: HTMLElement;
}) {
  const host = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    // Move the server form intact: autofill, CSRF, next and native submission stay owned by Django.
    host.current?.append(page);
    page.classList.add("enhanced");
  }, [page]);
  return (
    <>
      <AppBar position="static">
        <Toolbar sx={{ gap: 2, width: "100%", maxWidth: 1280, mx: "auto" }}>
          <Link
            href="https://main.i3alumba.ru/"
            color="inherit"
            underline="hover"
            variant="h6"
          >
            i3alumba
          </Link>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            Auth
          </Typography>
          <ThemeToggle />
        </Toolbar>
      </AppBar>
      <Container maxWidth="lg" sx={{ py: { xs: 4, sm: 8 } }}>
        <Card sx={{ maxWidth: 440, mx: "auto", p: { xs: 3, sm: 4 } }}>
          <Box ref={host} />
        </Card>
      </Container>
      {createPortal(
        <Button type="submit" variant="contained" fullWidth>
          Sign in
        </Button>,
        submit,
      )}
    </>
  );
}

if (nativePage && submitSlot && root) {
  createRoot(root).render(
    <ThemeProvider
      theme={theme}
      defaultMode="system"
      modeStorageKey={MODE_STORAGE_KEY}
      storageManager={storageManager}
    >
      <CssBaseline enableColorScheme />
      <LoginShell page={nativePage} submit={submitSlot} />
    </ThemeProvider>,
  );
}
