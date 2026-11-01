import { expect, test } from "@playwright/test";

test("enhancement keeps original native form and posts CSRF, next and credentials", async ({
  page,
}) => {
  await page.goto("/sso/login/?error=1");
  await expect(page.getByRole("link", { name: "i3alumba" })).toBeVisible();
  await expect(page.getByRole("alert")).toHaveText(
    "Invalid credentials or rate limit",
  );
  await expect(page.locator("form")).toHaveCount(1);
  await page.getByLabel("Username").fill("synthetic-user");
  await page.getByLabel("Password").fill("synthetic-password");
  const request = page.waitForRequest((req) => req.method() === "POST");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  const posted = await request;
  expect(posted.url()).toContain("/sso/login/");
  const fields = new URLSearchParams(posted.postData()!);
  expect(Object.fromEntries(fields)).toEqual({
    csrfmiddlewaretoken: "synthetic-csrf",
    next: "/o/authorize/?state=synthetic&client_id=fixture",
    username: "synthetic-user",
    password: "synthetic-password",
  });
  await expect(page.getByRole("heading")).toHaveText("Native POST received");
});

test("no-JS fallback submits the same native form", async ({ browser }) => {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();
  await page.setViewportSize({ width: 320, height: 720 });
  await page.goto("http://127.0.0.1:4178/sso/login/");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.getByLabel("Username").fill("fixture");
  await page.getByLabel("Password").fill("fixture-password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("heading")).toHaveText("Native POST received");
  await context.close();
});

test("failed asset loading leaves native recovery usable", async ({ page }) => {
  await page.route("**/static/sso/ui/login.js", (route) => route.abort());
  await page.goto("/sso/login/");
  await expect(page.getByLabel("Username")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
});

test("system mode and explicit toggle persist without submitting or losing values", async ({
  page,
}) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/sso/login/");
  await page.getByLabel("Username").fill("kept");
  const toggle = page.getByRole("button", { name: "Switch to light theme" });
  await expect(toggle).toHaveAttribute("type", "button");
  await toggle.click();
  await expect(
    page.getByRole("button", { name: "Switch to dark theme" }),
  ).toBeVisible();
  await expect(page.getByLabel("Username")).toHaveValue("kept");
  expect(
    (await page.context().cookies()).find((c) => c.name === "i3alumba-theme")
      ?.value,
  ).toBe("light");
  await page.reload();
  await expect(
    page.getByRole("button", { name: "Switch to dark theme" }),
  ).toBeVisible();
});

test("cookie wins over local storage; focus and timer synchronize external changes", async ({
  page,
  context,
}) => {
  await context.addCookies([
    { name: "i3alumba-theme", value: "dark", url: "http://127.0.0.1:4178" },
  ]);
  await page.addInitScript(() =>
    localStorage.setItem("i3alumba-color-mode", "light"),
  );
  await page.goto("/sso/login/");
  await expect(
    page.getByRole("button", { name: "Switch to light theme" }),
  ).toBeVisible();
  await page.evaluate(() => {
    document.cookie = "i3alumba-theme=light; Path=/";
    window.dispatchEvent(new Event("focus"));
  });
  await expect(
    page.getByRole("button", { name: "Switch to dark theme" }),
  ).toBeVisible();
  await page.evaluate(() => {
    document.cookie = "i3alumba-theme=dark; Path=/";
  });
  await expect(
    page.getByRole("button", { name: "Switch to light theme" }),
  ).toBeVisible();
});

test("denied storage and cookies do not break form or theme", async ({
  page,
}) => {
  await page.addInitScript(() => {
    Object.defineProperty(window, "localStorage", {
      get() {
        throw new Error("Denied");
      },
    });
    Object.defineProperty(document, "cookie", {
      get() {
        throw new Error("Denied");
      },
      set() {
        throw new Error("Denied");
      },
    });
  });
  await page.emulateMedia({ colorScheme: "light" });
  await page.goto("/sso/login/");
  await page.getByRole("button", { name: "Switch to dark theme" }).click();
  await expect(
    page.getByRole("button", { name: "Switch to light theme" }),
  ).toBeVisible();
  await expect(page.getByLabel("Password")).toBeVisible();
});

test("mobile shell has no horizontal overflow and supports keyboard form navigation", async ({
  page,
}) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await page.goto("/sso/login/");
  await expect(page.getByRole("link", { name: "i3alumba" })).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.getByLabel("Username").focus();
  await page.keyboard.press("Tab");
  await expect(page.getByLabel("Password")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(
    page.getByRole("button", { name: "Sign in", exact: true }),
  ).toBeFocused();
});

test("invalid preferences are ignored in favor of system", async ({
  page,
  context,
}) => {
  await context.addCookies([
    {
      name: "i3alumba-theme",
      value: "not-a-mode",
      url: "http://127.0.0.1:4178",
    },
  ]);
  await page.addInitScript(() =>
    localStorage.setItem("i3alumba-color-mode", "invalid"),
  );
  await page.emulateMedia({ colorScheme: "dark" });
  await page.goto("/sso/login/");
  await expect(
    page.getByRole("button", { name: "Switch to light theme" }),
  ).toBeVisible();
});

test("HTTPS preference is the only shared cookie and synchronizes subdomains", async ({
  context,
}) => {
  // All nominal public URLs are intercepted and fulfilled from the local synthetic fixture.
  await context.route("https://*.i3alumba.ru/**", async (route) => {
    const original = new URL(route.request().url());
    const response = await route.fetch({
      url: `http://127.0.0.1:4178${original.pathname}${original.search}`,
    });
    await route.fulfill({ response });
  });
  await context.addCookies([
    {
      name: "i3alumba-theme",
      value: "light",
      domain: ".i3alumba.ru",
      path: "/",
      secure: true,
      sameSite: "Lax",
    },
  ]);
  const auth = await context.newPage();
  const sibling = await context.newPage();
  await auth.goto("https://auth.i3alumba.ru/sso/login/");
  await sibling.goto("https://main.i3alumba.ru/sso/login/");
  await auth.getByRole("button", { name: "Switch to dark theme" }).click();
  await expect(
    sibling.getByRole("button", { name: "Switch to light theme" }),
  ).toBeVisible();
  const cookies = await context.cookies();
  expect(cookies).toHaveLength(1);
  expect(cookies[0]).toMatchObject({
    name: "i3alumba-theme",
    value: "dark",
    domain: ".i3alumba.ru",
    path: "/",
    secure: true,
    sameSite: "Lax",
  });
  expect(cookies[0].expires - Date.now() / 1000).toBeGreaterThan(31535000);
});
