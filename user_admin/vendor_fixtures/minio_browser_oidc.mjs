// Disposable readonly/drop-ALL/no-new-privileges/network-none fixture only.
// The operator's no-sandbox exception applies only here; TLS remains strict.
// Tests this guard's missing/wrong-browser/replay binding, not full OIDC/PKCE.
import { chromium } from "/fixture-playwright/index.mjs";
import { mkdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { execFileSync } from "node:child_process";

const native = "https://minio.i3alumba.ru";
const issuer = "https://auth.i3alumba.ru";
const callbackPath = "/api/v1/login/oauth2/auth";
const guardCookie = "__Host-minio-sso-browser";
const home = "/tmp/owned-browser-home";
const env = { ...process.env, HOME: home };
let browser;
let stage = "private_input";
let substage = "initializing";
let sequence = 0;
let result;
const diagnostic = {};

function require(value) {
  if (value !== true) throw new Error("browser_fixture_assertion");
}
function locationCategory(raw) {
  const url = new URL(raw);
  return {
    last_origin:
      url.origin === native
        ? "native"
        : url.origin === issuer
          ? "issuer"
          : "other",
    last_path:
      url.pathname === "/login"
        ? "console_login"
        : url.pathname === "/oauth_callback"
          ? "console_callback"
          : url.pathname === "/sso/login/"
            ? "auth_login"
            : url.pathname === "/o/authorize/"
              ? "auth_authorize"
              : "other",
  };
}
async function phase(run) {
  sequence++;
  writeFileSync(
    "/fixture-control/request.tmp",
    JSON.stringify({ run, sequence, phase: "bind" }),
    { mode: 0o600 },
  );
  renameSync("/fixture-control/request.tmp", "/fixture-control/request.json");
  const deadline = Date.now() + 120000;
  while (Date.now() < deadline) {
    let response;
    try {
      response = JSON.parse(
        readFileSync("/fixture-control/response.json", "utf8"),
      );
    } catch {
      // Not ready; never retry a mutation.
    }
    if (response?.run === run && response.sequence === sequence) {
      require(response.phase === "bind" && response.ok === true);
      require(
        response.engine_bind_published === true &&
          response.unbound_auth_credentials_absent === true &&
          response.ready_for_browser === true,
      );
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("browser_fixture_controller_timeout");
}
async function context() {
  const value = await browser.newContext({
    ignoreHTTPSErrors: false,
    serviceWorkers: "block",
  });
  await value.route("**/*", (route) => {
    const url = new URL(route.request().url());
    return [native, issuer].includes(url.origin)
      ? route.continue()
      : route.abort();
  });
  await value.routeWebSocket("**/*", (socket) => socket.close());
  return value;
}
async function status(page) {
  return page.evaluate(async () => {
    const response = await fetch("/_fixture/status", {
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(15000),
    });
    if (
      response.status !== 200 ||
      (response.headers.get("content-type") || "").split(";", 1)[0].trim() !==
        "application/json"
    )
      throw new Error("browser_fixture_assertion");
    const data = await response.json();
    // Do not return any unexpected router data into diagnostics or artifacts.
    return {
      token_exchange_count: data.token_exchange_count,
      verified_subject_count: data.verified_subject_count,
      claims_verified: data.claims_verified,
      observer_failed: data.observer_failed,
      token_request_count: data.token_request_count,
    };
  });
}
function counts(value, count) {
  require(
    value.token_request_count === count &&
      value.token_exchange_count === count &&
      value.verified_subject_count === count &&
      value.observer_failed === false &&
      value.claims_verified === count > 0,
  );
}
async function guardedCookie(value) {
  const cookies = (await value.cookies(native)).filter(
    (cookie) => cookie.name === guardCookie,
  );
  require(cookies.length === 1);
  const cookie = cookies[0];
  require(
    cookie.secure === true &&
      cookie.httpOnly === true &&
      cookie.domain === "minio.i3alumba.ru" &&
      cookie.path === "/" &&
      /^[A-Za-z0-9_-]{43}$/.test(cookie.value),
  );
  return cookie.value;
}
async function postCallback(page, data) {
  return page.evaluate(
    async ({ path, data }) => {
      const response = await fetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        redirect: "error",
        signal: AbortSignal.timeout(15000),
        body: JSON.stringify(data),
      });
      await response.arrayBuffer();
      return response.status;
    },
    { path: callbackPath, data },
  );
}
async function negativeGuard(original, data) {
  substage = "guard_missing_cookie";
  const originalCookie = await guardedCookie(original);
  const attacker = await context();
  try {
    const page = await attacker.newPage();
    const landing = await page.goto(native + "/_fixture/attacker", {
      waitUntil: "domcontentloaded",
      timeout: 20000,
    });
    require(landing?.status() === 200);
    require(
      (await attacker.cookies(native)).every((c) => c.name !== guardCookie),
    );
    counts(await status(page), 0);
    require((await postCallback(page, data)) === 403);
    counts(await status(page), 0);
    substage = "guard_wrong_browser";
    require(
      await page.evaluate(async () => {
        const response = await fetch("/api/v1/login", {
          redirect: "error",
          signal: AbortSignal.timeout(15000),
        });
        await response.arrayBuffer();
        return response.status === 200;
      }),
    );
    require((await guardedCookie(attacker)) !== originalCookie);
    require((await postCallback(page, data)) === 403);
    counts(await status(page), 0);
  } finally {
    await attacker.close();
  }
}
async function begin(value, account) {
  const page = await value.newPage();
  page.on("framenavigated", (frame) => {
    if (frame === page.mainFrame())
      Object.assign(diagnostic, locationCategory(frame.url()));
  });
  substage = "console_login_metadata";
  const metadata = page
    .waitForResponse(
      (response) => {
        const url = new URL(response.url());
        return (
          url.origin === native &&
          url.pathname === "/api/v1/login" &&
          response.request().method() === "GET"
        );
      },
      { timeout: 20000 },
    )
    .catch(() => null);
  const landing = await page.goto(native + "/login", {
    waitUntil: "domcontentloaded",
    timeout: 30000,
  });
  require(landing?.status() === 200);
  const response = await metadata;
  require(response !== null && response.status() === 200);
  await response.finished();
  const loginMetadata = await response.json();
  diagnostic.login_strategy = ["form", "redirect"].includes(
    loginMetadata.loginStrategy,
  )
    ? loginMetadata.loginStrategy
    : "other";
  diagnostic.redirect_rule_count = Array.isArray(loginMetadata.redirectRules)
    ? loginMetadata.redirectRules.length
    : -1;
  await guardedCookie(value);
  substage = "console_provider_click";
  diagnostic.public_login_controls = (
    await page.locator('button, a, [role="button"]').allTextContents()
  )
    .map((text) => text.trim())
    .filter(
      (text) =>
        /^[A-Za-z0-9 ()-]{1,60}$/.test(text) &&
        /log|sign|auth|sso|openid|fixture|provider/i.test(text),
    )
    .slice(0, 12);
  // This exact Console hides SSO behind its real alternative-methods control.
  const alternatives = page
    .getByRole("button", { name: "Other Authentication Methods", exact: true })
    .or(
      page.getByRole("link", {
        name: "Other Authentication Methods",
        exact: true,
      }),
    );
  require((await alternatives.count()) === 1);
  await alternatives.click();
  diagnostic.public_provider_text = (await page.locator("body").innerText())
    .split("\n")
    .map((text) => text.trim())
    .filter((text) => /^[A-Za-z0-9 ()-]{1,60}$/.test(text))
    .slice(0, 18);
  diagnostic.public_rule_fields = Object.keys(
    loginMetadata.redirectRules[0] ?? {},
  )
    .filter((key) => /^[a-zA-Z]{1,30}$/.test(key))
    .slice(0, 8);
  // Select a real rendered provider control, never manufacture an authorize URL.
  // The v0.27 provider is a rendered menu item, not a button/link role.
  const provider = page.getByText("Fixture Auth", { exact: true });
  await provider.first().waitFor({ state: "visible", timeout: 20000 });
  require((await provider.count()) === 1);
  await provider.click();
  await page.waitForURL(
    (url) => url.origin === issuer && url.pathname === "/sso/login/",
    { timeout: 20000 },
  );
  substage = "auth_password_form";
  const form = page.locator("form").filter({
    has: page.locator('input[name="username"]'),
  });
  require((await form.count()) === 1);
  require(
    (await form.locator('input[name="csrfmiddlewaretoken"]').inputValue())
      .length > 0,
  );
  await form.locator('input[name="username"]').fill(account.username);
  await form.locator('input[name="password"]').fill(account.password);
  return { page, form };
}
async function unbound(account) {
  const value = await context();
  try {
    let callbackObserved = false;
    value.on("request", (request) => {
      const url = new URL(request.url());
      if (url.origin === native && url.pathname === callbackPath)
        callbackObserved = true;
    });
    const { page, form } = await begin(value, account);
    substage = "auth_unbound_denial";
    const [denial] = await Promise.all([
      page.waitForResponse(
        (response) => {
          const url = new URL(response.url());
          return (
            url.origin === issuer &&
            url.pathname === "/o/authorize/" &&
            response.status() === 403
          );
        },
        { timeout: 20000 },
      ),
      form.locator('button[type="submit"]').click(),
    ]);
    await denial.finished();
    await page.waitForURL(
      (url) => url.origin === issuer && url.pathname === "/o/authorize/",
      { waitUntil: "domcontentloaded", timeout: 20000 },
    );
    require(!callbackObserved);
    require(
      (await value.cookies(native)).every((cookie) => cookie.name !== "token"),
    );
    // A separate same-origin page observes counters without changing the denial page.
    const probe = await value.newPage();
    await probe.goto(native + "/_fixture/attacker", {
      waitUntil: "domcontentloaded",
    });
    counts(await status(probe), 0);
  } finally {
    await value.close();
  }
}
async function consoleData(page, own, foreign) {
  substage = "console_session_buckets_canary";
  require(
    await page.evaluate(
      async ({ own, foreign }) => {
        const assert = (value) => {
          if (value !== true) throw new Error("browser_fixture_assertion");
        };
        const get = (path) =>
          fetch(path, {
            credentials: "same-origin",
            redirect: "error",
            cache: "no-store",
            signal: AbortSignal.timeout(20000),
          });
        const json = async (path) => {
          const response = await get(path);
          assert(response.status === 200);
          assert(
            (response.headers.get("content-type") || "")
              .split(";", 1)[0]
              .trim() === "application/json",
          );
          const body = await response.json();
          assert(
            body !== null && typeof body === "object" && !Array.isArray(body),
          );
          return body;
        };
        await json("/api/v1/session");
        const listing = await json("/api/v1/buckets");
        assert(Array.isArray(listing.buckets) && listing.buckets.length === 1);
        assert(listing.buckets[0].name === own.native_id);
        const target = (bucket) =>
          "/api/v1/buckets/" +
          bucket +
          "/objects/download?" +
          new URLSearchParams({ prefix: btoa("probe.txt") });
        const download = await get(target(own.native_id));
        assert(download.status === 200);
        // Private canary bytes remain in the browser RAM, including on failure.
        const bytes = await download.arrayBuffer();
        const digest = await crypto.subtle.digest("SHA-256", bytes);
        const hex = Array.from(new Uint8Array(digest), (byte) =>
          byte.toString(16).padStart(2, "0"),
        ).join("");
        assert(hex === own.canary_sha256);
        const denied = await get(target(foreign.native_id));
        assert(denied.status === 403);
        await denied.arrayBuffer();
        return true;
      },
      {
        own: { native_id: own.native_id, canary_sha256: own.canary_sha256 },
        foreign: { native_id: foreign.native_id },
      },
    ),
  );
}
async function login(account, foreign, guardProbe) {
  const value = await context();
  try {
    let intercepted = false;
    let callbackData;
    let settle;
    const checked = new Promise((resolve) => {
      settle = resolve;
    });
    if (guardProbe) {
      await value.route(
        (url) => url.origin === native && url.pathname === callbackPath,
        async (route) => {
          if (intercepted || route.request().method() !== "POST") {
            await route.continue();
            return;
          }
          intercepted = true;
          try {
            const request = route.request();
            require(request.url() === native + callbackPath);
            callbackData = JSON.parse(request.postData());
            require(
              typeof callbackData.code === "string" &&
                callbackData.code.length > 0 &&
                typeof callbackData.state === "string" &&
                callbackData.state.length > 0,
            );
            await negativeGuard(value, callbackData);
            substage = "original_callback_continued";
            await route.continue(); // The real original request, wholly unchanged.
            settle(true);
          } catch {
            await route.abort().catch(() => {});
            settle(false);
          }
        },
      );
    }
    const { page, form } = await begin(value, account);
    substage = "console_real_callback";
    const [callback] = await Promise.all([
      page.waitForResponse(
        (response) =>
          response.url() === native + callbackPath &&
          response.request().method() === "POST",
        { timeout: 90000 },
      ),
      form.locator('button[type="submit"]').click({ noWaitAfter: true }),
    ]);
    await callback.finished();
    if (guardProbe) require(await checked);
    require([200, 204].includes(callback.status()));
    await page.waitForURL(
      (url) =>
        url.origin === native &&
        !["/login", "/oauth_callback"].includes(url.pathname),
      { waitUntil: "domcontentloaded", timeout: 30000 },
    );
    const tokens = (await value.cookies(native)).filter(
      (cookie) => cookie.name === "token",
    );
    require(tokens.length === 1);
    require(
      tokens[0].value.length > 0 &&
        tokens[0].secure === true &&
        tokens[0].httpOnly === true &&
        tokens[0].domain === "minio.i3alumba.ru",
    );
    await consoleData(page, account, foreign);
    if (guardProbe) {
      substage = "guard_consumed_replay";
      counts(await status(page), 1);
      require((await postCallback(page, callbackData)) === 403);
      counts(await status(page), 1);
      callbackData = null;
    } else {
      counts(await status(page), 2);
    }
  } finally {
    await value.close();
  }
}

try {
  const accounts = JSON.parse(
    readFileSync("/browser-input/browser-accounts.json", "utf8"),
  );
  const run = readFileSync("/browser-input/run-id", "utf8");
  for (const account of [accounts.a, accounts.b]) {
    require(
      typeof account?.username === "string" &&
        account.username.length > 0 &&
        typeof account.password === "string" &&
        account.password.length > 0 &&
        typeof account.native_id === "string" &&
        /^ua-[0-9a-f]{32}$/.test(account.native_id) &&
        typeof account.auth_id === "string" &&
        /^[1-9][0-9]*$/.test(account.auth_id) &&
        typeof account.canary_sha256 === "string" &&
        /^[0-9a-f]{64}$/.test(account.canary_sha256),
    );
  }
  require(
    accounts.a.native_id !== accounts.b.native_id &&
      accounts.a.auth_id !== accounts.b.auth_id,
  );
  stage = "new_nss_profile";
  for (const relative of [".pki/nssdb", ".local/share/pki/nssdb"]) {
    const directory = `${home}/${relative}`;
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    execFileSync(
      "/fixture-public-bin/certutil",
      ["-N", "-d", `sql:${directory}`, "--empty-password"],
      { env, stdio: "pipe", timeout: 10000 },
    );
    execFileSync(
      "/fixture-public-bin/certutil",
      [
        "-A",
        "-d",
        `sql:${directory}`,
        "-n",
        "Owned Auth fixture CA",
        "-t",
        "C,,",
        "-i",
        "/browser-input/ca.crt",
      ],
      { env, stdio: "pipe", timeout: 10000 },
    );
  }
  browser = await chromium.launch({
    executablePath: "/opt/google/chrome/chrome",
    headless: true,
    chromiumSandbox: false,
    env,
    timeout: 15000,
  });
  stage = "unbound_denial";
  await unbound(accounts.a);
  stage = "engine_bind";
  await phase(run);
  stage = "subject_browser_login";
  await login(accounts.a, accounts.b, true);
  stage = "control_browser_login";
  await login(accounts.b, accounts.a, false);
  result = {
    ok: true,
    actual_browser_oidc: true,
    unbound_identity_denied: true,
    minio_own_console_data: true,
    minio_foreign_bucket_denied: true,
    minio_bucket_listing_scoped: true,
    console_cookie_secure_httponly: true,
    minio_token_claims_verified: true,
    guard_missing_cookie_denied: true,
    guard_wrong_browser_denied: true,
    guard_replay_denied: true,
    control_browser_access: true,
    scope: "isolated initial Auth-MinIO Console provisioning",
  };
} catch (error) {
  result = {
    ok: false,
    code: "minio_browser_oidc_failed",
    stage,
    browser_diagnostic: {
      ...diagnostic,
      substage,
      error_type: [
        "Error",
        "TimeoutError",
        "TypeError",
        "SyntaxError",
      ].includes(error?.name)
        ? error.name
        : "other",
    },
  };
  process.exitCode = 1;
} finally {
  if (browser) await browser.close().catch(() => {});
  writeFileSync("/fixture-control/browser-result.tmp", JSON.stringify(result), {
    mode: 0o600,
  });
  renameSync(
    "/fixture-control/browser-result.tmp",
    "/fixture-control/browser-result.json",
  );
}
