// Explicit disposable fixture only: readonly/drop-ALL/no-new-privileges/network-none.
// Operator authorized Chromium's no-sandbox exception here only; TLS stays strict.
import { chromium } from "/fixture-playwright/index.mjs";
import { mkdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { execFileSync } from "node:child_process";

const native = "https://localhost:19443";
const issuer = "https://localhost:19445";
const callbackPath = "/_fixture/client";
const home = "/tmp/owned-browser-home";
const env = { ...process.env, HOME: home };
let browser;
let stage = "private_input";
let substage = "initializing";
let sequence = 0;
const diagnostic = {};
let result;

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
      url.pathname === callbackPath
        ? "fixture_client"
        : url.pathname === "/sso/login/"
          ? "auth_login"
          : url.pathname === "/o/authorize/"
            ? "auth_authorize"
            : url.pathname.startsWith("/_synapse/client/")
              ? "synapse_callback"
              : url.pathname.startsWith("/_matrix/client/")
                ? "matrix_client"
                : "other",
  };
}
async function phase(run, name) {
  sequence++;
  writeFileSync(
    "/fixture-control/request.tmp",
    JSON.stringify({ run, sequence, phase: name }),
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
      /* Not ready; never retry a mutation. */
    }
    if (response?.run === run && response.sequence === sequence) {
      require(response.phase === name && response.ok === true);
      return response;
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
    const allowed =
      [native, issuer].includes(url.origin) &&
      (!url.searchParams.has("loginToken") ||
        (url.origin === native && url.pathname === callbackPath));
    return allowed ? route.continue() : route.abort();
  });
  return value;
}
async function login(account, deny = false) {
  const value = await context();
  try {
    const page = await value.newPage();
    let loginTokenObserved = false;
    page.on("request", (request) => {
      if (new URL(request.url()).searchParams.has("loginToken"))
        loginTokenObserved = true;
    });
    page.on("framenavigated", (frame) => {
      if (frame === page.mainFrame())
        Object.assign(diagnostic, locationCategory(frame.url()));
    });
    substage = "native_sso_redirect";
    const redirect = new URL(
      "/_matrix/client/v3/login/sso/redirect/oidc-common-auth",
      native,
    );
    redirect.searchParams.set("redirectUrl", native + callbackPath);
    await page.goto(redirect.href, {
      waitUntil: "domcontentloaded",
      timeout: 30000,
    });
    await page.waitForURL(
      (url) => url.origin === issuer && url.pathname === "/sso/login/",
      { timeout: 20000 },
    );
    substage = "auth_login_form";
    const form = page
      .locator("form")
      .filter({ has: page.locator('input[name="username"]') });
    require((await form.count()) === 1);
    require(
      (await form.locator('input[name="csrfmiddlewaretoken"]').inputValue())
        .length > 0,
    );
    await form.locator('input[name="username"]').fill(account.username);
    await form.locator('input[name="password"]').fill(account.password);
    substage = deny ? "auth_unbound_denial" : "synapse_callback";
    if (deny) {
      const [response] = await Promise.all([
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
      await response.finished();
      await page.waitForURL(
        (url) => url.origin === issuer && url.pathname === "/o/authorize/",
        { waitUntil: "domcontentloaded", timeout: 20000 },
      );
      require(!loginTokenObserved);
      const destination = new URL(page.url());
      require(
        destination.origin === issuer &&
          destination.pathname === "/o/authorize/",
      );
      return;
    }
    await Promise.all([
      page.waitForURL(
        (url) =>
          url.origin === native &&
          url.pathname === callbackPath &&
          url.searchParams.getAll("loginToken").length === 1 &&
          !!url.searchParams.get("loginToken"),
        { waitUntil: "domcontentloaded", timeout: 30000 },
      ),
      form.locator('button[type="submit"]').click(),
    ]);
    substage = "matrix_token_whoami_sync";
    // Tokens never leave this browser execution context, even on failure.
    const verified = await page.evaluate(
      async ({ expectedId, callbackPath }) => {
        const assert = (condition) => {
          if (!condition) throw new Error("matrix_browser_assertion");
        };
        const url = new URL(window.location.href);
        assert(
          url.origin === "https://localhost:19443" &&
            url.pathname === callbackPath &&
            url.searchParams.getAll("loginToken").length === 1,
        );
        let loginToken = url.searchParams.get("loginToken");
        assert(typeof loginToken === "string" && loginToken.length > 0);
        window.history.replaceState(null, "", callbackPath);
        const json = async (response) => {
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
        const session = await json(
          await fetch("/_matrix/client/v3/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            redirect: "error",
            signal: AbortSignal.timeout(20000),
            body: JSON.stringify({
              type: "m.login.token",
              token: loginToken,
              initial_device_display_name: "Owned browser fixture",
            }),
          }),
        );
        loginToken = null;
        assert(session.user_id === expectedId);
        assert(
          typeof session.access_token === "string" &&
            session.access_token.length > 0,
        );
        const headers = { Authorization: `Bearer ${session.access_token}` };
        const whoami = await json(
          await fetch("/_matrix/client/v3/account/whoami", {
            headers,
            redirect: "error",
            signal: AbortSignal.timeout(20000),
          }),
        );
        assert(whoami.user_id === expectedId);
        const sync = await json(
          await fetch("/_matrix/client/v3/sync?timeout=0", {
            headers,
            redirect: "error",
            signal: AbortSignal.timeout(20000),
          }),
        );
        assert(
          typeof sync.next_batch === "string" && sync.next_batch.length > 0,
        );
        return true;
      },
      { expectedId: account.native_id, callbackPath },
    );
    require(verified === true);
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
        /^@[^:]+:.+$/.test(account.native_id),
    );
  }
  require(accounts.a.native_id !== accounts.b.native_id);
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
  await login(accounts.a, true);
  stage = "engine_bind";
  const bound = await phase(run, "bind");
  require(
    bound.engine_bind_published === true &&
      bound.unbound_auth_credentials_absent === true &&
      bound.ready_for_browser === true,
  );
  stage = "subject_browser_login";
  await login(accounts.a);
  stage = "control_browser_login";
  await login(accounts.b);
  result = {
    ok: true,
    actual_browser_oidc: true,
    unbound_identity_denied: true,
    auth_to_matrix_code_flow_matches_confirmed_ids: true,
    matrix_whoami_and_sync: true,
    control_browser_access_preserved: true,
    callback_state_nonce_pkce_negative_cases: "not_tested",
    scope: "isolated initial Auth-Synapse browser provisioning",
  };
} catch (error) {
  result = {
    ok: false,
    code: "matrix_browser_oidc_failed",
    stage,
    browser_diagnostic: {
      ...diagnostic,
      substage,
      error_type: [
        "Error",
        "TimeoutError",
        "TypeError",
        "SyntaxError",
      ].includes(error.name)
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
