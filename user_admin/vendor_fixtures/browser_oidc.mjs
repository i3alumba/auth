// Explicit fixture only. Operator allowed --no-sandbox ONLY in this disposable,
// readonly/drop-ALL/no-new-privileges/network-none container. TLS is NOT bypassed.
import { chromium } from "/fixture-playwright/index.mjs";
import { mkdirSync, readFileSync, writeFileSync, renameSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  originalAuthCookie,
  authenticatedState,
} from "./browser_session_assertions.mjs";

const native = "https://localhost:19443";
const issuer = "https://localhost:19445";
const home = "/tmp/owned-browser-home";
const env = { ...process.env, HOME: home };
const accounts = JSON.parse(
  readFileSync("/browser-input/browser-accounts.json", "utf8"),
);
const run = readFileSync("/browser-input/run-id", "utf8");
let browser;
let stage = "new_nss_profile";
let sequence = 0;
let substage = "initializing";
const diagnostic = {};
const result = {
  ok: false,
  actual_browser_oidc: false,
  production_calls: false,
  fixture_only_no_sandbox_authorized: true,
  ignore_https_errors: false,
};

function require(value) {
  if (value !== true) throw new Error("browser_fixture_assertion");
}
function pathOf(url) {
  return new URL(url);
}
async function phase(name) {
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
      /* Not ready, no mutation retry. */
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
  substage = "browser_context";
  const value = await browser.newContext({ ignoreHTTPSErrors: false });
  await value.route("**/*", (route) =>
    [native, issuer].includes(pathOf(route.request().url()).origin)
      ? route.continue()
      : route.abort(),
  );
  return value;
}
async function begin(value, account, deny = false) {
  substage = "browser_page";
  const page = await value.newPage();
  page.on("framenavigated", (frame) => {
    if (frame !== page.mainFrame()) return;
    const u = pathOf(frame.url());
    diagnostic.last_origin =
      u.origin === native ? "native" : u.origin === issuer ? "issuer" : "other";
    diagnostic.last_path = [
      "/users/sign_in",
      "/users/auth/openid_connect",
      "/users/auth/openid_connect/callback",
      "/sso/login/",
      "/o/authorize/",
      "/api/v4/user",
    ].includes(u.pathname)
      ? u.pathname
      : "other";
  });
  substage = "native_sign_in";
  const signIn = await page.goto(native + "/users/sign_in", {
    waitUntil: "domcontentloaded",
    timeout: 30000,
  });
  diagnostic.sign_in_status = signIn?.status() ?? null;
  substage = "native_provider_button";
  const providerForm = page.locator(
    'form[action$="/users/auth/openid_connect"] button[type="submit"]',
  );
  const providerLabel = page.getByRole("button", { name: /Fixture Auth/ });
  diagnostic.provider_form_buttons = await providerForm.count();
  diagnostic.provider_label_buttons = await providerLabel.count();
  if (diagnostic.provider_form_buttons === 1) await providerForm.click();
  else {
    require(diagnostic.provider_label_buttons === 1);
    await providerLabel.click();
  }
  substage = "idp_redirect";
  await page.waitForURL(
    (url) => url.origin === issuer && url.pathname === "/sso/login/",
    { timeout: 20000 },
  );
  substage = "auth_login_form";
  const form = page
    .locator("form")
    .filter({ has: page.locator('input[name="username"]') });
  await form.locator('input[name="username"]').fill(account.username);
  await form.locator('input[name="password"]').fill(account.password);
  const denied = deny
    ? page.waitForResponse(
        (response) => {
          const u = pathOf(response.url());
          return (
            u.origin === issuer &&
            u.pathname === "/o/authorize/" &&
            response.status() === 403
          );
        },
        { timeout: 20000 },
      )
    : null;
  substage = "auth_login_submit";
  await form.locator('button[type="submit"]').click();
  if (deny) {
    substage = "auth_denied_response";
    await denied;
    require(pathOf(page.url()).origin === issuer);
    return page;
  }
  substage = "native_callback_identity";
  await page.waitForURL(
    (url) =>
      url.origin === native &&
      !url.pathname.startsWith("/users/auth/") &&
      url.pathname !== "/users/sign_in",
    { timeout: 30000 },
  );
  const response = await page.goto(native + "/api/v4/user", {
    waitUntil: "domcontentloaded",
    timeout: 20000,
  });
  require(response.status() === 200);
  const identity = await response.json();
  require(String(identity.id) === account.native_id);
  return page;
}
async function denied(account) {
  const value = await context();
  try {
    await begin(value, account, true);
  } finally {
    await value.close();
  }
}
async function privateData(session, account, expected) {
  const url = pathOf(account.private_url);
  require(
    url.origin === native &&
      /^\/api\/v4\/projects\/[1-9][0-9]*\/repository\/files\/README\.md\/raw$/.test(
        url.pathname,
      ),
  );
  substage = expected ? "private_data_allowed" : "private_data_denied";
  const response = await session.page.goto(account.private_url, {
    waitUntil: "domcontentloaded",
    timeout: 20000,
  });
  const matches =
    createHash("sha256")
      .update(await response.body())
      .digest("hex") === account.private_data_sha256;
  diagnostic.private_status = response.status();
  diagnostic.private_data_matches = matches;
  if (expected) require(response.status() === 200 && matches);
  else {
    let redirectedToLogin = false;
    const destination = pathOf(session.page.url());
    if (
      response.status() === 200 &&
      destination.origin === native &&
      destination.pathname === "/users/sign_in"
    ) {
      let request = response.request().redirectedFrom();
      for (
        let count = 0;
        request && count < 5;
        count++, request = request.redirectedFrom()
      ) {
        const previous = await request.response();
        const location = previous?.headers()["location"];
        if (
          request.url() === account.private_url &&
          [302, 303, 307, 308].includes(previous.status()) &&
          location
        ) {
          const next = new URL(location, request.url());
          redirectedToLogin =
            next.origin === native && next.pathname === "/users/sign_in";
        }
      }
      redirectedToLogin =
        redirectedToLogin &&
        (await session.page
          .locator(
            'form[action$="/users/auth/openid_connect"] button[type="submit"]',
          )
          .count()) === 1;
    }
    require(
      !matches &&
        ([401, 403, 404].includes(response.status()) || redirectedToLogin),
    );
    if (redirectedToLogin)
      result.private_access_redirected_to_real_sign_in = true;
  }
  return response.status();
}
async function authSession(session) {
  substage = "auth_session_state";
  diagnostic.auth_cookie_present = (await session.context.cookies(issuer)).some(
    (cookie) => cookie.name === "__Host-fixture-auth-session",
  );
  const response = await session.page.goto(issuer + "/api/session/", {
    waitUntil: "domcontentloaded",
    timeout: 20000,
  });
  require(response.status() === 200);
  const authenticated = authenticatedState(await response.json());
  diagnostic.auth_session_authenticated = authenticated;
  return authenticated;
}
async function loggedIn(account) {
  const value = await context();
  try {
    const page = await begin(value, account);
    return { context: value, page };
  } catch (error) {
    await value.close();
    throw error;
  }
}

try {
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
  await denied(accounts.a);
  result.unbound_identity_denied = true;
  stage = "engine_bind";
  const bound = await phase("bind");
  require(
    bound.ready_for_browser === true &&
      bound.unbound_auth_credentials_absent === true,
  );
  result.unbound_auth_credentials_absent = true;
  stage = "subject_browser_login";
  const a = await loggedIn(accounts.a);
  stage = "control_browser_login";
  const b = await loggedIn(accounts.b);
  await privateData(a, accounts.a, true);
  await privateData(b, accounts.b, true);
  result.auth_to_gitlab_code_flow_matches_confirmed_ids = true;
  stage = "central_revoke";
  const revoked = await phase("revoke");
  require(revoked.epoch_advanced === false);
  await denied(accounts.a);
  result.central_grant_revocation_denies_fresh_oidc = true;
  await privateData(a, accounts.a, true);
  result.central_deny_precedes_native_data_block = true;
  stage = "native_block";
  await phase("block");
  // Fresh OIDC denial was already proved immediately before native block.
  // Do not repeat password work: production limits five attempts per 15 min;
  // the fifth distinct login below proves post-reactivation authentication.
  const control = await b.page.goto(native + "/api/v4/user", {
    waitUntil: "domcontentloaded",
    timeout: 20000,
  });
  require(
    control.status() === 200 &&
      String((await control.json()).id) === accounts.b.native_id,
  );
  result.control_browser_session_preserved = true;
  const existing = await a.page.goto(native + "/api/v4/user", {
    waitUntil: "domcontentloaded",
    timeout: 20000,
  });
  result.banned_existing_identity_endpoint_status = existing.status();
  result.banned_existing_private_data_status = await privateData(
    a,
    accounts.a,
    false,
  );
  await privateData(b, accounts.b, true);
  result.existing_private_browser_data = true;
  result.control_private_browser_data_preserved = true;
  stage = "regrant_then_enable";
  await phase("grant");
  await phase("enable");
  const restored = await loggedIn(accounts.a);
  await privateData(restored, accounts.a, true);
  diagnostic.session_check = "restored_a_before_deactivation";
  require(await authSession(restored));
  const originalRestoredAuthCookie = originalAuthCookie(
    await restored.context.cookies(issuer),
  );
  diagnostic.session_check = "control_b_before_deactivation";
  require(await authSession(b));
  result.fresh_browser_regrant_restores_same_identity = true;
  stage = "deactivation_epoch";
  const deactivated = await phase("deactivate");
  require(
    deactivated.epoch_advanced === true &&
      deactivated.prior_oidc_access_existed === true &&
      deactivated.oauth_credentials_removed === true,
  );
  diagnostic.session_check = "deactivated_original_a";
  require((await authSession(a)) === false);
  await phase("block-deactivated");
  await privateData(restored, accounts.a, false);
  stage = "reactivation_epoch";
  const reactivated = await phase("reactivate");
  require(reactivated.epoch_advanced === false);
  await phase("enable-reactivated");
  // This Auth session has not touched the IdP since BEFORE deactivation.
  diagnostic.session_check = "reactivated_stale_a";
  originalAuthCookie(
    await restored.context.cookies(issuer),
    originalRestoredAuthCookie,
  );
  result.original_auth_cookie_retained_until_reactivation_check = true;
  require((await authSession(restored)) === false);
  result.old_auth_sessions_stay_revoked_after_reactivation = true;
  result.deactivation_removes_oauth_credentials = true;
  // Old-session assertions are complete. Release their renderers before a
  // fourth login instead of relaxing the container's PID/memory limits.
  await a.context.close();
  await restored.context.close();
  stage = "fresh_browser_after_reactivation";
  const final = await loggedIn(accounts.a);
  await privateData(final, accounts.a, true);
  await privateData(b, accounts.b, true);
  diagnostic.session_check = "control_b_after_reactivation";
  require(await authSession(b));
  result.same_private_data_after_reactivation = true;
  await final.context.close();
  await b.context.close();
  result.deactivation_epoch_browser = true;
  result.callback_state_nonce_pkce_negative_cases = "not_tested";
  result.actual_browser_oidc = true;
  result.ok = true;
  result.scope =
    "isolated Auth-GitLab binding/private-browser-data/grant-ban-regrant/deactivation-epoch slice";
} catch (error) {
  const memoryEvents = readFileSync("/sys/fs/cgroup/memory.events", "utf8")
    .split("\n")
    .filter((line) => /^(?:oom|oom_kill|max) /.test(line));
  const pidEvents = readFileSync("/sys/fs/cgroup/pids.events", "utf8")
    .split("\n")
    .filter((line) => /^max /.test(line));
  result.browser_diagnostic = {
    ...diagnostic,
    memory_events: memoryEvents,
    pids_events: pidEvents,
    browser_closed: /(?:has been closed|browser closed|Target crashed)/i.test(
      String(error.message ?? ""),
    ),
    substage,
    error_type: ["Error", "TimeoutError", "TypeError"].includes(error.name)
      ? error.name
      : "other",
    network_error:
      String(error.message ?? "").match(/\bERR_[A-Z_]+\b/)?.[0] ?? "none",
  };
  result.ok = false;
  result.code = "gitlab_browser_oidc_failed";
  result.stage = stage;
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
