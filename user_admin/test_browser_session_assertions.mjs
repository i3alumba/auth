import test from "node:test";
import assert from "node:assert/strict";
import {
  originalAuthCookie,
  authenticatedState,
} from "./vendor_fixtures/browser_session_assertions.mjs";

const cookie = {
  name: "__Host-fixture-auth-session",
  value: "PUBLIC_SYNTHETIC_ORIGINAL",
  secure: true,
  path: "/",
  domain: "localhost",
};

test("same original issued cookie is retained only in memory", () => {
  const expected = originalAuthCookie([cookie]);
  assert.equal(originalAuthCookie([{ ...cookie }], expected), expected);
});
test("missing or duplicate cookies cannot prove stale-session rejection", () => {
  for (const cookies of [[], null, [cookie, cookie]])
    assert.throws(() => originalAuthCookie(cookies, cookie.value));
});
test("changed, insecure or wrong-path cookies cannot prove the original contract", () => {
  for (const change of [
    { value: "PUBLIC_SYNTHETIC_CHANGED" },
    { secure: false },
    { path: "/other" },
    { domain: "other.invalid" },
    { value: "" },
  ])
    assert.throws(() =>
      originalAuthCookie([{ ...cookie, ...change }], cookie.value),
    );
});
test("only explicit boolean session states are accepted", () => {
  assert.equal(authenticatedState({ authenticated: true }), true);
  assert.equal(authenticatedState({ authenticated: false }), false);
});
test("missing or malformed authentication fields are not interpreted as denial", () => {
  for (const payload of [
    null,
    [],
    {},
    { authenticated: undefined },
    { authenticated: null },
    { authenticated: "false" },
    { authenticated: 0 },
  ])
    assert.throws(() => authenticatedState(payload));
});
