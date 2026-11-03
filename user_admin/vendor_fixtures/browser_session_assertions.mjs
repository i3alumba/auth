// Fixture oracles only. Opaque values are returned for in-memory comparison;
// never serialize, log or hash them as evidence.
export function originalAuthCookie(cookies, expected) {
  if (!Array.isArray(cookies)) throw new Error("fixture_auth_cookie_invalid");
  const matches = cookies.filter(
    (cookie) => cookie?.name === "__Host-fixture-auth-session",
  );
  if (matches.length !== 1)
    throw new Error("fixture_auth_cookie_missing_or_ambiguous");
  const cookie = matches[0];
  if (
    typeof cookie.value !== "string" ||
    !cookie.value ||
    cookie.secure !== true ||
    cookie.path !== "/" ||
    cookie.domain !== "localhost"
  )
    throw new Error("fixture_auth_cookie_invalid");
  if (expected !== undefined && cookie.value !== expected)
    throw new Error("fixture_auth_cookie_changed");
  return cookie.value;
}

export function authenticatedState(payload) {
  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    typeof payload.authenticated !== "boolean"
  )
    throw new Error("fixture_auth_session_response_invalid");
  return payload.authenticated;
}
