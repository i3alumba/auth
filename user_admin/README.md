# User administration: disabled central API and native-lifecycle foundation

**Not enabled or production-ready.** Source includes the central HTTP API,
credential epochs and offline native-lifecycle foundation. The parent Dashboard
contains the Users matrix and native pause/resume controls. A separate default-dry-run
worker is prepared, but every versioned native profile remains activation-blocked.
No production credentials or existing-user role migration is provided. See
[WORKER.md](WORKER.md) for strict file configuration, modes, Docker usage and gates. See parent
`docs/USER-ADMINISTRATION.md` for scope and Astra review gates.
`USER_ADMIN_API_ENABLED=False` and `USER_ADMIN_HOSTING_GRANTS_READY=False` remain
explicit defaults for separate opt-in environment switches. The prepared Hosting
consumer contract must be deployed and verified before enabling its switch;
until then independent Hosting mutations are rejected.

The schema is additive. The migration seeds only a singleton database lock; it
never scans users or schedules native work. Web settings explicitly leave
`USER_ADMIN_NATIVE_EXECUTION_ENABLED=False`. Dedicated worker settings require their
own explicit opt-in and still reject all current blocked profiles before reading
private credentials; they expose no HTTP endpoints.

Jenkins is explicitly outside the operator-approved scope. Scheduling rejects
it, and execution rejects legacy/imported Jenkins queue rows before consulting
any adapter. Existing Jenkins identities, groups, SSO, native rights, credentials,
sessions, jobs and configuration must not be managed by this panel. Its existing
Dashboard card and admission rules stay unchanged, including for `is_admin`.

## Current MVP: provisioning first

The default worker scope is now `provision_only`: new CREATE and its exact original
BIND/initial ENABLE continuations only. Independent provisioning acceptance blockers
remain sealed. BLOCK is finalized without an adapter as
`unsupported/revocation_deferred`; later-generation rebind/unlock is
`unsupported/reenable_not_supported`. Pause, UNKNOWN reservations, stale generations,
current enabled intent, live grants and ownership protections remain enforced.
Central denial stops new Auth issuance, not existing external credentials. Full
native lifecycle/revocation is deferred, not implicitly accepted by this MVP.
See `WORKER.md` for action predicates and remaining deployment boundaries.

## Internal contracts

- `engine.schedule(...)` records a versioned desired target state, outbox
  operation and audit in one transaction. The central API calls it
  inside its own atomic user/permission transaction. Only live active superusers
  may schedule; `is_staff` alone is insufficient.
- `UserControl.creation_receipt` is reserved for a user created transactionally
  by the panel. Existing users/bindings cannot be silently adopted or
  provisioned. There is intentionally no automatic adoption function.
- `engine.execute(operation_id, adapter)` performs at most one native call.
  Read-only inspection precedes mutations of existing accounts. Adapters declare
  exact service/instance capabilities and create-only support, and must verify
  immutable subject/owner/native ID before returning an `Observation`.
- Remote IO never runs while the singleton database lock is held. Per-target
  `running`/`outcome_unknown` reservations do not expire or get reclaimed.
  Restart/recovery must not blindly replay an ambiguous remote mutation.
- Late create results retain the verified native ID for a newer block. Old
  generations never overwrite the newer desired state or replay old grants.
- A pending, never-started CREATE can be cancelled without native IO: the
  blocking intent is `not_required` / `not_created`, not a fabricated confirmation
  of native session revocation. CREATE eligibility is rechecked at execution.
- Only strictly typed, validated observations become durable evidence. Invalid
  post-apply results retain an unknown-outcome reservation; handled read-only
  inspection failures release it without retaining exception text.
- Foreign native blocks cannot be cleared or relabelled as our own.
- Login/session/API-credential evidence is recorded separately. Missing evidence
  is `partial`, not success. Native exceptions and raw response bodies never
  become durable error text; only bounded codes are stored.

`NativeAdapter` is a protocol, not a production implementation. In particular,
Synapse's user `PUT` upsert is not create-only and MinIO IAM disable does not
prove OIDC STS revocation. The allowed native targets are GitLab, Matrix and
MinIO only. No native capability is accepted by these tests.

## Verification

Use the isolated settings and dependency installation described in Auth's
README:

```sh
DJANGO_SETTINGS_MODULE=auth.test_settings python manage.py test user_admin
DJANGO_SETTINGS_MODULE=auth.test_settings python manage.py test
DJANGO_SETTINGS_MODULE=auth.test_settings python manage.py makemigrations --check --dry-run
black --check user_admin
```

Tests use an ephemeral SQLite DB and fake native adapter, not production URLs,
passwords, tokens or real service accounts. They cover idempotency, transaction
rollback, stale generations, revocation in flight, missing ownership, foreign
blocks, unsupported create-only semantics, reservation retention, secret
redaction and preservation of existing Auth data.

The complete 353-test Auth suite passed without skips on an isolated local
PostgreSQL 17.9 fixture; SQLite ran 353 tests with 13 PostgreSQL-only skips. Real
multi-connection checks cover last-administrator removal, optimistic conflicts,
credential issuance/revocation races, native create single-winner behavior and
absence of DB locks during remote IO. Migration drift check passed. Legacy
password routes retain password-only saves and Django's unusable-password branch;
empty-password session login after disabling passwords is rejected. Use `auth.test_postgres_settings` only in its documented isolated
loopback/container fixture; never point this suite at production.

These fake-native tests do **not** establish vendor API semantics, actual process
crash recovery or vendor-native token/session revocation. Those remain explicit
acceptance gates before any native executor is enabled. Central last-admin and
Auth credential-epoch safeguards have separate API/PostgreSQL tests.

## Exact-version MinIO fixture boundary

An independently authorized read-only export supplied the immutable pinned MinIO
image; every blob and the exact binary version were verified. The separate local
fixture uses new run-scoped containers, tmpfs synthetic credentials/data and a
network-none shared loopback, with no host ports or production mounts.

Own-only S3 scope, old STS/presigned GET, Console HTTP-cookie download and
self-derived service-account read/write were checked across block/enable with the
same credentials and preserved control data/policy. This is **not browser/OAuth
acceptance or full login revocation**: a valid old JWT still issues STS, Console
login issues a cookie/204, and session responds 200 while S3 is denied. Blocked
`new_login` is therefore `unsupported`; other channel evidence remains unknown.
The operator explicitly selected option 1: S3-denial-only semantics for MinIO,
without an additional native login/issuance gate. Keep this limitation visible;
it does not authorize production credentials/resources, adoption, publication or
activation, nor weaken other services' criteria. No new admin Allow was introduced.
GitLab and Synapse have their own partial exact-image acceptance below.
The separate worker has no accepted executable profile; Auth web never executes
native work.

See `vendor_fixtures/README.md` for helper setup, strict proof/timeout cleanup and
limits, and the parent native-gates document for the accepted scope and remaining gates.

## Exact-version Synapse fixture boundary

The separately approved immutable image export verified every blob and actual
Synapse 1.164.1 version. A new four-container loopback-only tmpfs fixture exercised
the real adapter CREATE/BIND/lock/unlock. Password login and original-token sync
return `M_USER_LOCKED` while locked; the same originals work after unlock. Original
devices/profiles/room membership/messages and genuinely signed public device keys
are preserved, and the control user continues working. This is server-side key
storage preservation, not encrypted-chat or browser/OIDC acceptance.

Refresh returns 200 while locked, but its replacement access token still cannot
sync. The operator separately and explicitly accepted this native Matrix lock
behavior without destroying sessions/keys; it is not inferred from MinIO consent.
Keep issuance and access denial separate; no worker activation, publication or
relaxation of remaining service criteria is implied. Source recheck
closed the fixture's post-unlock membership coverage finding. Every owned container
was checked absent; native credentials/bodies never became durable evidence.

## Initial real-browser Matrix and MinIO provisioning

Separate fresh fixtures now exercise actual Auth code flows for both providers.
Matrix uses exact Synapse with PKCE `always`, no existing-user adoption and real
Chromium login-token exchange, matching precreated MXIDs, `whoami` and `sync`.
Unbound Auth issuance is denied; both newly bound subjects can log in. Eleven
owned containers were checked absent; Astra accepted this narrow first-login scope.

MinIO uses the unchanged real legacy state guard and named PKCE exception. Canonical
hostnames resolve only to owned loopback through fresh read-only container hosts
files; no host DNS/sysctl/security settings change. Chromium clicks the actual
Console UI, then uses real Auth and Console callbacks. Real ID tokens are verified
in memory against the public issuer key and exact subject/policy. Only the own
bucket is listed, its canary matches, and foreign-bucket reads return 403. Missing
cookie, independently initialized wrong-browser cookie and consumed replay are
rejected without extra token exchanges. Thirteen owned containers were checked
absent; Astra accepted the bounded initial provisioning/browser slice.

Native outcomes remain PARTIAL/unknown, not upgraded by browser success. Console
upload, full negative nonce/PKCE/callback coverage and external revocation are not
claimed. Independent B's first login is not preservation of an old native session.
All worker acceptance blockers remain sealed; this is not production activation.

## Exact-version GitLab fixture boundary

The pinned self-managed GitLab 18.1.0 CE image passed real candidate
CREATE/BIND/ban/unban, password login, frozen original HTTP-cookie private README,
PAT, strict-host-key SSH and HTTPS Git-ref checks. Original password/PAT/keys/refs,
group memberships/access levels, control user and API-created pending/runner-claimed
running CI jobs plus active schedules were preserved. Completion of the real
`AntiAbuse::BanDuplicateUsersWorker` was observed with the exact email-subaddress
restriction explicitly false. This does not claim actual CI-script execution.

A banned cookie can still return 200 from identity introspection, while the same
cookie gets 404/no original bytes for the private README. After unban that original
cookie returned 401; no restoration or permanent revocation of all sessions is
claimed. Same password/PAT/SSH keys work again. Actual browser/OIDC remains gated.
All twelve owned containers of that native-channel fixture, including immutable-source
helpers, were registered before launch and checked absent. Timeout/interruption cleanup regressions and
independent Astra closure passed. No privileged mode, host ports, writable host
cgroups or host kernel changes were used.

## Separate real-browser GitLab slice

A new isolated fixture additionally exercised actual Chromium → real Django Auth
→ exact GitLab authorization-code redirects with strict TLS, PKCE/nonce configured,
central CREATE provenance and real engine BIND publication. Unbound identity was
denied; after BIND both browser identities matched the created native IDs. Central
grant revocation denied fresh OIDC before native ban; the control browser session
survived, and regrant/unban restored fresh login to the same native identity.
The expanded run also checked a provenance-owned private README: central grant
removal alone left native data accessible; native ban denied the original browser
session's data while preserving the control user's access. Fresh login after
regrant and after reactivation restored the same native ID and original data.
Deactivation advanced the central epoch and removed previously issued OAuth
credentials. Before its first post-reactivation Auth request, an untouched old
session retained its **identical original cookie**, yet received explicit boolean
`authenticated: false`. Cookie values stayed in memory only. The control Auth
session remained authenticated. All twenty-one owned containers were checked absent.
Astra closed the stale-cookie oracle finding after five negative Node oracle tests
and a fresh real-browser run; the full Auth suite and migration-drift check passed.

This remains a **partial browser slice**: the banned identity endpoint returned
200, so it is not an introspection/session-revocation guarantee. Data denial can
also be a verified redirect to the real native sign-in page, not an arbitrary
HTTP 200. Negative callback/state/nonce/PKCE cases remain untested by the GitLab slice;
separate initial Synapse/MinIO browser slices are described above. Deployment and
activation acceptance is not implied.

The operator explicitly allowed `--no-sandbox` only for the disposable browser,
retaining container isolation, nonroot/read-only/drop-ALL/no-new-privileges and
resource bounds. Host security/packages were not changed. A fresh private NSS CA
store passed trusted TLS and rejected an untrusted certificate; no HTTPS-ignore
flag or fabricated network response was used. Native worker profiles remain sealed.
See `vendor_fixtures/README.md` for the separate foundation and limitations.

## Central API contract

The bearer-only `/api/user-admin/` namespace exposes capabilities, paginated users,
create, versioned profile/role/service PATCH, deactivate/reactivate and change
status. There is no delete endpoint. `is_admin` projects `is_superuser`; no public
`is_staff` editor exists. Mutations use UUID idempotency keys and strong ETags.
Self-lockout, last-admin removal and ambiguous service-group aliases fail closed.
Legacy native identities remain unmanaged; no adoption implementation exists and
matching username/email never establishes ownership. Native intents and central changes commit atomically, but no
remote work is executed by the web request.

Deactivation advances the credential epoch and removes central OAuth credentials.
JWT/refresh/session/OIDC paths bind to the original password-event proof, so
reactivation cannot revive pre-deactivation credentials. Legacy password routes
serialize and revalidate the actor before password-only persistence; the Django
admin cannot hard-delete users. These source changes are not deployment approval.
