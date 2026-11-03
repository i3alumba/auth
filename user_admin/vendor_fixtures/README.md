# Explicit isolated vendor fixtures

These helpers are never imported by web/worker startup and never export production
images. They are **not** a worker, activation mechanism or full vendor acceptance.
The host orchestration is an explicitly run local acceptance procedure, not an
application service or a production deployment manifest.

## MinIO prerequisites and safety

- Trusted immutable MinIO `RELEASE.2023-05-18T00-05-36Z` image; the accepted local
  artifact uses manifest
  `sha256:1bafa2f68bad591fc47a0efce28da9345983ba23fc2b90e4e5a6917cb133aa53`.
  Verify every descriptor/blob and `/opt/bin/minio --version`; do not rebuild or
  replace this vendor image with another release or an untrusted mirror.
- Linux Docker, Python and OpenSSL for host orchestration. The Python test-runtime
  image needs Auth's existing dependencies, including Django, PyJWT/cryptography.
  Use Auth's existing Docker/dependency setup; no new runtime SDK is required.
- Create only new UUID-labelled local containers. The namespace holder uses
  `--network none`; all helpers/vendor containers share only its loopback via
  `--network container:<own-holder>`. Never publish host ports or join a production
  namespace. Use non-root UID, read-only root, dropped capabilities,
  `no-new-privileges`, resource bounds and `--log-driver none`.
- All vendor data and generated secrets live on tmpfs. Mount Auth source read-only
  at `/workspace`, and a new private `/dev/shm` runtime directory read-only at
  `/fixture`. Never mount production data, env, credentials, PVCs or writable layers.
- `/fixture/marker` contains exactly `PUBLIC_PAGE_SYNTHETIC_FIXTURE_V1`.
  Synthetic files are `root-user`, `root-password`, `oidc-secret`,
  `tls/private.key`, `tls/public.crt` and `tls/CAs/fixture.crt`.
  Use private directory/key permissions, verified TLS with `localhost` SAN, and
  credentials generated only for this run. Load credentials from files into the
  vendor process, not Docker argv or persisted container-config environment.

`oidc.py` serves only synthetic discovery/JWKS over verified HTTPS on loopback 19445. It has no authorize/token/userinfo API and does not prove an OAuth browser
flow. Start it explicitly with `python -B -m user_admin.vendor_fixtures.oidc /fixture`.
Configure the new MinIO fixture with that issuer, claim `policy`, client
`synthetic-client`, HTTPS S3 on loopback 9443 and Console on 9444. A redirect URI of
`https://localhost:9444/oauth_callback` is fixture-only, not a production change.

After both local services are healthy, run the probe in the **same own isolated
namespace**, with the mounts/security controls above:

```sh
DJANGO_SETTINGS_MODULE=auth.test_settings \
  python -B -m user_admin.vendor_fixtures.minio_probe /fixture
```

The probe hard-codes only these local origins. It uses synthetic subjects, two new
UUID buckets/individual policies, ephemeral STS, cookies and self-derived service
accounts. Native bodies, credentials, cookies and signed URLs remain in memory;
only bounded status/boolean/hash evidence is emitted. The Console path is actual
HTTP cookie authorization, **not** a browser or OAuth redirect/callback test.

## Evidence and cleanup

`runner.py` provides host-side lifecycle primitives:

- `FixtureContainers` accepts only `minio` (default), `synapse` or `gitlab` as
  its explicit service namespace; names/labels cannot be injected or shared.
- `FixtureContainers.launch` reserves every unique run-scoped name **before**
  invoking Docker, including health/probe helpers and timeout paths.
- `cleanup` filters exact planned names plus the full run label, validates
  immutable IDs, removes only those IDs, continues after failures and checks
  absence. Never use prune, broad name/prefix deletion or unrelated containers.
  A killed host or unavailable daemon still requires operator recovery from the
  saved exact run names/labels; a timeout is never green evidence.
- Initialize a new-run false proof **before bootstrap**. `checked_probe` requires
  a dictionary, `ok is True` and zero process exit. Replace evidence atomically;
  publish success only after all planned containers are checked absent. Remove
  only the run's own tmpfs directory after stopping its containers.

Observed exact-version result: own-only S3 access/listing; foreign bucket and
admin-info denial; old STS/presigned GET, original Console cookie downloads and
original service-account read/write denied while blocked; enable restores their
original data, preserving the control user/policy.

**Not full login revocation:** while policy-blocked, a valid old OIDC JWT still
obtains STS, Console login returns 204 with a cookie, and `/api/v1/session` returns 200. The adapter reports blocked `new_login=unsupported`. Data denial and credential
issuance are separate facts. The operator explicitly selected option 1:
S3-denial-only blocking for newly managed MinIO accounts, without a full native
login/issuance gate. Preserve the unsupported login evidence; this consent is not
production activation, credentials, resource creation or publication authority.
Complete S3/admin API coverage, browser/OAuth and crash recovery are not claimed.

## Exact Synapse 1.164.1 fixture

Use only the verified pinned image
`sha256:ba2859095a5e592ba229b55381aceb23fd7152456eed1573143dfaef0ab11b7e`.
The same safety constraints apply, with service namespace `synapse`, loopback
HTTPS18448, four new owned containers and no production mounts/ports/credentials.
Generate a separate tmpfs runtime with the marker, TLS files, `registration-secret`,
`admin-password`, signing key and explicit homeserver/logging configuration.
Run the vendor with `python -B -m synapse.app.homeserver --config-path
/fixture/homeserver.yaml`; use only client listener, SQLite/tmpfs storage, disabled
federation domain whitelist, stats disabled and a NullHandler log configuration.
No configured OIDC provider is needed to test external-ID storage, but that does
**not** establish a usable SSO redirect/callback path.

Run `python -B -m user_admin.vendor_fixtures.synapse_probe /fixture` in the same
owned network namespace using Auth test settings/source and verified fixture CA.
The probe retains only its own UUID-localpart CREATE passwords in memory; it never
logs bodies or reads a production password. Distinct nonrefreshable and refresh
sessions avoid confusing legitimate refresh rotation with lost original tokens.
It compares original-token/password access, device/profile state, membership and
messages, and genuinely signed public device keys before/during/after lock.
Control-user access and its message during lock are checked independently.

Actual result: correct-password login and original-token sync fail with
`M_USER_LOCKED`; after unlock the same originals work and stored state is preserved.
**Refresh still returns 200 while locked**, but its replacement token cannot sync.
The operator separately accepted this native Matrix lock/refresh behavior, without
destroying sessions or keys; remaining activation/release gates stay closed.
This is explicit Matrix consent, not inherited MinIO scope. Browser/OIDC, encrypted-chat
decryption, federation, all exemptions and crash recovery are not claimed. Do not
call logout-all, deactivate, delete devices or reset preserved credentials.

## Exact GitLab 18.1.0 CE fixture

Use only `sha256:a68f3b3f27db3e5894784301714ecfadf03cf739f06420a741b349b38c0bdda0`.
The twelve-container owned lifecycle includes both immutable startup-source readers;
register all names before Docker and protect setup failures before vendor bootstrap.
An outer cleanup guard runs before private tmpfs disposal. The fixture uses shared
loopback HTTPS19443/SSH19022, no host ports, no privileged mode and an aggregate
memory cap of 6,000,000,000 decimal bytes, without swap.

Omnibus requires a writable fixture root and executable helper tmpfs on
`/var/opt/gitlab`, `/tmp` and `/run`; retain nosuid/nodev. Replace only the exact
installed startup sysctl echo with a no-op in an own readonly bind and disable
package kernel changes. Never make host cgroups writable or alter the kernel.
Fixture-only Rails bootstrap and password seeding address only confirmed new owned
synthetic users, never production adapters, original accounts or native passwords.
Synthetic secrets/data/config/logs stay on tmpfs; TLS and SSH host keys are verified.

`gitlab_probe.py`, `gitlab_cookie.py` and ordered `gitlab_host.py` phases exercise
real CREATE/BIND/ban/unban, password/original frozen-cookie private README, PAT,
SSH/HTTPS refs, groups and control user. Compare Git ref IDs after intentional CI
commits, not variable transport capabilities. Preserve pending jobs, a runner-claimed
running job and active schedules; observe duplicate-user-worker completion with
`enforce_email_subaddress_restrictions=false`. CI script execution is not tested.

A banned original cookie returns identity HTTP200 but private README404/no original
bytes; fresh password admission is denied. After unban the old cookie returns401,
while original password/PAT/SSH keys and refs work. Do not claim cookie restoration,
permanent/full credential revocation, actual browser/OIDC or production acceptance.
Final run checked all twelve owned containers absent. Astra closed the source-reader
timeout/interruption lifecycle finding after regression tests and a fresh full run.

## Separate real Auth/browser GitLab fixture

The isolated browser fixture uses the real Django IdP, fresh PostgreSQL and RSA
issuer, exact pinned GitLab, and Chromium over verified loopback HTTPS. It tests
CREATE/BIND ownership, unbound denial, confirmed native IDs, central grant denial
before native ban, private README denial through the existing native browser
session, control preservation and same-ID/data restoration. Deactivation removes
previously issued OAuth credentials and advances the epoch. An untouched old Auth
session must retain its identical original cookie immediately before its first
post-reactivation request and return explicit boolean `authenticated: false`.
Fresh login and the independent control Auth session must still work. Cookie values
are compared only in memory, never logged, hashed or included in evidence.

`browser_session_assertions.mjs` fails closed for missing/changed cookies and
malformed authentication responses; five negative oracle tests run with:

```sh
node --test user_admin/test_browser_session_assertions.mjs
```

Astra closed the stale-cookie P1 after a fresh expanded run; all 21 owned containers
were checked absent. A native denial may be 401/403/404 or a verified redirect from
the private resource to the same-origin real sign-in page with original data absent.
An identity endpoint's HTTP 200 is not session-revocation proof. Finished contexts
are closed before another login to retain PID/memory bounds; redundant password
work is avoided without disabling the production five-attempt/15-minute limiter.
The operator's no-sandbox exception applies only to this disposable Chromium;
strict TLS and nonroot/read-only/drop-ALL/no-new-privileges isolation remain.

This is still a partial slice: negative callback/state/nonce/PKCE cases,
credential delivery and deployment/activation acceptance remain outstanding.
Separate initial Synapse/MinIO browser flows below now passed. Worker profile
blockers are unchanged.

## Initial Matrix and MinIO browser provisioning

`matrix_browser_oidc.mjs` uses the real Auth and exact Synapse provider with PKCE
`always`, no existing-user adoption, central CREATE/BIND and precreated MXIDs.
Unbound issuance is denied; actual browser login-token exchange, `whoami` and
`sync` pass for two independent new users. All eleven owned containers were checked
absent. This does not prove preservation of an older native session.

`minio_browser_settings.py` and `minio_browser_router.py` exercise the **unchanged**
legacy guard using canonical names resolved exclusively to own loopback. Every
participant receives a fresh read-only hosts file, never host DNS changes. Router
startup requires both names resolve only to 127.0.0.1 and unprivileged loopback443
binding; failure means stop, not privilege/sysctl changes. Only fixed verified-TLS
Auth/Console upstreams exist; private S3 is never a public router destination.
Request/response/concurrency/deadline limits and separate Set-Cookie forwarding
are tested. Measured exact-release public assets fit the 16 MiB response ceiling.

Real Console UI first opens Other Authentication Methods, then the Fixture Auth
menu item. Unbound Auth denial precedes BIND. Bound browser sessions list only their
own bucket, read the matching seeded canary and receive 403 for the other bucket.
An in-memory observer verifies actual issuer ID-token signature/issuer/audience/
subject/policy against the public key and expected own mappings, emitting only
counters. Actual callback attempts without a guard cookie, with an independently
initialized browser cookie and after consumption fail without extra token exchanges;
the original request continues unchanged. All thirteen owned containers were checked
absent; Astra accepted this narrow initial provisioning/browser scope.

This is not synthetic JWT/native-credential Console login. No cookies or responses
are injected. Token/code/state/secret bytes are never logged. Console upload, full
nonce/PKCE negative coverage and native revocation are not claimed. Both adapters'
observations stay PARTIAL/unknown; browser success does not rewrite capability
channels or open worker acceptance gates.

The router module is an **internal fixture executable**, not a deployable proxy.
Inside the owned network-none namespace only, reuse the Auth QA image and run
`python -B -m user_admin.vendor_fixtures.minio_browser_router` with read-only
`/workspace` source and `/fixture-router` marker/run ID, fresh TLS/CA, issuer
**public** key and expected subject/policy metadata. It binds only loopback443,
accepts no configurable upstream/host/port flags and stops on invalid prerequisites.
Never mount the issuer private key, RP secret or native root credentials into it.
The explicit parent fixture owns launch limits and exact-ID cleanup before tmpfs
disposal; it is not a production launch command.

## No-network helper tests

```sh
DJANGO_SETTINGS_MODULE=auth.test_settings python -B manage.py test \
  user_admin.test_native_minio user_admin.test_native_policy \
  user_admin.test_vendor_fixtures user_admin.test_fixture_runner \
  user_admin.test_console_fixture user_admin.test_synapse_fixture \
  user_admin.test_gitlab_fixture user_admin.test_gitlab_cookie_fixture \
  user_admin.test_gitlab_host_fixture
```

These tests include strict proof/timeout/ownership failure paths and a frozen
presigned-GET vector independently checked against botocore 1.43.123. They do not
start Docker or native services. See the parent native-gates document for the
remaining browser/OIDC, credential delivery, deployment-protocol and release
approval boundaries. Completed immutable exports must not be repeated.
