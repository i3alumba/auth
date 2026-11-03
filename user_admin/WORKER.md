# Default-disabled native worker

This is an internal Django management command, not another HTTP service. It
reuses Auth's image, dependencies, database/outbox and reviewed execution engine.
It does not migrate a database, discover/adopt vendor users, clear reservations,
retry ambiguous writes or manage Jenkins.

**Source preparation only. Execution is currently blocked.** Versioned
`worker_profiles.py` records exact-image fixture references and limited tested
channels. Every profile retains browser/OIDC, deployment-protocol and production
activation blockers. JSON, CLI flags and environment variables cannot clear
those blockers or manufacture confirmed observations. Do not remove gates as an
operational workaround. Native channel results can remain `partial`/`unknown`;
MinIO's blocked new-login evidence remains `unsupported`.

## MVP: initial provisioning only

`execution_scope` defaults to `provision_only`; the example sets it explicitly.
The only other accepted value is `lifecycle`. A scope restricts actions; it is
not an execution opt-in or acceptance evidence. Initial provisioning and lifecycle
have separate source-controlled blockers; clearing one cannot clear the other.
Both remain blocked pending their respective browser/deployment/activation acceptance.

Provision-only execution permits CREATE and its original deterministic BIND,
plus initial ENABLE only from that same generation's `native_enable_pending`
BIND. BIND itself can grant access; `unbound` does not mean physically locked.
Safety instead requires unpublished random credentials, no central identity and
no usable unbound SSO/policy. No external users are adopted.

BLOCK is finalized as `unsupported/revocation_deferred` without constructing an
adapter or touching the vendor. Later-generation BIND/unlock is finalized as
`unsupported/reenable_not_supported`, never guessed from an old native state.
These terminal limitations do not reserve the target or starve later CREATEs.
Existing pause/RUNNING/UNKNOWN fences take precedence; stale intents are superseded.
Central active/grant checks and generation/authority rechecks remain mandatory.

Removing access still denies fresh Auth issuance, **not existing external sessions
or credentials**. A request already dispatched across the system boundary can
finish after central revocation; retain its truthful evidence, not a promise of
compensation. Regrant may need operator attention; this MVP never unlocks a foreign
or previously blocked identity automatically. Jenkins remains excluded.

## Installation and configuration

Run from `auth/`. Install its existing dependencies as described in `../README.md`,
or build its existing multistage Dockerfile:

```sh
docker build -t user-admin-auth-local .
```

Use `examples/worker.json` as a **nonsecret** example. Replace `.invalid` origins
only after separately verified deployment acceptance. `primary` must match the
existing target instance. Configuration is strict JSON, at most 64 KiB/eight
instances: no duplicate/unknown keys, literal credentials, imports, custom headers,
actions, evidence or execution bypasses. Origins must be fixed verified HTTPS,
without credentials, path prefixes, queries or fragments. No insecure TLS/proxy
mode is available.

`private_root` must be an absolute, privately owned directory (0700); each named
credential is a regular, owner/root-owned private file (0600/0400), at most 16 KiB.
Names are basenames below that root. Symlinks, hardlinks, unsafe writable parents,
FIFOs and path traversal are refused using descriptor-relative opens. An optional
`ca_file` is a private PEM file below the same root, at most 64 KiB. Trusted root
sticky ancestors such as `/dev/shm` are allowed, but the private root itself must
remain private. Native tokens are never CLI/environment arguments.

Required file fields:

| Service | Credentials                              | Additional configuration                          |
| ------- | ---------------------------------------- | ------------------------------------------------- |
| GitLab  | `token_file`                             | none                                              |
| Matrix  | `token_file`, `registration_secret_file` | `server_name`                                     |
| MinIO   | `access_key_file`, `secret_key_file`     | reviewed claim-only/exclusive/standalone protocol |

An executable process loads one credential snapshot; rotation requires a restart.
Preview validates directory metadata, **not credential contents or connectivity**.
Logs contain only bounded codes, operation UUIDs, service/instance and status;
never dump configuration, profiles, native responses or exception strings.

GitLab CREATE requires a freshly validated, nonempty local email with no known
case-insensitive local collision. It never fabricates an email or looks up/adopts
an existing native account. Native username is the stable, injective 29-character
`ua_` + lowercase unpadded base32 target UUID; Auth username/password are not copied
or renamed. Display name comes from the local profile. Profile fields are re-read
at validation and immediately before CREATE; no cross-system atomic uniqueness is
claimed. Invalid local prerequisites remain pending and do not starve later rows.

## Modes and flags

Run only against an explicitly configured, already migrated **isolated fixture**
database while acceptance remains closed. The command never starts migrations.

```sh
# Default: one read-only bounded preview. No native credential contents are read.
python -B manage.py user_admin_worker --settings=auth.worker_settings \
  --config=/absolute/worker.json

# Continuous preview; SIGTERM/SIGINT stop at operation boundaries.
python -B manage.py user_admin_worker --settings=auth.worker_settings \
  --config=/absolute/worker.json --dry-run --watch --batch-size=20 --interval=5

# Exactly one existing eligible operation, never an automatic continuation.
python -B manage.py user_admin_worker --settings=auth.worker_settings \
  --config=/absolute/worker.json --operation=00000000-0000-0000-0000-000000000001
```

- `--dry-run` (default) / `--execute` are mutually exclusive.
- `--once` (default) / `--watch` are mutually exclusive.
- `--operation UUID` cannot be combined with watch.
- `--batch-size`: 1–100; `--interval`: finite 1–60 seconds.
- No force, adoption, reset, reservation-expiry or mutation-retry options exist.
- Exit 0: successful preview/no-work/completed pass; 2: setup/runtime failure;
  3: executable pass with incomplete outcomes. A preview does not certify readiness.

`--execute` additionally requires exact `auth.worker_settings`, explicit
`USER_ADMIN_WORKER_ENABLED=1`, and cleared source-controlled acceptance gates.
**Today it fails before reading private credentials even with that opt-in.** Web
settings retain their hard-coded execution-off constant; worker settings disable
the administration API and expose no HTTP URLs.

For Docker, override Auth's default migration/Gunicorn command explicitly. In an
owned local fixture, use only its network-none shared-loopback namespace, readonly
configuration/private mounts and bounded resources; never host networking/ports
or production mounts:

```sh
docker run --rm --network container:OWN_FIXTURE_HOLDER \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --cpus 1 --memory 512m --memory-swap 512m --pids-limit 128 \
  --mount type=bind,src=/absolute/worker.json,dst=/config/worker.json,readonly \
  --mount type=bind,src=/absolute/private,dst=/run/user-admin-private,readonly \
  --entrypoint python user-admin-auth-local -B manage.py user_admin_worker \
  --settings=auth.worker_settings --config=/config/worker.json --dry-run --once
```

The example requires that fixture's explicit database configuration and matching
UID/file ownership; it is not a production launch recipe. Use owned-container
lifecycle registration/cleanup for automated tests, including timeout paths.

## Selection, shutdown and recovery

Only configured service/instance pairs, PENDING rows, unpaused targets and targets
without RUNNING/UNKNOWN reservations are selected, before the batch limit.
Keyset traversal advances past invalid local profiles. Only `engine.execute()`
claims/finalizes, rechecking authority, generation and grants under its locks;
no vendor IO is performed under database locks. Newly queued BIND/ENABLE phases
await a subsequent pass. Terminal/ambiguous operations are not replayed.

Graceful stop prevents further operation selections and allows the current call
and finalization to finish. Forced termination keeps durable reservations. DNS
resolution is not hard-deadline bounded. Process death or idle time never proves
quiescence; unknown outcomes need separate authoritative recovery, not a timer.

## Deployment boundary

No worker is added to `k8s/base`, no Secret is issued and no workload is started.
Auth's PostgreSQL remains its existing loopback sidecar: do **not** expose a new
DB Service, change database identity or give the web container native credentials.
Future integration must preserve private worker-only mounts and the existing DB
network boundary, and be reviewed before activation. Kubernetes projected Secret
symlinks need controlled staging of explicit keys into a new private tmpfs; do not
weaken file validation. No issuer private key is needed for this worker.

An Auth rollout restarts its PostgreSQL sidecar. Publication, private production
credential delivery, runtime/network changes and rollout require separate explicit
approval and a fresh protected backup/baseline. This command is not that approval.

## Launch preparation: synthetic staging verified, production gates open

A future worker must share the existing Auth Pod's loopback database and exact
Auth image, with an explicit management-command entrypoint, no migrations, no
HTTP endpoints and no issuer key. Do not inherit the web's complete SSO environment:
`SSO_ENABLED=false` and **both** issuer-key environment variables must be absent.
Native credentials belong only to the worker, never the web/static containers.

Projected secrets/configuration are symlinks. Pin one projection generation and
stage only explicit bounded keys into fresh UID-owned 0700 directories/0600 regular
files. Mount the private child read-only via subPath beneath safe ancestors; rotate
by restaging and restarting. Do not loosen the strict loader to accommodate symlinks.
An authorized isolated **Kubernetes** rehearsal verified nonroot UID/GID 1000
emptyDir staging and actual read-only directory/file subPaths with the real strict
loader on alpha's cached Auth image. Run `1e58e24bd90e4d78916f5f131138c969`
used only a synthetic ConfigMap, no production Secret/PVC, a deny-all network
policy and bounded hardened containers. UID-preconditioned namespace deletion
and final absence were verified. Do not repeat the completed rehearsal.

This proves only that synthetic staging path on that node/image, not real Secret
delivery, rotation, private native HTTPS or production activation. Do not compensate
for future failures with root init, global fsGroup, capabilities or ownership
changes on existing database PVCs. No production worker manifest is attached to
`k8s/base`; source-controlled execution gates remain closed.

Auth uses `Recreate`; adding a sidecar restarts PostgreSQL and reruns existing init
migration/bootstrap. A staging init can block startup and a crash-looping worker
can impair Pod readiness even without probes. Default dry-run does not make that
rollout harmless. A future opt-in launch needs a fresh protected backup, original
identity/data baseline, release approval, verified private HTTPS native API origins
and worker-only credential delivery. Do not expose admin/S3 routes publicly merely
to satisfy the worker's strict TLS transport. No new DB Service is permitted.

Stopping the worker does not undo account/bucket creation. Never delete identities,
users, buckets or data as an automatic rollback; UNKNOWN reservations remain held.
Central permission removal remains distinct from external-session revocation.

## Verification

```sh
DJANGO_SETTINGS_MODULE=auth.test_settings python -B manage.py test \
  user_admin.test_worker_config user_admin.test_worker_runtime \
  user_admin.test_worker_command user_admin.test_native_management
```

Tests cover strict parsing/filesystem attacks, zero-side-effect preview, sealed
profile gates, current GitLab profile reads, receipt wiring, eligibility/fairness,
stale/unknown reservations, shutdown boundaries, sanitized failures and unchanged
partial results. Run the complete Auth suite and migration-drift check too;
PostgreSQL concurrency coverage remains in the core's isolated test suite.
