"""Explicit, atomic provisioning. Never discover users or print private input."""

import json
import re
import sys

import bcrypt
from pathlib import Path
from urllib.parse import urlsplit

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction
from django.utils.crypto import salted_hmac
from oauth2_provider.models import get_application_model

from sso.models import ProvisionRun, Service, ServiceIdentity


class Conflict(Exception):
    pass


def require(condition):
    if not condition:
        raise Conflict()


def fields(value, required, optional=()):
    require(
        isinstance(value, dict)
        and set(required) <= value.keys()
        and not value.keys() - set(required) - set(optional)
    )


def bootstrap_fingerprint(config):
    fields(config, ["users", "services", "identities"])
    require(all(isinstance(config[k], list) for k in config))
    canonical = {}
    for section, excluded in [
        ("users", {"import_bcrypt", "unusable_password"}),
        ("services", set()),
        ("identities", {"minio_policy", "jenkins_admin"}),
    ]:
        rows = []
        for row in config[section]:
            require(isinstance(row, dict))
            row = {key: value for key, value in row.items() if key not in excluded}
            if section == "services" and "client" in row:
                require(isinstance(row["client"], dict))
                row["client"] = {
                    key: value
                    for key, value in row["client"].items()
                    if key != "secret"
                }
                if isinstance(row["client"].get("redirect_uris"), list):
                    row["client"]["redirect_uris"] = sorted(
                        row["client"]["redirect_uris"]
                    )
            rows.append(row)
        canonical[section] = sorted(
            rows, key=lambda row: json.dumps(row, sort_keys=True)
        )
    return salted_hmac(
        "sso.bootstrap", json.dumps(canonical, sort_keys=True)
    ).hexdigest()


class Command(BaseCommand):
    help = (
        "Validate private SSO JSON (dry-run by default); --apply persists atomically."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--config", required=True, help="Private JSON file or - for stdin"
        )
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args, **options):
        try:
            raw = (
                sys.stdin.read()
                if options["config"] == "-"
                else Path(options["config"]).read_text()
            )
            config = json.loads(raw)
            with transaction.atomic():
                fingerprint = bootstrap_fingerprint(config)
                run = ProvisionRun.objects.select_for_update().first()
                # One immutable bootstrap manifest. Changed bindings need an operator migration,
                # not a new bootstrap that could recreate intentionally deleted objects.
                require(run is None or run.fingerprint == fingerprint)
                created = self.provision(config, run)
                if run is None:
                    ProvisionRun.objects.create(
                        fingerprint=fingerprint, created_ids=created
                    )
                if not options["apply"]:
                    transaction.set_rollback(True)
        except (Conflict, ValueError, TypeError, KeyError, IntegrityError, OSError):
            raise CommandError(
                "Invalid or conflicting SSO configuration; transaction rolled back (private details suppressed)."
            ) from None
        self.stdout.write(
            "Applied atomically."
            if options["apply"]
            else "Dry-run valid; no changes persisted."
        )

    def provision(self, config, run):
        fields(config, ["users", "services", "identities"])
        require(all(isinstance(config[k], list) for k in config))
        created = {
            "users": [],
            "groups": [],
            "services": [],
            "applications": [],
            "identities": [],
            "memberships": [],
            "password_imports": {},
        }
        bindings = {
            key: {}
            for key in ["users", "groups", "services", "applications", "identities"]
        }
        previous = run.created_ids.get("bindings", {}) if run else {}

        def remember(kind, name, obj):
            require(obj is not None)
            if run:
                require(previous.get(kind, {}).get(name) == obj.pk)
            bindings[kind][name] = obj.pk

        User = get_user_model()
        users = {}
        for row in config["users"]:
            fields(row, ["username"], ["id", "import_bcrypt", "unusable_password"])
            name = row["username"]
            require(name not in users)
            if "id" in row:
                require(
                    (row["id"], name) in {(1, "i3alumba"), (2, "gore")}
                    and set(row) == {"id", "username"}
                )
                user = User.objects.filter(pk=row["id"], username=name).first()
                require(user is not None)
            else:
                require(name == "procsima")
                require(
                    (run is not None and set(row) == {"username"})
                    or set(row) == {"username", "import_bcrypt"}
                    or (
                        set(row) == {"username", "unusable_password"}
                        and row["unusable_password"] is True
                    )
                )
                imported = row.get("import_bcrypt")
                if "import_bcrypt" in row:
                    require(
                        isinstance(imported, str)
                        and re.fullmatch(r"\$2a\$13\$[./A-Za-z0-9]{53}", imported)
                        is not None
                    )
                    # Reject a syntactically shaped but unsupported bcrypt salt before storing it.
                    bcrypt.hashpw(b"sso-compatibility-probe", imported.encode("ascii"))
                user = User.objects.filter(username=name).first()
                if user:
                    # Provenance is the original transaction, not a matching mutable password.
                    require(
                        run is not None and user.pk in run.created_ids.get("users", [])
                    )
                    if "import_bcrypt" in row or "unusable_password" in row:
                        require(
                            run.created_ids.get("password_imports", {}).get(
                                str(user.pk)
                            )
                            == salted_hmac(
                                "sso.password_import", imported or "unusable"
                            ).hexdigest()
                        )
                else:
                    require(run is None)
                    user = User(username=name)
                    if imported:
                        user.password = "bcrypt$" + imported
                    else:
                        user.set_unusable_password()
                    user.save()
                    require(user.pk > 2)
                    created["users"].append(user.pk)
                    created["password_imports"][str(user.pk)] = salted_hmac(
                        "sso.password_import", imported or "unusable"
                    ).hexdigest()
            remember("users", name, user)
            users[name] = user
        services = {}
        Application = get_application_model()
        for row in config["services"]:
            fields(row, ["slug", "group"], ["client"])
            slug = row["slug"]
            require(slug in Service.Slug.values and slug not in services)
            group_row = row["group"]
            fields(group_row, ["name"], ["id", "create"])
            if "id" in group_row:
                require(set(group_row) == {"id", "name"})
                group = Group.objects.filter(
                    pk=group_row["id"], name=group_row["name"]
                ).first()
                require(group is not None)
            else:
                require(group_row.get("create") is True and slug == "jenkins")
                group = Group.objects.filter(name=group_row["name"]).first()
                require(group is not None or run is None)
                new = group is None
                if new:
                    group = Group.objects.create(name=group_row["name"])
                if new:
                    created["groups"].append(group.pk)
            legacy = {
                "drive": (2, "Drive"),
                "minio": (3, "Minio"),
                "gitlab": (4, "Gitlab"),
                "matrix": (5, "Matrix"),
            }
            if slug in legacy:
                require((group.pk, group.name) == legacy[slug])
            remember("groups", slug, group)
            client_id = None
            if "client" in row:
                client_row = row["client"]
                fields(client_row, ["id", "secret", "redirect_uris"])
                client_id, secret, redirects = (
                    client_row["id"],
                    client_row["secret"],
                    client_row["redirect_uris"],
                )
                require(
                    isinstance(client_id, str)
                    and 0 < len(client_id) <= 100
                    and isinstance(secret, str)
                    and len(secret) >= 32
                )
                require(
                    isinstance(redirects, list)
                    and bool(redirects)
                    and len(set(redirects)) == len(redirects)
                )
                for uri in redirects:
                    require(isinstance(uri, str))
                    parsed = urlsplit(uri)
                    require(
                        parsed.scheme == "https"
                        and bool(parsed.hostname)
                        and not parsed.username
                        and not parsed.fragment
                        and not any(c.isspace() for c in uri)
                        and "*" not in uri
                    )
                for other in Application.objects.exclude(client_id=client_id):
                    require(
                        not set(redirects).intersection(other.redirect_uris.split())
                    )
                app = Application.objects.filter(client_id=client_id).first()
                expected = {
                    "client_type": "confidential",
                    "authorization_grant_type": "authorization-code",
                    "algorithm": "RS256",
                    "skip_authorization": True,
                    "hash_client_secret": True,
                }
                if app:
                    require(
                        check_password(secret, app.client_secret)
                        and set(app.redirect_uris.split()) == set(redirects)
                    )
                    require(
                        all(
                            getattr(app, key) == value
                            for key, value in expected.items()
                        )
                    )
                else:
                    require(run is None)
                    app = Application.objects.create(
                        client_id=client_id,
                        client_secret=make_password(secret),
                        name=f"Common Auth {slug}",
                        redirect_uris=" ".join(redirects),
                        **expected,
                    )
                    created["applications"].append(app.pk)
                remember("applications", client_id, app)
            service = Service.objects.filter(slug=slug).first()
            if service:
                require(
                    service.group_id == group.pk and service.oidc_client_id == client_id
                )
            else:
                require(run is None)
                service = Service.objects.create(
                    slug=slug, group=group, oidc_client_id=client_id
                )
                created["services"].append(service.pk)
            remember("services", slug, service)
            services[slug] = service
        seen = set()
        for row in config["identities"]:
            fields(
                row,
                ["username", "service", "external_id", "external_username"],
                ["minio_policy", "jenkins_admin"],
            )
            name, slug = row["username"], row["service"]
            require(name in users and slug in services and (name, slug) not in seen)
            seen.add((name, slug))
            require(
                all(
                    isinstance(row[k], str) and 0 < len(row[k]) <= 255
                    for k in ["external_id", "external_username"]
                )
            )
            require(isinstance(row.get("jenkins_admin", False), bool))
            require(
                isinstance(row.get("minio_policy", ""), str)
                and len(row.get("minio_policy", "")) <= 255
            )
            require(slug == "minio" or not row.get("minio_policy"))
            require(slug == "jenkins" or not row.get("jenkins_admin"))
            if slug == "jenkins" and name == "i3alumba":
                require(row["external_username"] == "i3alumba")
            user, service = users[name], services[slug]
            values = {
                key: row.get(key, default)
                for key, default in [
                    ("external_id", ""),
                    ("external_username", ""),
                    ("minio_policy", ""),
                    ("jenkins_admin", False),
                ]
            }
            identity = ServiceIdentity.objects.filter(
                user=user, service=service
            ).first()
            if identity:
                require(
                    all(
                        getattr(identity, key) == values[key]
                        for key in (
                            ["external_id", "external_username"] if run else values
                        )
                    )
                )
            else:
                require(run is None)
                identity = ServiceIdentity.objects.create(
                    user=user, service=service, **values
                )
                created["identities"].append(identity.pk)
            remember("identities", name + ":" + slug, identity)
            if run is None and not user.groups.filter(pk=service.group_id).exists():
                user.groups.add(service.group)
                created["memberships"].append([user.pk, service.group_id])
        created["bindings"] = bindings
        return created
