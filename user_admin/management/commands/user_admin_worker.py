"""Explicit, default-read-only outbox worker; never invoked by web startup."""

import json
import math
import signal
import threading
from uuid import UUID

from django.core.management.base import BaseCommand, CommandError

from ...worker_config import WorkerError, load_config, load_private_snapshot
from ...worker_runtime import admission, run_pass


class Command(BaseCommand):
    help = "Preview existing native intents; execution requires dedicated settings and cleared profile gates."
    requires_system_checks = []

    def add_arguments(self, parser):
        parser.add_argument(
            "--config",
            required=True,
            help="Absolute path to a nonsecret JSON configuration.",
        )
        mode = parser.add_mutually_exclusive_group()
        mode.add_argument(
            "--dry-run",
            action="store_true",
            help="Default: no credentials, adapters, native requests or DB writes.",
        )
        mode.add_argument(
            "--execute",
            action="store_true",
            help="Explicit execution; not sufficient to clear acceptance gates.",
        )
        lifecycle = parser.add_mutually_exclusive_group()
        lifecycle.add_argument(
            "--once", action="store_true", help="Default: one bounded queue pass."
        )
        lifecycle.add_argument(
            "--watch",
            action="store_true",
            help="Poll bounded passes until SIGTERM/SIGINT.",
        )
        parser.add_argument(
            "--operation",
            type=UUID,
            help="Exactly this existing eligible operation; never its continuation.",
        )
        parser.add_argument("--batch-size", type=int, default=20)
        parser.add_argument("--interval", type=float, default=5)

    def handle(self, *args, **options):
        if (
            not 1 <= options["batch_size"] <= 100
            or not math.isfinite(options["interval"])
            or not 1 <= options["interval"] <= 60
            or (options["operation"] is not None and options["watch"])
        ):
            raise CommandError("invalid_worker_options", returncode=2)
        stopping = threading.Event()
        previous = {}
        try:
            config = load_config(options["config"])
            dry_run = not options["execute"]
            snapshot = None
            if not dry_run:
                admission(config)  # Before any private credential contents.
                snapshot = load_private_snapshot(config)
            self.stdout.write(
                json.dumps(
                    {
                        "mode": "dry_run" if dry_run else "execute",
                        "credentials": "unchecked" if dry_run else "snapshot_loaded",
                        "activation": "profile_gated",
                        "execution_scope": config.execution_scope,
                        "native_connectivity_certified": False,
                    }
                )
            )
            for signum in [signal.SIGTERM, signal.SIGINT]:
                previous[signum] = signal.signal(
                    signum, lambda signum, frame: stopping.set()
                )
            cursor = None
            incomplete = False
            while not stopping.is_set():
                cursor, processed, partial = run_pass(
                    config,
                    limit=options["batch_size"],
                    cursor=cursor,
                    operation_id=options["operation"],
                    dry_run=dry_run,
                    snapshot=snapshot,
                    stopping=stopping.is_set,
                    report=lambda event: self.stdout.write(
                        json.dumps(event, sort_keys=True)
                    ),
                )
                incomplete |= partial
                if options["operation"] is not None and not processed:
                    self.stdout.write('{"status":"operation_not_eligible"}')
                    incomplete = True
                if not options["watch"]:
                    break
                stopping.wait(options["interval"])
            if incomplete and not dry_run:
                raise CommandError("worker_incomplete", returncode=3)
        except WorkerError as error:
            raise CommandError(error.code, returncode=2) from None
        except CommandError:
            raise
        except Exception:
            # Never print exception strings, native responses or credentials.
            # A failed/crashed engine claim keeps its durable reservation.
            raise CommandError("worker_runtime_failed", returncode=2) from None
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
