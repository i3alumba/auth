"""Host-side lifecycle helpers for new, exclusively owned local test containers.

No production endpoints, generic Docker cleanup, environment inspection or logs.
Names are reserved before each CLI invocation so timeout cleanup includes helpers.
"""

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import NamedTemporaryFile
from typing import Callable


@dataclass
class FixtureContainers:
    run_id: str
    invoke: Callable = subprocess.run
    on_plan: Callable | None = None
    service: str = "minio"
    names: list[str] = field(default_factory=list, init=False)

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{32}", self.run_id):
            raise ValueError("invalid_fixture_run_id")
        if self.service not in {"minio", "synapse", "gitlab"}:
            raise ValueError("invalid_fixture_service")

    def launch(self, role: str, args: list[str], *, detached: bool, timeout: int):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", role):
            raise ValueError("invalid_fixture_role")
        name = "users-" + self.service + "-" + self.run_id + "-" + role
        if name in self.names:
            raise ValueError("duplicate_fixture_role")
        self.names.append(name)
        if self.on_plan is not None:
            self.on_plan(tuple(self.names))
        return self.invoke(
            [
                "docker",
                "run",
                "--name",
                name,
                "--label",
                "public-page.fixture=" + self.service + "-exact",
                "--label",
                "public-page.fixture.run=" + self.run_id,
                "--log-driver",
                "none",
                "-d" if detached else "--rm",
                *args,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def _owned_ids(self, name: str) -> list[str]:
        result = self.invoke(
            [
                "docker",
                "container",
                "ls",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                "name=^/" + name + "$",
                "--filter",
                "label=public-page.fixture.run=" + self.run_id,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        ids = result.stdout.split()
        if result.returncode or any(
            not re.fullmatch(r"[0-9a-f]{64}", cid) for cid in ids
        ):
            raise RuntimeError("fixture_ownership_lookup_failed")
        return ids

    def cleanup(self) -> dict:
        failures = []
        for name in reversed(self.names):
            try:
                for cid in self._owned_ids(name):
                    removed = self.invoke(
                        ["docker", "rm", "-f", cid],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    if removed.returncode:
                        raise RuntimeError("fixture_removal_failed")
                if self._owned_ids(name):
                    raise RuntimeError("fixture_still_present")
            except (OSError, RuntimeError, subprocess.SubprocessError):
                # One failed cleanup must not skip other exact owned names.
                failures.append(name)
        return {
            "planned_container_count": len(self.names),
            "checked_absent": not failures,
            "failures": failures,
        }


def checked_probe(stdout: str, returncode: int) -> dict:
    try:
        proof = json.loads(stdout)
    except (ValueError, TypeError):
        proof = None
    if type(proof) is not dict:
        return {"ok": False, "code": "fixture_probe_output_invalid"}
    if proof.get("ok") is not True or returncode != 0:
        proof["ok"] = False
        proof.setdefault("code", "fixture_probe_process_failed")
    return proof


def write_proof(path: Path, proof: dict) -> None:
    """Atomic secret-free evidence replacement; never append to old green proof."""
    temporary = None
    try:
        with NamedTemporaryFile(
            mode="w",
            dir=path.parent,
            prefix=path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary = Path(file.name)
            json.dump(proof, file, sort_keys=True, indent=2)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def initialize_proof(path: Path, run_id: str) -> None:
    write_proof(path, {"run": run_id, "ok": False, "stage": "initializing"})
