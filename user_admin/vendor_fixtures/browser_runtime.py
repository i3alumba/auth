"""Public readonly browser dependencies and a fixture-only resource ledger.

No launch, native credentials, production imports or sandbox changes on import.
The separate browser script must explicitly record the operator's fixture-only
no-sandbox exception; this module never enables it automatically.
"""

from dataclasses import dataclass, field
import math
from pathlib import Path
import re
import subprocess

GITLAB_FIXTURE_MEMORY_LIMIT = 6_000_000_000
PUBLIC_BINARIES = (
    Path("/opt/google/chrome/chrome"),
    Path("/usr/bin/node"),
    Path("/usr/bin/certutil"),
)
PUBLIC_LIBRARY_DIRECTORIES = (
    Path("/usr/lib/x86_64-linux-gnu"),
    Path("/usr/lib/x86_64-linux-gnu/nss"),
    Path("/usr/lib"),
    Path("/usr/lib/nss"),
)
NSS_MODULES = (
    "libsoftokn3.so",
    "libfreeblpriv3.so",
    "libfreebl3.so",
    "libnssckbi.so",
    "libnssdbm3.so",
)
PUBLIC_FONTS = (
    Path("/usr/share/fonts"),
    Path("/etc/fonts"),
    Path("/usr/share/fontconfig"),
)


@dataclass(frozen=True)
class MemoryBudget:
    """Reservations stay charged until the caller confirms owned absence."""

    limit: int = GITLAB_FIXTURE_MEMORY_LIMIT
    reservations: dict[str, int] = field(default_factory=dict, init=False)

    def __post_init__(self):
        if (
            type(self.limit) is not int
            or not 0 < self.limit <= GITLAB_FIXTURE_MEMORY_LIMIT
        ):
            raise ValueError("invalid_fixture_memory_budget")

    def reserve(self, role: str, memory: int) -> None:
        if (
            not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", role)
            or role in self.reservations
            or type(memory) is not int
            or memory <= 0
        ):
            raise ValueError("invalid_fixture_memory_reservation")
        if sum(self.reservations.values()) + memory > self.limit:
            raise ValueError("fixture_aggregate_memory_exceeded")
        self.reservations[role] = memory

    def release(self, role: str, *, checked_absent: bool) -> None:
        if checked_absent is not True or role not in self.reservations:
            raise ValueError("fixture_absence_required")
        del self.reservations[role]


def bounded_args(
    *, memory: int, uid: int, gid: int, cpus: float = 1, pids: int = 128
) -> list[str]:
    if (
        type(memory) is not int
        or not 0 < memory <= GITLAB_FIXTURE_MEMORY_LIMIT
        or type(uid) is not int
        or uid <= 0
        or type(gid) is not int
        or gid < 0
        or type(pids) is not int
        or not 1 <= pids <= 768
        or type(cpus) not in {int, float}
        or not math.isfinite(cpus)
        or not 0 < cpus <= 4
    ):
        raise ValueError("invalid_browser_fixture_limits")
    return [
        "--pull",
        "never",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        f"{uid}:{gid}",
        "--cpus",
        str(cpus),
        "--memory",
        str(memory),
        "--memory-swap",
        str(memory),
        "--pids-limit",
        str(pids),
    ]


def local_image_id(reference: str, invoke=subprocess.run) -> str:
    """Inspect cached metadata only; never pull a missing QA or vendor image."""
    if type(reference) is not str or not re.fullmatch(
        r"[a-z0-9][a-zA-Z0-9_./:@-]{0,255}", reference
    ):
        raise ValueError("invalid_fixture_image_reference")
    result = invoke(
        ["docker", "image", "inspect", reference, "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    identity = result.stdout.strip()
    if result.returncode or not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
        raise RuntimeError("fixture_local_image_required")
    return identity


def public_libraries(invoke=subprocess.run) -> dict[str, Path]:
    """Inspect only fixed public executables/modules, never homes or profiles."""
    libraries = {}
    binaries = list(PUBLIC_BINARIES)
    for name in NSS_MODULES:
        binaries.extend(
            directory / name
            for directory in PUBLIC_LIBRARY_DIRECTORIES
            if (directory / name).is_file()
        )
    for binary in binaries:
        resolved_binary = binary.resolve()
        if not str(resolved_binary).startswith(
            ("/usr/bin/", "/usr/lib/", "/lib/", "/opt/google/chrome/")
        ):
            raise RuntimeError("browser_fixture_nonpublic_binary")
        result = invoke(
            ["ldd", str(binary)], capture_output=True, text=True, timeout=20
        )
        if result.returncode or "not found" in result.stdout:
            raise RuntimeError("browser_fixture_public_dependency_missing")
        for line in result.stdout.splitlines():
            match = re.search(r"(?:=>\s*)?(/[^\s]+)", line)
            if match:
                original = Path(match.group(1))
                resolved = original.resolve()
                if not str(resolved).startswith(
                    ("/usr/lib/", "/lib/", "/opt/google/chrome/")
                ):
                    raise RuntimeError("browser_fixture_nonpublic_dependency")
                if original.name in libraries and libraries[original.name] != resolved:
                    raise RuntimeError("browser_fixture_library_collision")
                libraries[original.name] = resolved
        if binary.name.startswith("lib"):
            libraries[binary.name] = resolved_binary
            signature = binary.with_suffix(".chk")
            if signature.is_file():
                libraries[signature.name] = signature.resolve()
    libraries["ld-linux-x86-64.so.2"] = Path("/lib64/ld-linux-x86-64.so.2").resolve()
    return libraries
