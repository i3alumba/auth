"""Non-executable configuration and descriptor-validated private snapshots."""

import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .worker_profiles import PROFILES


class WorkerError(Exception):
    def __init__(self, code="invalid_worker_config"):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class InstanceConfig:
    service: str
    instance: str
    origin: str = field(repr=False)
    acceptance_profile: str
    credentials: tuple[tuple[str, str], ...] = field(repr=False)
    server_name: str = ""
    ca_file: str = ""


@dataclass(frozen=True)
class WorkerConfig:
    private_root: str = field(repr=False)
    instances: tuple[InstanceConfig, ...]
    execution_scope: str = "provision_only"


CREDENTIALS = {
    "gitlab": {"token_file"},
    "matrix": {"token_file", "registration_secret_file"},
    "minio": {"access_key_file", "secret_key_file"},
}
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}\Z")
FILENAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}\Z")


def _keys(value, required, optional=frozenset()):
    if (
        type(value) is not dict
        or not required <= value.keys()
        or value.keys() - required - optional
    ):
        raise WorkerError()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WorkerError()
        result[key] = value
    return result


def _invalid_constant(value):
    raise WorkerError()


def _directory(path, *, private=False):
    """Walk without symlinks, retaining dirfds across component substitution."""
    parsed = PurePosixPath(path)
    if not parsed.is_absolute() or ".." in parsed.parts or str(parsed) != path:
        raise WorkerError("unsafe_worker_path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for index, part in enumerate(parsed.parts[1:]):
            child = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            last = index == len(parsed.parts) - 2
            sticky_parent = (
                not last and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            )
            if (
                info.st_uid not in {0, os.geteuid()}
                or (info.st_mode & 0o022 and not sticky_parent)
                or (last and private and info.st_mode & 0o077)
            ):
                raise WorkerError("unsafe_worker_path")
        if private and path == "/":
            raise WorkerError("unsafe_worker_path")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_at(directory, name, maximum, *, private):
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
        dir_fd=directory,
    )
    try:
        info = os.fstat(fd)
        forbidden = 0o077 if private else 0o022
        if (
            not stat.S_ISREG(info.st_mode)
            or (private and info.st_nlink != 1)
            or info.st_uid not in {0, os.geteuid()}
            or info.st_mode & forbidden
            or not 0 < info.st_size <= maximum
        ):
            raise WorkerError("unsafe_worker_file")
        data = os.read(fd, maximum + 1)
        if len(data) > maximum or len(data) != info.st_size:
            raise WorkerError("unsafe_worker_file")
        return data
    finally:
        os.close(fd)


def load_config(path):
    try:
        parsed = PurePosixPath(path)
        if not parsed.is_absolute() or parsed.name in {"", ".", ".."}:
            raise WorkerError()
        directory = _directory(str(parsed.parent))
        try:
            raw = _read_at(directory, parsed.name, 65536, private=False)
        finally:
            os.close(directory)
        data = json.loads(
            raw, object_pairs_hook=_pairs, parse_constant=_invalid_constant
        )
        _keys(
            data, {"schema_version", "private_root", "instances"}, {"execution_scope"}
        )
        execution_scope = data.get("execution_scope", "provision_only")
        if type(execution_scope) is not str or execution_scope not in {
            "provision_only",
            "lifecycle",
        }:
            raise WorkerError("invalid_worker_scope")
        if (
            type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or type(data["private_root"]) is not str
            or type(data["instances"]) is not list
            or not 1 <= len(data["instances"]) <= 8
        ):
            raise WorkerError()
        directory = _directory(data["private_root"], private=True)
        os.close(directory)  # Dry-run validates metadata, never secret contents.
        instances = []
        seen = set()
        for item in data["instances"]:
            _keys(
                item,
                {"service", "instance", "origin", "acceptance_profile", "credentials"},
                {"server_name", "ca_file"},
            )
            service = item["service"]
            if type(service) is not str or service not in CREDENTIALS:
                raise WorkerError()
            if type(item["instance"]) is not str or not IDENTIFIER.fullmatch(
                item["instance"]
            ):
                raise WorkerError()
            pair = (service, item["instance"])
            if pair in seen:
                raise WorkerError()
            seen.add(pair)
            profile = (
                PROFILES.get(item["acceptance_profile"])
                if type(item["acceptance_profile"]) is str
                else None
            )
            if profile is None or profile.service != service:
                raise WorkerError("acceptance_profile_required")
            origin = item["origin"]
            if (
                type(origin) is not str
                or not origin.isascii()
                or any(ord(c) <= 32 or ord(c) == 127 for c in origin)
            ):
                raise WorkerError()
            url = urlsplit(origin)
            if (
                url.scheme != "https"
                or not url.hostname
                or not re.fullmatch(r"[a-zA-Z0-9.:-]+", url.hostname)
                or url.username is not None
                or url.password is not None
                or url.path not in {"", "/"}
                or url.query
                or url.fragment
                or not 1 <= (443 if url.port is None else url.port) <= 65535
            ):
                raise WorkerError("fixed_https_origin_required")
            credentials = item["credentials"]
            _keys(credentials, CREDENTIALS[service])
            for value in credentials.values():
                if (
                    type(value) is not str
                    or not FILENAME.fullmatch(value)
                    or value in {".", ".."}
                ):
                    raise WorkerError("unsafe_worker_path")
            server = item.get("server_name", "")
            if (
                type(server) is not str
                or (
                    service == "matrix"
                    and not re.fullmatch(
                        r"[a-z0-9][a-z0-9.-]{0,252}(?::[1-9][0-9]{0,4})?", server
                    )
                )
                or (service != "matrix" and server)
            ):
                raise WorkerError()
            ca_file = item.get("ca_file", "")
            if type(ca_file) is not str or (
                ca_file and not FILENAME.fullmatch(ca_file)
            ):
                raise WorkerError()
            instances.append(
                InstanceConfig(
                    service,
                    item["instance"],
                    origin,
                    profile.code,
                    tuple(sorted(credentials.items())),
                    server,
                    ca_file,
                )
            )
        return WorkerConfig(data["private_root"], tuple(instances), execution_scope)
    except WorkerError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        raise WorkerError() from None


def load_private_snapshot(config):
    """Read once per executable process; rotations require a restart."""
    directory = None
    try:
        directory = _directory(config.private_root, private=True)
        snapshot = {}
        for instance in config.instances:
            values = {}
            for key, filename in instance.credentials:
                raw = _read_at(directory, filename, 16384, private=True)
                value = raw.removesuffix(b"\n").removesuffix(b"\r").decode("ascii")
                if not value or any(not 33 <= ord(c) <= 126 for c in value):
                    raise WorkerError("invalid_worker_credential")
                values[key] = value
            if instance.ca_file:
                values["ca_pem"] = _read_at(
                    directory, instance.ca_file, 65536, private=True
                ).decode("ascii")
            snapshot[(instance.service, instance.instance)] = values
        return snapshot
    except WorkerError:
        raise
    except (OSError, ValueError, UnicodeError):
        raise WorkerError("invalid_worker_credential") from None
    finally:
        if directory is not None:
            os.close(directory)
