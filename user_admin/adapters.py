"""Narrow native-worker contract; no native credentials belong in the web app.

Production adapters must be separately capability-tested. A fake implementing
this protocol is not evidence that a particular vendor version supports it.
"""

from dataclasses import dataclass
from typing import Literal, Protocol
from uuid import UUID

Evidence = Literal["confirmed", "unknown", "unsupported"]


@dataclass(frozen=True)
class Capabilities:
    service: str
    instance: str
    actions: frozenset[str]
    # A remote PUT/upsert is NOT create-only, even after a preceding GET.
    create_only: bool = False


@dataclass(frozen=True)
class Command:
    target_id: UUID
    operation_id: UUID
    user_id: int
    service: str
    instance: str
    generation: int
    action: str
    native_id: str
    authority_epoch: int = 0


@dataclass(frozen=True)
class Binding:
    """Remote binding verified by the adapter; not arbitrary extra OIDC claims."""

    external_id: str
    external_username: str
    minio_policy: str = ""


@dataclass(frozen=True)
class Observation:
    native_id: str
    subject: str
    instance: str
    owner: UUID
    state: Literal["enabled", "blocked", "unbound"]
    new_login: Evidence = "unknown"
    existing_sessions: Evidence = "unknown"
    api_credentials: Evidence = "unknown"
    # Opaque nonsecret provenance marker verified by the native adapter.
    block_receipt: str = ""
    binding: Binding | None = None


class NativeAdapter(Protocol):
    capabilities: Capabilities

    def inspect(self, command: Command) -> Observation:
        """Read only; verify immutable provider-subject and management ownership."""

    def apply(self, command: Command) -> Observation:
        """No arbitrary URLs/scripts, credential copying or destructive deletion.

        Create must be create-only and stamp ownership in the same remote effect.
        A staged CREATE records an unbound resource; BIND is a separate durable
        operation and must not create/overwrite another account. Only verified
        BIND may publish its typed identity in the central final transaction.
        Block must preserve password, memberships and data. Enable must not clear
        an unrelated ban; the inspected block receipt must still match remotely.
        Transport timeout or uncertain remote effect must raise OutcomeUnknown.
        Never include raw native responses/credentials in exception strings.
        """


class OutcomeUnknown(Exception):
    """A remote side effect might still complete. Never automatically replay."""
