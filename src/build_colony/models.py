from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class BlockerKind(str, Enum):
    EXTERNAL_EVIDENCE = "external_evidence"
    HARDWARE = "hardware"
    DATA = "data"
    TIME = "time"
    AUTHORIZATION = "authorization"
    AUTHORITY = "authority"


class ColonyVerdict(str, Enum):
    CONTINUE = "continue"
    REACHABLE_CEILINGS_REACHED = "reachable_ceilings_reached"
    ATTENTION_REQUIRED = "attention_required"


@dataclass(frozen=True)
class EvidenceGate:
    id: str
    description: str
    accepted_kinds: tuple[str, ...]
    minimum: int = 1

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("evidence gate id cannot be empty")
        if self.minimum < 1:
            raise ValueError("evidence gate minimum must be >= 1")
        if not self.accepted_kinds:
            raise ValueError("evidence gate must accept at least one evidence kind")
        if "claim" in self.accepted_kinds:
            raise ValueError("worker claims cannot satisfy an evidence gate")


@dataclass(frozen=True)
class Domain:
    id: str
    objective: str
    dependencies: tuple[str, ...] = ()
    write_scopes: tuple[str, ...] = ()
    exclusive_resources: tuple[str, ...] = ()
    gates: tuple[EvidenceGate, ...] = ()
    permitted_blockers: tuple[BlockerKind, ...] = ()


@dataclass(frozen=True)
class Profile:
    project: str
    profile_version: str
    goal: str
    invariants: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    domains: tuple[Domain, ...]

    @property
    def domain_ids(self) -> tuple[str, ...]:
        return tuple(domain.id for domain in self.domains)


@dataclass(frozen=True)
class Evidence:
    gate: str
    kind: str
    locator: str
    sha256: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class Blocker:
    kind: BlockerKind
    detail: str
    evidence: tuple[Evidence, ...] = ()


@dataclass(frozen=True)
class WorkerResult:
    domain_id: str
    outcome: str
    evidence: tuple[Evidence, ...] = ()
    blocker: Blocker | None = None
    revision: str | None = None

    def __post_init__(self) -> None:
        if self.outcome not in {"built", "blocked", "failed"}:
            raise ValueError("worker result outcome must be built, blocked, or failed")
        if self.outcome == "blocked" and self.blocker is None:
            raise ValueError("blocked result requires a blocker")
        if self.outcome != "blocked" and self.blocker is not None:
            raise ValueError("only blocked results may include a blocker")


@dataclass(frozen=True)
class VerificationResult:
    domain_id: str
    accepted: bool
    status: str
    reasons: tuple[str, ...] = ()
    satisfied_gates: tuple[str, ...] = ()


@dataclass(frozen=True)
class IntegrationItem:
    domain_id: str
    revision: str | None
    wave: int


@dataclass(frozen=True)
class ColonyAssessment:
    verdict: ColonyVerdict
    reached: tuple[str, ...] = ()
    externally_blocked: tuple[str, ...] = ()
    dependency_blocked: tuple[str, ...] = ()
    pending: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    project_complete: bool = False
    note: str = ""


def unique(values: Iterable[str]) -> bool:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            return False
        seen.add(value)
    return True
