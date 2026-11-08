from __future__ import annotations

import json
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import StateError
from .models import EvidenceGate
from .protocol import RunManifest, RoleContract, WorkPackage, verify_manifest_document

STATE_PROTOCOL_VERSION = "0.0.5"
LEDGER_SCHEMA_VERSION = 1


class PackageState(str, Enum):
    PENDING = "pending"
    ISSUED = "issued"
    DISPATCHED = "dispatched"
    ACTIVE = "active"
    SUBMITTED_BUILT = "submitted_built"
    SUBMITTED_BLOCKED = "submitted_blocked"
    VERIFIED = "verified"
    EXTERNALLY_BLOCKED = "externally_blocked"
    FAILED = "failed"
    REJECTED = "rejected"
    INTEGRATED = "integrated"


class EventType(str, Enum):
    ISSUE = "issue"
    BIND_DISPATCH = "bind_dispatch"
    REVOKE_DISPATCH = "revoke_dispatch"
    START = "start"
    SUBMIT_BUILT = "submit_built"
    SUBMIT_BLOCKED = "submit_blocked"
    SUBMIT_FAILED = "submit_failed"
    VERIFY_ACCEPT = "verify_accept"
    VERIFY_BLOCKER = "verify_blocker"
    VERIFY_REJECT = "verify_reject"
    INTEGRATE = "integrate"


@dataclass(frozen=True)
class LedgerEvent:
    seq: int
    run_id: str
    package_id: str
    role: str
    event_type: str
    payload_json: str
    previous_event_digest: str
    manifest_digest: str
    event_digest: str


@dataclass(frozen=True)
class RunLedger:
    schema_version: int
    state_protocol_version: str
    run_id: str
    manifest_digest: str
    events: tuple[LedgerEvent, ...]
    head_event_digest: str


@dataclass(frozen=True)
class ExecutionFrontier:
    ready: tuple[str, ...]
    dispatchable: tuple[str, ...]
    active: tuple[str, ...]
    waiting_dependencies: tuple[str, ...]
    waiting_serialization: tuple[str, ...]
    dependency_blocked: tuple[str, ...]
    attention_required: tuple[str, ...]
    verified_waiting_integration: tuple[str, ...]
    integrated: tuple[str, ...]
    externally_blocked: tuple[str, ...]
    next_integratable: str | None


def _normal(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {field.name: _normal(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, dict):
        return {str(key): _normal(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_normal(item) for item in value]
    return value


def manifest_from_document(document: dict[str, Any]) -> RunManifest:
    accepted, reasons = verify_manifest_document(document)
    if not accepted:
        raise StateError("invalid run manifest: " + "; ".join(reasons))

    contracts = tuple(
        RoleContract(
            id=item["id"],
            role=item["role"],
            permissions=tuple(item["permissions"]),
            prohibitions=tuple(item["prohibitions"]),
        )
        for item in document["role_contracts"]
    )
    packages = []
    for item in document["packages"]:
        gates = tuple(
            EvidenceGate(
                id=gate["id"],
                description=gate["description"],
                accepted_kinds=tuple(gate["accepted_kinds"]),
                minimum=int(gate.get("minimum", 1)),
            )
            for gate in item["gates"]
        )
        packages.append(
            WorkPackage(
                package_id=item["package_id"],
                run_id=item["run_id"],
                domain_id=item["domain_id"],
                wave=int(item["wave"]),
                objective=item["objective"],
                dependencies=tuple(item["dependencies"]),
                serialize_after=tuple(item["serialize_after"]),
                write_scopes=tuple(item["write_scopes"]),
                exclusive_resources=tuple(item["exclusive_resources"]),
                gates=gates,
                permitted_blockers=tuple(item["permitted_blockers"]),
                invariants=tuple(item["invariants"]),
                forbidden_actions=tuple(item["forbidden_actions"]),
                role_contract_ids=tuple(item["role_contract_ids"]),
                package_digest=item["package_digest"],
            )
        )
    return RunManifest(
        schema_version=int(document["schema_version"]),
        protocol_version=document["protocol_version"],
        run_id=document["run_id"],
        project=document["project"],
        profile_version=document["profile_version"],
        profile_digest=document["profile_digest"],
        source_revision=document["source_revision"],
        schedule=tuple(tuple(wave) for wave in document["schedule"]),
        role_contracts=contracts,
        packages=tuple(packages),
        manifest_digest=document["manifest_digest"],
    )


def new_ledger(manifest: RunManifest) -> RunLedger:
    return RunLedger(
        schema_version=LEDGER_SCHEMA_VERSION,
        state_protocol_version=STATE_PROTOCOL_VERSION,
        run_id=manifest.run_id,
        manifest_digest=manifest.manifest_digest,
        events=(),
        head_event_digest="",
    )


def ledger_to_dict(ledger: RunLedger) -> dict[str, Any]:
    return _normal(ledger)


def write_ledger(ledger: RunLedger, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(ledger_to_dict(ledger), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_ledger_document(path: str | Path) -> dict[str, Any]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StateError(f"could not load execution ledger: {exc}") from exc
    if not isinstance(document, dict):
        raise StateError("execution ledger root must be an object")
    return document


def ledger_from_document(document: dict[str, Any]) -> RunLedger:
    required = {
        "schema_version", "state_protocol_version", "run_id",
        "manifest_digest", "events", "head_event_digest"
    }
    missing = sorted(required - set(document))
    if missing:
        raise StateError(f"ledger missing fields: {missing}")
    if not isinstance(document["events"], list):
        raise StateError("ledger events must be a list")
    try:
        events = tuple(LedgerEvent(**item) for item in document["events"])
    except (TypeError, KeyError) as exc:
        raise StateError(f"invalid ledger event: {exc}") from exc
    return RunLedger(
        schema_version=int(document["schema_version"]),
        state_protocol_version=document["state_protocol_version"],
        run_id=document["run_id"],
        manifest_digest=document["manifest_digest"],
        events=events,
        head_event_digest=document["head_event_digest"],
    )
