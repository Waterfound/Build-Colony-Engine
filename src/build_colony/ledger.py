from __future__ import annotations

import json
from typing import Any

from .errors import StateError
from .frontier import build_frontier, initial_states, next_integratable
from .protocol import RunManifest, canonical_json, sha256_digest
from .state_models import (
    LEDGER_SCHEMA_VERSION,
    STATE_PROTOCOL_VERSION,
    EventType,
    LedgerEvent,
    PackageState,
    RunLedger,
)

ROLE_EVENTS: dict[str, frozenset[str]] = {
    "coordinator": frozenset({
        EventType.ISSUE.value,
        EventType.BIND_DISPATCH.value,
        EventType.REVOKE_DISPATCH.value,
    }),
    "builder": frozenset({
        EventType.START.value,
        EventType.SUBMIT_BUILT.value,
        EventType.SUBMIT_BLOCKED.value,
        EventType.SUBMIT_FAILED.value,
    }),
    "verifier": frozenset({
        EventType.VERIFY_ACCEPT.value,
        EventType.VERIFY_BLOCKER.value,
        EventType.VERIFY_REJECT.value,
    }),
    "integrator": frozenset({EventType.INTEGRATE.value}),
}

TRANSITIONS: dict[tuple[PackageState, str], PackageState] = {
    (PackageState.PENDING, EventType.ISSUE.value): PackageState.ISSUED,
    (PackageState.ISSUED, EventType.BIND_DISPATCH.value): PackageState.DISPATCHED,
    (PackageState.DISPATCHED, EventType.REVOKE_DISPATCH.value): PackageState.ISSUED,
    (PackageState.ACTIVE, EventType.REVOKE_DISPATCH.value): PackageState.ISSUED,
    (PackageState.DISPATCHED, EventType.START.value): PackageState.ACTIVE,
    (PackageState.ACTIVE, EventType.SUBMIT_BUILT.value): PackageState.SUBMITTED_BUILT,
    (PackageState.ACTIVE, EventType.SUBMIT_BLOCKED.value): PackageState.SUBMITTED_BLOCKED,
    (PackageState.ACTIVE, EventType.SUBMIT_FAILED.value): PackageState.FAILED,
    (PackageState.SUBMITTED_BUILT, EventType.VERIFY_ACCEPT.value): PackageState.VERIFIED,
    (PackageState.SUBMITTED_BUILT, EventType.VERIFY_REJECT.value): PackageState.REJECTED,
    (PackageState.SUBMITTED_BLOCKED, EventType.VERIFY_BLOCKER.value): PackageState.EXTERNALLY_BLOCKED,
    (PackageState.SUBMITTED_BLOCKED, EventType.VERIFY_REJECT.value): PackageState.REJECTED,
    (PackageState.VERIFIED, EventType.INTEGRATE.value): PackageState.INTEGRATED,
}


def _event_material(event: LedgerEvent) -> dict[str, Any]:
    return {
        "seq": event.seq,
        "run_id": event.run_id,
        "package_id": event.package_id,
        "role": event.role,
        "event_type": event.event_type,
        "payload_json": event.payload_json,
        "previous_event_digest": event.previous_event_digest,
        "manifest_digest": event.manifest_digest,
    }


def _require_sha256(payload: dict[str, Any], field: str) -> None:
    value = payload.get(field)
    if not isinstance(value, str) or len(value) != 64:
        raise StateError(f"{field} must be a 64-character SHA-256 hex digest")
    if any(ch not in "0123456789abcdef" for ch in value.lower()):
        raise StateError(f"{field} must be a 64-character SHA-256 hex digest")


def _require_nonempty_string(payload: dict[str, Any], field: str) -> None:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise StateError(f"{field} must be a non-empty string")


def _dispatch_attempt(payload: dict[str, Any], *, explicit: bool = False) -> int:
    if explicit and "dispatch_attempt" not in payload:
        raise StateError("dispatch_attempt is required")
    value = payload.get("dispatch_attempt", 1)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StateError("dispatch_attempt must be an integer >= 1")
    return value


def _optional_session_digest(payload: dict[str, Any]) -> str | None:
    value = payload.get("session_bundle_digest")
    if value is None:
        return None
    _require_sha256(payload, "session_bundle_digest")
    return value


def _validate_payload(event_type: str, payload: dict[str, Any]) -> None:
    if event_type == EventType.BIND_DISPATCH.value:
        _require_nonempty_string(payload, "dispatch_id")
        _require_sha256(payload, "dispatch_receipt_digest")
        _dispatch_attempt(payload)
        _optional_session_digest(payload)
    elif event_type == EventType.REVOKE_DISPATCH.value:
        _require_nonempty_string(payload, "dispatch_id")
        _require_sha256(payload, "dispatch_receipt_digest")
        _dispatch_attempt(payload, explicit=True)
        _optional_session_digest(payload)
        _require_nonempty_string(payload, "reason")
    elif event_type == EventType.START.value:
        _require_nonempty_string(payload, "dispatch_id")
        _require_sha256(payload, "dispatch_receipt_digest")
        _dispatch_attempt(payload)
        _optional_session_digest(payload)
    elif event_type == EventType.SUBMIT_BUILT.value:
        _require_nonempty_string(payload, "dispatch_id")
        _require_sha256(payload, "result_envelope_digest")
        _require_sha256(payload, "result_digest")
        _require_nonempty_string(payload, "revision")
        _dispatch_attempt(payload)
        _optional_session_digest(payload)
    elif event_type == EventType.SUBMIT_BLOCKED.value:
        _require_nonempty_string(payload, "dispatch_id")
        _require_sha256(payload, "result_envelope_digest")
        _require_sha256(payload, "result_digest")
        _require_nonempty_string(payload, "blocker_kind")
        _dispatch_attempt(payload)
        _optional_session_digest(payload)
    elif event_type == EventType.SUBMIT_FAILED.value:
        _require_nonempty_string(payload, "dispatch_id")
        _require_sha256(payload, "result_envelope_digest")
        _require_sha256(payload, "result_digest")
        _dispatch_attempt(payload)
        _optional_session_digest(payload)
    elif event_type in {
        EventType.VERIFY_ACCEPT.value,
        EventType.VERIFY_REJECT.value,
    }:
        _require_sha256(payload, "verification_digest")
        _require_sha256(payload, "result_digest")
    elif event_type == EventType.VERIFY_BLOCKER.value:
        _require_sha256(payload, "verification_digest")
        _require_sha256(payload, "result_digest")
        _require_nonempty_string(payload, "blocker_kind")
    elif event_type == EventType.INTEGRATE.value:
        _require_nonempty_string(payload, "revision")


def _validate_role_event(role: str, event_type: str) -> None:
    if role not in ROLE_EVENTS:
        raise StateError(f"unknown role: {role}")
    if event_type not in ROLE_EVENTS[role]:
        raise StateError(f"role {role} is not allowed to emit {event_type}")


def _binding_attempt(binding: dict[str, Any]) -> int:
    return _dispatch_attempt(binding)


def _validate_dispatch_binding_match(
    *,
    package,
    payload: dict[str, Any],
    dispatch_binding: dict[str, Any] | None,
    label: str,
) -> None:
    if dispatch_binding is None:
        raise StateError(f"package {package.domain_id} has no bound dispatch")
    if payload["dispatch_id"] != dispatch_binding["dispatch_id"]:
        raise StateError(f"{label} dispatch_id mismatch for {package.domain_id}")
    if _dispatch_attempt(payload) != _binding_attempt(dispatch_binding):
        raise StateError(f"{label} dispatch_attempt mismatch for {package.domain_id}")
    payload_session = payload.get("session_bundle_digest")
    bound_session = dispatch_binding.get("session_bundle_digest")
    if bound_session is not None and payload_session != bound_session:
        raise StateError(f"{label} session bundle mismatch for {package.domain_id}")


def _validate_package_binding(
    *,
    package,
    event_type: str,
    payload: dict[str, Any],
    dispatch_binding: dict[str, Any] | None,
    submitted: dict[str, Any] | None,
) -> None:
    if event_type == EventType.START.value:
        _validate_dispatch_binding_match(
            package=package,
            payload=payload,
            dispatch_binding=dispatch_binding,
            label="builder start",
        )
        if payload["dispatch_receipt_digest"].lower() != dispatch_binding["dispatch_receipt_digest"].lower():
            raise StateError(f"builder start dispatch receipt mismatch for {package.domain_id}")

    if event_type in {
        EventType.SUBMIT_BUILT.value,
        EventType.SUBMIT_BLOCKED.value,
        EventType.SUBMIT_FAILED.value,
    }:
        _validate_dispatch_binding_match(
            package=package,
            payload=payload,
            dispatch_binding=dispatch_binding,
            label="builder submission",
        )

    if event_type == EventType.REVOKE_DISPATCH.value:
        _validate_dispatch_binding_match(
            package=package,
            payload=payload,
            dispatch_binding=dispatch_binding,
            label="dispatch revocation",
        )
        if payload["dispatch_receipt_digest"].lower() != dispatch_binding["dispatch_receipt_digest"].lower():
            raise StateError(f"dispatch revocation receipt mismatch for {package.domain_id}")

    if event_type == EventType.SUBMIT_BLOCKED.value:
        blocker_kind = payload["blocker_kind"]
        if blocker_kind not in package.permitted_blockers:
            raise StateError(
                f"blocker kind {blocker_kind} is not permitted for package {package.domain_id}"
            )

    if event_type in {
        EventType.VERIFY_ACCEPT.value,
        EventType.VERIFY_REJECT.value,
        EventType.VERIFY_BLOCKER.value,
    }:
        if submitted is None:
            raise StateError(f"package {package.domain_id} has no submitted result to verify")
        if payload["result_digest"].lower() != submitted["result_digest"].lower():
            raise StateError(
                f"verification result_digest does not match submitted result for {package.domain_id}"
            )

    if event_type == EventType.VERIFY_BLOCKER.value:
        blocker_kind = payload["blocker_kind"]
        if blocker_kind not in package.permitted_blockers:
            raise StateError(
                f"blocker kind {blocker_kind} is not permitted for package {package.domain_id}"
            )
        if blocker_kind != submitted.get("blocker_kind"):
            raise StateError(
                f"verification blocker_kind does not match submitted blocker for {package.domain_id}"
            )

    if event_type == EventType.INTEGRATE.value:
        if submitted is None:
            raise StateError(f"package {package.domain_id} has no submitted revision to integrate")
        submitted_revision = submitted.get("revision")
        if payload["revision"] != submitted_revision:
            raise StateError(
                f"integration revision does not match submitted revision for {package.domain_id}"
            )


def _replay_runtime(manifest: RunManifest, ledger: RunLedger):
    if ledger.schema_version != LEDGER_SCHEMA_VERSION:
        raise StateError(f"unsupported ledger schema_version: {ledger.schema_version}")
    if ledger.state_protocol_version != STATE_PROTOCOL_VERSION:
        raise StateError(f"unsupported state_protocol_version: {ledger.state_protocol_version}")
    if ledger.run_id != manifest.run_id:
        raise StateError("ledger run_id does not match manifest")
    if ledger.manifest_digest != manifest.manifest_digest:
        raise StateError("ledger manifest_digest does not match manifest")

    package_by_id = {package.package_id: package for package in manifest.packages}
    states = initial_states(manifest)
    dispatch_bindings: dict[str, dict[str, Any]] = {}
    last_attempt: dict[str, int] = {package.domain_id: 0 for package in manifest.packages}
    submissions: dict[str, dict[str, Any]] = {}
    previous_digest = ""

    for expected_seq, event in enumerate(ledger.events, start=1):
        if event.seq != expected_seq:
            raise StateError(f"ledger sequence mismatch at event {expected_seq}")
        if event.run_id != manifest.run_id:
            raise StateError(f"event {event.seq} run_id mismatch")
        if event.manifest_digest != manifest.manifest_digest:
            raise StateError(f"event {event.seq} manifest_digest mismatch")
        if event.package_id not in package_by_id:
            raise StateError(f"event {event.seq} references unknown package_id")
        if event.previous_event_digest != previous_digest:
            raise StateError(f"event {event.seq} previous digest mismatch")
        _validate_role_event(event.role, event.event_type)

        try:
            payload = json.loads(event.payload_json)
        except json.JSONDecodeError as exc:
            raise StateError(f"event {event.seq} payload_json is invalid") from exc
        if not isinstance(payload, dict):
            raise StateError(f"event {event.seq} payload must be an object")
        if event.payload_json != canonical_json(payload):
            raise StateError(f"event {event.seq} payload_json is not canonical")
        _validate_payload(event.event_type, payload)

        expected_digest = sha256_digest(_event_material(event))
        if event.event_digest != expected_digest:
            raise StateError(f"event {event.seq} digest mismatch")

        package = package_by_id[event.package_id]
        domain_id = package.domain_id
        current = states[domain_id]
        transition = TRANSITIONS.get((current, event.event_type))
        if transition is None:
            raise StateError(
                f"invalid state transition for {domain_id}: {current.value} + {event.event_type}"
            )

        _validate_package_binding(
            package=package,
            event_type=event.event_type,
            payload=payload,
            dispatch_binding=dispatch_bindings.get(domain_id),
            submitted=submissions.get(domain_id),
        )

        if event.event_type == EventType.ISSUE.value:
            frontier = build_frontier(manifest, states)
            if domain_id not in frontier.ready:
                raise StateError(f"package {domain_id} is not on the execution frontier")
        elif event.event_type == EventType.BIND_DISPATCH.value:
            frontier = build_frontier(manifest, states)
            if domain_id not in frontier.dispatchable:
                raise StateError(f"package {domain_id} is not dispatchable")
            attempt = _dispatch_attempt(payload)
            expected_attempt = last_attempt[domain_id] + 1
            if attempt != expected_attempt:
                raise StateError(
                    f"dispatch attempt for {domain_id} must be {expected_attempt}; got {attempt}"
                )
        elif event.event_type == EventType.INTEGRATE.value:
            expected_domain = next_integratable(manifest, states)
            if expected_domain != domain_id:
                raise StateError(
                    f"package {domain_id} is not next in serialized integration order; "
                    f"expected {expected_domain}"
                )

        if event.event_type == EventType.BIND_DISPATCH.value:
            dispatch_bindings[domain_id] = dict(payload)
            last_attempt[domain_id] = _dispatch_attempt(payload)
        elif event.event_type == EventType.REVOKE_DISPATCH.value:
            dispatch_bindings.pop(domain_id, None)
        elif event.event_type in {
            EventType.SUBMIT_BUILT.value,
            EventType.SUBMIT_BLOCKED.value,
            EventType.SUBMIT_FAILED.value,
        }:
            submissions[domain_id] = dict(payload)

        states[domain_id] = transition
        previous_digest = event.event_digest

    if ledger.head_event_digest != previous_digest:
        raise StateError("ledger head_event_digest mismatch")
    return states, dispatch_bindings, last_attempt, submissions


def replay_ledger(manifest: RunManifest, ledger: RunLedger) -> dict[str, PackageState]:
    states, _, _, _ = _replay_runtime(manifest, ledger)
    return states


def current_dispatch_binding(
    manifest: RunManifest,
    ledger: RunLedger,
    domain_id: str,
) -> dict[str, Any] | None:
    _, bindings, _, _ = _replay_runtime(manifest, ledger)
    if domain_id not in {package.domain_id for package in manifest.packages}:
        raise StateError(f"unknown domain: {domain_id}")
    binding = bindings.get(domain_id)
    return dict(binding) if binding is not None else None


def next_dispatch_attempt(manifest: RunManifest, ledger: RunLedger, domain_id: str) -> int:
    _, _, attempts, _ = _replay_runtime(manifest, ledger)
    if domain_id not in attempts:
        raise StateError(f"unknown domain: {domain_id}")
    return attempts[domain_id] + 1


def verify_ledger(manifest: RunManifest, ledger: RunLedger) -> tuple[bool, tuple[str, ...]]:
    try:
        replay_ledger(manifest, ledger)
    except StateError as exc:
        return False, (str(exc),)
    return True, ()


def execution_frontier(manifest: RunManifest, ledger: RunLedger):
    return build_frontier(manifest, replay_ledger(manifest, ledger))


def append_event(
    manifest: RunManifest,
    ledger: RunLedger,
    *,
    package_id: str,
    role: str,
    event_type: str,
    payload: dict[str, Any] | None = None,
) -> RunLedger:
    states = replay_ledger(manifest, ledger)
    package_by_id = {package.package_id: package for package in manifest.packages}
    if package_id not in package_by_id:
        raise StateError(f"unknown package_id: {package_id}")
    _validate_role_event(role, event_type)

    package = package_by_id[package_id]
    current = states[package.domain_id]
    if (current, event_type) not in TRANSITIONS:
        raise StateError(f"invalid state transition: {current.value} + {event_type}")

    payload_value = dict(payload or {})
    _validate_payload(event_type, payload_value)

    if event_type == EventType.ISSUE.value:
        if package.domain_id not in build_frontier(manifest, states).ready:
            raise StateError(f"package {package.domain_id} is not on the execution frontier")
    elif event_type == EventType.BIND_DISPATCH.value:
        if package.domain_id not in build_frontier(manifest, states).dispatchable:
            raise StateError(f"package {package.domain_id} is not dispatchable")
    elif event_type == EventType.INTEGRATE.value:
        expected_domain = next_integratable(manifest, states)
        if expected_domain != package.domain_id:
            raise StateError(
                f"package {package.domain_id} is not next in serialized integration order; expected {expected_domain}"
            )

    unsigned = LedgerEvent(
        seq=len(ledger.events) + 1,
        run_id=manifest.run_id,
        package_id=package_id,
        role=role,
        event_type=event_type,
        payload_json=canonical_json(payload_value),
        previous_event_digest=ledger.head_event_digest,
        manifest_digest=manifest.manifest_digest,
        event_digest="",
    )
    event = LedgerEvent(
        seq=unsigned.seq,
        run_id=unsigned.run_id,
        package_id=unsigned.package_id,
        role=unsigned.role,
        event_type=unsigned.event_type,
        payload_json=unsigned.payload_json,
        previous_event_digest=unsigned.previous_event_digest,
        manifest_digest=unsigned.manifest_digest,
        event_digest=sha256_digest(_event_material(unsigned)),
    )
    updated = RunLedger(
        schema_version=ledger.schema_version,
        state_protocol_version=ledger.state_protocol_version,
        run_id=ledger.run_id,
        manifest_digest=ledger.manifest_digest,
        events=ledger.events + (event,),
        head_event_digest=event.event_digest,
    )
    replay_ledger(manifest, updated)
    return updated
