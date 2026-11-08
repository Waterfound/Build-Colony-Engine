from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from typing import Any, Mapping

from .attestation import ActorAttestation, AttestationTrustPolicy, append_attested_event
from .errors import BuildColonyError, PoolError
from .ledger import append_event
from .protocol import RunManifest, sha256_digest
from .runner_pool import (
    POOL_PROTOCOL_VERSION,
    POOL_SCHEMA_VERSION,
    DispatchPlan,
    PoolAssignment,
    ReferencePoolSessionRunner,
    RunnerRegistry,
    compile_assignment_request,
    verify_dispatch_plan,
)
from .runner_session import SessionDispatchBundle, SessionRunnerAdapter, session_bundle_from_dict
from .runner_session_strict import bind_session_dispatch, build_session_bundle, verify_session_bundle
from .state_models import EventType, RunLedger


@dataclass(frozen=True)
class PoolBundleEntry:
    ordinal: int
    domain_id: str
    assignment_digest: str
    lease_id: str
    bundle: SessionDispatchBundle
    entry_digest: str


@dataclass(frozen=True)
class PoolDispatchFailure:
    ordinal: int
    domain_id: str
    adapter_id: str
    reason: str


@dataclass(frozen=True)
class PoolDispatchAttempt:
    schema_version: int
    pool_protocol_version: str
    plan_id: str
    plan_digest: str
    ledger_head_digest: str
    entries: tuple[PoolBundleEntry, ...]
    failures: tuple[PoolDispatchFailure, ...]
    complete: bool
    attempt_digest: str


@dataclass(frozen=True)
class PoolBindingIntent:
    ordinal: int
    domain_id: str
    package_id: str
    assignment_digest: str
    lease_id: str
    role: str
    action: str
    payload: dict[str, Any]
    payload_digest: str
    intent_digest: str


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


def _without(value: Any, *names: str) -> dict[str, Any]:
    payload = _normal(value)
    for name in names:
        payload.pop(name, None)
    return payload


def _failure(assignment: PoolAssignment, reason: str) -> PoolDispatchFailure:
    return PoolDispatchFailure(
        ordinal=assignment.ordinal,
        domain_id=assignment.domain_id,
        adapter_id=assignment.adapter_id,
        reason=reason,
    )


def _entry(assignment: PoolAssignment, bundle: SessionDispatchBundle) -> PoolBundleEntry:
    unsigned = PoolBundleEntry(
        ordinal=assignment.ordinal,
        domain_id=assignment.domain_id,
        assignment_digest=assignment.assignment_digest,
        lease_id=assignment.lease_id,
        bundle=bundle,
        entry_digest="",
    )
    return PoolBundleEntry(
        ordinal=unsigned.ordinal,
        domain_id=unsigned.domain_id,
        assignment_digest=unsigned.assignment_digest,
        lease_id=unsigned.lease_id,
        bundle=unsigned.bundle,
        entry_digest=sha256_digest(_without(unsigned, "entry_digest")),
    )


def build_dispatch_attempt(
    plan: DispatchPlan,
    manifest: RunManifest,
    ledger: RunLedger,
    registry: RunnerRegistry,
    adapters: Mapping[str, SessionRunnerAdapter],
) -> PoolDispatchAttempt:
    accepted, reasons = verify_dispatch_plan(plan, manifest, ledger, registry)
    if not accepted:
        raise PoolError("cannot dispatch invalid/stale pool plan: " + "; ".join(reasons))
    entries: list[PoolBundleEntry] = []
    failures: list[PoolDispatchFailure] = []
    for assignment in plan.assignments:
        adapter = adapters.get(assignment.adapter_id)
        if adapter is None:
            failures.append(_failure(assignment, "missing_adapter"))
            continue
        try:
            capabilities = adapter.capabilities()
            if capabilities.adapter_id != assignment.adapter_id:
                raise PoolError("adapter identity does not match pool assignment")
            if capabilities.provider != assignment.provider:
                raise PoolError("adapter provider does not match pool assignment")
            if capabilities.capability_digest != assignment.capability_digest:
                raise PoolError("adapter capabilities do not match pool assignment")
            request = compile_assignment_request(
                plan, manifest, ledger, registry, domain_id=assignment.domain_id
            )
            receipt = adapter.dispatch(request)
            bundle = build_session_bundle(capabilities, request, receipt)
            bundle_ok, bundle_reasons = verify_session_bundle(bundle, manifest)
            if not bundle_ok:
                raise PoolError("invalid session bundle: " + "; ".join(bundle_reasons))
            if bundle.request.package_id != assignment.package_id:
                raise PoolError("session bundle package does not match pool assignment")
            if bundle.request.dispatch_attempt != assignment.dispatch_attempt:
                raise PoolError("session bundle attempt does not match pool assignment")
            entries.append(_entry(assignment, bundle))
        except BuildColonyError as exc:
            failures.append(_failure(assignment, str(exc)))
        except Exception as exc:
            failures.append(_failure(assignment, f"runner_exception:{type(exc).__name__}:{exc}"))
    entries.sort(key=lambda item: item.ordinal)
    failures.sort(key=lambda item: item.ordinal)
    complete = len(entries) == len(plan.assignments) and not failures
    unsigned = PoolDispatchAttempt(
        schema_version=POOL_SCHEMA_VERSION,
        pool_protocol_version=POOL_PROTOCOL_VERSION,
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        ledger_head_digest=ledger.head_event_digest,
        entries=tuple(entries),
        failures=tuple(failures),
        complete=complete,
        attempt_digest="",
    )
    return PoolDispatchAttempt(
        schema_version=unsigned.schema_version,
        pool_protocol_version=unsigned.pool_protocol_version,
        plan_id=unsigned.plan_id,
        plan_digest=unsigned.plan_digest,
        ledger_head_digest=unsigned.ledger_head_digest,
        entries=unsigned.entries,
        failures=unsigned.failures,
        complete=unsigned.complete,
        attempt_digest=sha256_digest(_without(unsigned, "attempt_digest")),
    )


def build_reference_dispatch_attempt(plan, manifest, ledger, registry) -> PoolDispatchAttempt:
    adapters = {
        caps.adapter_id: ReferencePoolSessionRunner(caps) for caps in registry.runners
    }
    return build_dispatch_attempt(plan, manifest, ledger, registry, adapters)


def verify_dispatch_attempt(attempt, plan, manifest, ledger, registry):
    reasons: list[str] = []
    if attempt.schema_version != POOL_SCHEMA_VERSION:
        reasons.append(f"unsupported pool attempt schema version: {attempt.schema_version}")
    if attempt.pool_protocol_version != POOL_PROTOCOL_VERSION:
        reasons.append(f"unsupported pool attempt protocol version: {attempt.pool_protocol_version}")
    if attempt.plan_id != plan.plan_id or attempt.plan_digest != plan.plan_digest:
        reasons.append("pool attempt is not bound to supplied plan")
    if attempt.ledger_head_digest != ledger.head_event_digest:
        reasons.append("pool attempt is stale for current ledger head")
    if attempt.attempt_digest != sha256_digest(_without(attempt, "attempt_digest")):
        reasons.append("pool attempt digest mismatch")
    plan_ok, plan_reasons = verify_dispatch_plan(plan, manifest, ledger, registry)
    if not plan_ok:
        reasons.extend(plan_reasons)
    assignments = {item.domain_id: item for item in plan.assignments}
    covered: set[str] = set()
    for entry in attempt.entries:
        if entry.domain_id in covered:
            reasons.append(f"duplicate attempt domain: {entry.domain_id}")
            continue
        covered.add(entry.domain_id)
        assignment = assignments.get(entry.domain_id)
        if assignment is None:
            reasons.append(f"attempt contains unassigned domain: {entry.domain_id}")
            continue
        if entry.ordinal != assignment.ordinal:
            reasons.append(f"attempt ordinal mismatch: {entry.domain_id}")
        if entry.assignment_digest != assignment.assignment_digest:
            reasons.append(f"attempt assignment digest mismatch: {entry.domain_id}")
        if entry.lease_id != assignment.lease_id:
            reasons.append(f"attempt lease mismatch: {entry.domain_id}")
        if entry.entry_digest != sha256_digest(_without(entry, "entry_digest")):
            reasons.append(f"attempt entry digest mismatch: {entry.domain_id}")
        bundle_ok, bundle_reasons = verify_session_bundle(entry.bundle, manifest)
        if not bundle_ok:
            reasons.extend(f"{entry.domain_id}: {reason}" for reason in bundle_reasons)
        if entry.bundle.request.package_id != assignment.package_id:
            reasons.append(f"attempt package mismatch: {entry.domain_id}")
        if entry.bundle.request.dispatch_attempt != assignment.dispatch_attempt:
            reasons.append(f"attempt dispatch_attempt mismatch: {entry.domain_id}")
        if entry.bundle.capabilities.adapter_id != assignment.adapter_id:
            reasons.append(f"attempt adapter mismatch: {entry.domain_id}")
    for failure in attempt.failures:
        if failure.domain_id in covered:
            reasons.append(f"attempt domain has both receipt and failure: {failure.domain_id}")
            continue
        covered.add(failure.domain_id)
        assignment = assignments.get(failure.domain_id)
        if assignment is None:
            reasons.append(f"attempt failure references unassigned domain: {failure.domain_id}")
            continue
        if failure.ordinal != assignment.ordinal:
            reasons.append(f"attempt failure ordinal mismatch: {failure.domain_id}")
        if failure.adapter_id != assignment.adapter_id:
            reasons.append(f"attempt failure adapter mismatch: {failure.domain_id}")
        if not failure.reason.strip():
            reasons.append(f"attempt failure reason is empty: {failure.domain_id}")
    if covered != set(assignments):
        reasons.append("pool attempt does not account for every assignment")
    expected_complete = len(attempt.entries) == len(plan.assignments) and not attempt.failures
    if attempt.complete != expected_complete:
        reasons.append("pool attempt complete flag is inconsistent")
    return not reasons, tuple(dict.fromkeys(reasons))


def _pool_binding_payload(plan, assignment, bundle, manifest, ledger):
    candidate = bind_session_dispatch(manifest, ledger, bundle)
    payload = json.loads(candidate.events[-1].payload_json)
    payload.update(
        {
            "pool_protocol_version": POOL_PROTOCOL_VERSION,
            "pool_plan_id": plan.plan_id,
            "pool_plan_digest": plan.plan_digest,
            "pool_assignment_digest": assignment.assignment_digest,
            "pool_lease_id": assignment.lease_id,
        }
    )
    return payload


def bind_dispatch_attempt(attempt, plan, manifest, ledger, registry) -> RunLedger:
    accepted, reasons = verify_dispatch_attempt(attempt, plan, manifest, ledger, registry)
    if not accepted:
        raise PoolError("cannot bind invalid pool attempt: " + "; ".join(reasons))
    if not attempt.complete:
        raise PoolError("incomplete pool attempt cannot mutate the execution ledger")
    assignments = {item.domain_id: item for item in plan.assignments}
    updated = ledger
    for entry in sorted(attempt.entries, key=lambda item: item.ordinal):
        assignment = assignments[entry.domain_id]
        payload = _pool_binding_payload(plan, assignment, entry.bundle, manifest, updated)
        updated = append_event(
            manifest,
            updated,
            package_id=entry.bundle.request.package_id,
            role="coordinator",
            event_type=EventType.BIND_DISPATCH.value,
            payload=payload,
        )
    return updated


def build_binding_intents(attempt, plan, manifest, ledger, registry):
    accepted, reasons = verify_dispatch_attempt(attempt, plan, manifest, ledger, registry)
    if not accepted:
        raise PoolError("cannot build intents for invalid pool attempt: " + "; ".join(reasons))
    if not attempt.complete:
        raise PoolError("incomplete pool attempt has no bindable intent set")
    assignments = {item.domain_id: item for item in plan.assignments}
    simulated = ledger
    intents: list[PoolBindingIntent] = []
    for entry in sorted(attempt.entries, key=lambda item: item.ordinal):
        assignment = assignments[entry.domain_id]
        payload = _pool_binding_payload(plan, assignment, entry.bundle, manifest, simulated)
        unsigned = PoolBindingIntent(
            ordinal=entry.ordinal,
            domain_id=entry.domain_id,
            package_id=entry.bundle.request.package_id,
            assignment_digest=entry.assignment_digest,
            lease_id=entry.lease_id,
            role="coordinator",
            action=EventType.BIND_DISPATCH.value,
            payload=payload,
            payload_digest=sha256_digest(payload),
            intent_digest="",
        )
        intent = PoolBindingIntent(
            ordinal=unsigned.ordinal,
            domain_id=unsigned.domain_id,
            package_id=unsigned.package_id,
            assignment_digest=unsigned.assignment_digest,
            lease_id=unsigned.lease_id,
            role=unsigned.role,
            action=unsigned.action,
            payload=unsigned.payload,
            payload_digest=unsigned.payload_digest,
            intent_digest=sha256_digest(_without(unsigned, "intent_digest")),
        )
        intents.append(intent)
        simulated = append_event(
            manifest,
            simulated,
            package_id=intent.package_id,
            role=intent.role,
            event_type=intent.action,
            payload=intent.payload,
        )
    return tuple(intents)


def bind_dispatch_attempt_attested(
    attempt,
    plan,
    manifest,
    ledger,
    registry,
    policy: AttestationTrustPolicy,
    attestations: Mapping[str, ActorAttestation],
) -> RunLedger:
    intents = build_binding_intents(attempt, plan, manifest, ledger, registry)
    entries = {entry.domain_id: entry for entry in attempt.entries}
    assignments = {item.domain_id: item for item in plan.assignments}
    updated = ledger
    for intent in intents:
        attestation = attestations.get(intent.domain_id)
        if attestation is None:
            raise PoolError(f"missing actor attestation for pool domain: {intent.domain_id}")
        if attestation.package_id != intent.package_id:
            raise PoolError(f"actor attestation package mismatch: {intent.domain_id}")
        if attestation.role != intent.role:
            raise PoolError(f"actor attestation role mismatch: {intent.domain_id}")
        if attestation.action != intent.action:
            raise PoolError(f"actor attestation action mismatch: {intent.domain_id}")
        current_payload = _pool_binding_payload(
            plan,
            assignments[intent.domain_id],
            entries[intent.domain_id].bundle,
            manifest,
            updated,
        )
        if current_payload != intent.payload:
            raise PoolError(f"pool binding intent became stale: {intent.domain_id}")
        updated = append_attested_event(
            manifest, updated, policy, attestation, payload=intent.payload
        )
    return updated


def attempt_to_dict(attempt: PoolDispatchAttempt) -> dict[str, Any]:
    return _normal(attempt)


def attempt_from_document(document: dict[str, Any]) -> PoolDispatchAttempt:
    try:
        entries = tuple(
            PoolBundleEntry(
                ordinal=int(item["ordinal"]),
                domain_id=item["domain_id"],
                assignment_digest=item["assignment_digest"],
                lease_id=item["lease_id"],
                bundle=session_bundle_from_dict(item["bundle"]),
                entry_digest=item["entry_digest"],
            )
            for item in document["entries"]
        )
        failures = tuple(
            PoolDispatchFailure(
                ordinal=int(item["ordinal"]),
                domain_id=item["domain_id"],
                adapter_id=item["adapter_id"],
                reason=item["reason"],
            )
            for item in document["failures"]
        )
        return PoolDispatchAttempt(
            schema_version=int(document["schema_version"]),
            pool_protocol_version=document["pool_protocol_version"],
            plan_id=document["plan_id"],
            plan_digest=document["plan_digest"],
            ledger_head_digest=document["ledger_head_digest"],
            entries=entries,
            failures=failures,
            complete=bool(document["complete"]),
            attempt_digest=document["attempt_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PoolError(f"invalid pool attempt document: {exc}") from exc


def binding_intents_to_dict(intents: tuple[PoolBindingIntent, ...]) -> list[dict[str, Any]]:
    return [_normal(intent) for intent in intents]
