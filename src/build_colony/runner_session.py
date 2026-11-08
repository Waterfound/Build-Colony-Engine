from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .errors import SessionError
from .ledger import append_event, next_dispatch_attempt, replay_ledger
from .models import EvidenceGate
from .protocol import RunManifest, WorkPackage, sha256_digest
from .runner_adapter import RunnerCapabilities, reference_capabilities, verify_capabilities
from .state_models import EventType, PackageState, RunLedger

SESSION_PROTOCOL_VERSION = "0.0.5"
SESSION_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class SessionDispatchRequest:
    schema_version: int
    session_protocol_version: str
    dispatch_id: str
    dispatch_attempt: int
    run_id: str
    manifest_digest: str
    source_revision: str
    package_id: str
    package_digest: str
    domain_id: str
    adapter_id: str
    provider: str
    capability_digest: str
    mode: str
    objective: str
    dependencies: tuple[str, ...]
    write_scopes: tuple[str, ...]
    exclusive_resources: tuple[str, ...]
    invariants: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    gates: tuple[EvidenceGate, ...]
    request_digest: str


@dataclass(frozen=True)
class SessionDispatchReceipt:
    schema_version: int
    session_protocol_version: str
    dispatch_id: str
    dispatch_attempt: int
    run_id: str
    manifest_digest: str
    package_id: str
    package_digest: str
    adapter_id: str
    provider: str
    capability_digest: str
    request_digest: str
    accepted: bool
    external_run_id: str
    receipt_digest: str


@dataclass(frozen=True)
class SessionDispatchBundle:
    schema_version: int
    session_protocol_version: str
    capabilities: RunnerCapabilities
    request: SessionDispatchRequest
    receipt: SessionDispatchReceipt
    bundle_digest: str


@dataclass(frozen=True)
class SessionResultEnvelope:
    schema_version: int
    session_protocol_version: str
    dispatch_id: str
    dispatch_attempt: int
    run_id: str
    manifest_digest: str
    package_id: str
    package_digest: str
    adapter_id: str
    provider: str
    external_run_id: str
    request_digest: str
    receipt_digest: str
    session_bundle_digest: str
    outcome: str
    revision: str | None
    blocker_kind: str | None
    evidence_locators: tuple[str, ...]
    result_digest: str
    envelope_digest: str


@runtime_checkable
class SessionRunnerAdapter(Protocol):
    """Provider-neutral retry-aware runner surface.

    A session adapter transports one logical dispatch attempt. Satisfying this
    protocol does not grant Verifier or Integrator authority.
    """

    def capabilities(self) -> RunnerCapabilities:
        ...

    def dispatch(self, request: SessionDispatchRequest) -> SessionDispatchReceipt:
        ...


class ReferenceSessionRunnerAdapter:
    """Deterministic in-process v0.0.5 conformance adapter."""

    def capabilities(self) -> RunnerCapabilities:
        return reference_capabilities()

    def dispatch(self, request: SessionDispatchRequest) -> SessionDispatchReceipt:
        return accept_reference_session_dispatch(request)


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


def _validate_nonempty(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise SessionError(f"{field} must be a non-empty string")


def _validate_sha256(value: str, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise SessionError(f"{field} must be a 64-character SHA-256 hex digest")
    if any(character not in "0123456789abcdef" for character in value.lower()):
        raise SessionError(f"{field} must be a 64-character SHA-256 hex digest")


def _package_for_domain(manifest: RunManifest, domain_id: str) -> WorkPackage:
    package = next((item for item in manifest.packages if item.domain_id == domain_id), None)
    if package is None:
        raise SessionError(f"unknown domain: {domain_id}")
    return package


def _request_seed(
    manifest: RunManifest,
    package: WorkPackage,
    capabilities: RunnerCapabilities,
    mode: str,
    attempt: int,
) -> dict[str, Any]:
    return {
        "session_protocol_version": SESSION_PROTOCOL_VERSION,
        "run_id": manifest.run_id,
        "manifest_digest": manifest.manifest_digest,
        "source_revision": manifest.source_revision,
        "package_id": package.package_id,
        "package_digest": package.package_digest,
        "adapter_id": capabilities.adapter_id,
        "provider": capabilities.provider,
        "capability_digest": capabilities.capability_digest,
        "mode": mode,
        "dispatch_attempt": attempt,
    }


def compile_session_dispatch_request(
    manifest: RunManifest,
    ledger: RunLedger,
    *,
    domain_id: str,
    capabilities: RunnerCapabilities,
    mode: str = "execute",
) -> SessionDispatchRequest:
    accepted, reasons = verify_capabilities(capabilities)
    if not accepted:
        raise SessionError("invalid runner capabilities: " + "; ".join(reasons))
    if mode not in capabilities.modes:
        raise SessionError(f"runner does not support mode: {mode}")

    package = _package_for_domain(manifest, domain_id)
    states = replay_ledger(manifest, ledger)
    if states[domain_id] != PackageState.ISSUED:
        raise SessionError(
            f"package {domain_id} must be issued before session dispatch; "
            f"current state={states[domain_id].value}"
        )
    if package.write_scopes and not capabilities.supports_write:
        raise SessionError(f"runner {capabilities.adapter_id} cannot accept packages with write scopes")

    attempt = next_dispatch_attempt(manifest, ledger, domain_id)
    seed = _request_seed(manifest, package, capabilities, mode, attempt)
    dispatch_id = f"bcs-{sha256_digest(seed)[:20]}"
    unsigned = SessionDispatchRequest(
        schema_version=SESSION_SCHEMA_VERSION,
        session_protocol_version=SESSION_PROTOCOL_VERSION,
        dispatch_id=dispatch_id,
        dispatch_attempt=attempt,
        run_id=manifest.run_id,
        manifest_digest=manifest.manifest_digest,
        source_revision=manifest.source_revision,
        package_id=package.package_id,
        package_digest=package.package_digest,
        domain_id=package.domain_id,
        adapter_id=capabilities.adapter_id,
        provider=capabilities.provider,
        capability_digest=capabilities.capability_digest,
        mode=mode,
        objective=package.objective,
        dependencies=package.dependencies,
        write_scopes=package.write_scopes,
        exclusive_resources=package.exclusive_resources,
        invariants=package.invariants,
        forbidden_actions=package.forbidden_actions,
        gates=package.gates,
        request_digest="",
    )
    return SessionDispatchRequest(
        **{
            **asdict(unsigned),
            "dependencies": unsigned.dependencies,
            "write_scopes": unsigned.write_scopes,
            "exclusive_resources": unsigned.exclusive_resources,
            "invariants": unsigned.invariants,
            "forbidden_actions": unsigned.forbidden_actions,
            "gates": unsigned.gates,
            "request_digest": sha256_digest(_without(unsigned, "request_digest")),
        }
    )


def verify_session_dispatch_request(
    request: SessionDispatchRequest,
    manifest: RunManifest,
    package: WorkPackage,
    capabilities: RunnerCapabilities,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if request.schema_version != SESSION_SCHEMA_VERSION:
        reasons.append("unsupported session dispatch schema version")
    if request.session_protocol_version != SESSION_PROTOCOL_VERSION:
        reasons.append("unsupported session protocol version")
    if request.dispatch_attempt < 1:
        reasons.append("dispatch_attempt must be >= 1")
    if request.run_id != manifest.run_id or request.manifest_digest != manifest.manifest_digest:
        reasons.append("session dispatch is not bound to supplied manifest")
    if request.source_revision != manifest.source_revision:
        reasons.append("session dispatch source revision mismatch")
    if request.package_id != package.package_id or request.package_digest != package.package_digest:
        reasons.append("session dispatch package identity mismatch")
    if request.domain_id != package.domain_id:
        reasons.append("session dispatch domain mismatch")
    if request.adapter_id != capabilities.adapter_id or request.provider != capabilities.provider:
        reasons.append("session dispatch adapter/provider mismatch")
    if request.capability_digest != capabilities.capability_digest:
        reasons.append("session dispatch capability digest mismatch")
    if request.mode not in capabilities.modes:
        reasons.append("session dispatch mode is not supported by capabilities")
    if package.write_scopes and not capabilities.supports_write:
        reasons.append("runner capabilities do not permit required writes")

    seed = _request_seed(manifest, package, capabilities, request.mode, request.dispatch_attempt)
    if request.dispatch_id != f"bcs-{sha256_digest(seed)[:20]}":
        reasons.append("session dispatch_id does not match immutable attempt inputs")
    if request.objective != package.objective:
        reasons.append("session dispatch objective differs from Work Package")
    if request.dependencies != package.dependencies:
        reasons.append("session dispatch dependencies differ from Work Package")
    if request.write_scopes != package.write_scopes:
        reasons.append("session dispatch write scopes differ from Work Package")
    if request.exclusive_resources != package.exclusive_resources:
        reasons.append("session dispatch exclusive resources differ from Work Package")
    if request.invariants != package.invariants:
        reasons.append("session dispatch invariants differ from Work Package")
    if request.forbidden_actions != package.forbidden_actions:
        reasons.append("session dispatch forbidden actions differ from Work Package")
    if request.gates != package.gates:
        reasons.append("session dispatch evidence gates differ from Work Package")
    if request.request_digest != sha256_digest(_without(request, "request_digest")):
        reasons.append("session dispatch request digest mismatch")
    return not reasons, tuple(reasons)


def accept_session_dispatch(
    request: SessionDispatchRequest,
    capabilities: RunnerCapabilities,
    *,
    external_run_id: str,
) -> SessionDispatchReceipt:
    _validate_nonempty(external_run_id, "external_run_id")
    if request.adapter_id != capabilities.adapter_id or request.provider != capabilities.provider:
        raise SessionError("request adapter/provider does not match accepting capabilities")
    if request.capability_digest != capabilities.capability_digest:
        raise SessionError("request capability digest does not match accepting capabilities")
    if request.request_digest != sha256_digest(_without(request, "request_digest")):
        raise SessionError("session dispatch request digest mismatch")

    unsigned = SessionDispatchReceipt(
        schema_version=SESSION_SCHEMA_VERSION,
        session_protocol_version=SESSION_PROTOCOL_VERSION,
        dispatch_id=request.dispatch_id,
        dispatch_attempt=request.dispatch_attempt,
        run_id=request.run_id,
        manifest_digest=request.manifest_digest,
        package_id=request.package_id,
        package_digest=request.package_digest,
        adapter_id=capabilities.adapter_id,
        provider=capabilities.provider,
        capability_digest=capabilities.capability_digest,
        request_digest=request.request_digest,
        accepted=True,
        external_run_id=external_run_id,
        receipt_digest="",
    )
    return SessionDispatchReceipt(
        **{
            **asdict(unsigned),
            "receipt_digest": sha256_digest(_without(unsigned, "receipt_digest")),
        }
    )


def accept_reference_session_dispatch(request: SessionDispatchRequest) -> SessionDispatchReceipt:
    capabilities = reference_capabilities()
    if request.adapter_id != capabilities.adapter_id or request.capability_digest != capabilities.capability_digest:
        raise SessionError("session request is not addressed to reference adapter")
    external_run_id = f"refs-{sha256_digest({'dispatch_id': request.dispatch_id})[:20]}"
    return accept_session_dispatch(request, capabilities, external_run_id=external_run_id)


def verify_session_dispatch_receipt(
    receipt: SessionDispatchReceipt,
    request: SessionDispatchRequest,
    capabilities: RunnerCapabilities,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if not receipt.accepted:
        reasons.append("session dispatch receipt is not accepted")
    bindings = (
        (receipt.dispatch_id, request.dispatch_id, "dispatch_id"),
        (receipt.dispatch_attempt, request.dispatch_attempt, "dispatch_attempt"),
        (receipt.run_id, request.run_id, "run_id"),
        (receipt.manifest_digest, request.manifest_digest, "manifest_digest"),
        (receipt.package_id, request.package_id, "package_id"),
        (receipt.package_digest, request.package_digest, "package_digest"),
        (receipt.request_digest, request.request_digest, "request_digest"),
        (receipt.adapter_id, capabilities.adapter_id, "adapter_id"),
        (receipt.provider, capabilities.provider, "provider"),
        (receipt.capability_digest, capabilities.capability_digest, "capability_digest"),
    )
    for actual, expected, field in bindings:
        if actual != expected:
            reasons.append(f"session dispatch receipt {field} mismatch")
    if not isinstance(receipt.external_run_id, str) or not receipt.external_run_id.strip():
        reasons.append("session dispatch receipt external_run_id is empty")
    if receipt.receipt_digest != sha256_digest(_without(receipt, "receipt_digest")):
        reasons.append("session dispatch receipt digest mismatch")
    return not reasons, tuple(reasons)


def build_session_bundle(
    capabilities: RunnerCapabilities,
    request: SessionDispatchRequest,
    receipt: SessionDispatchReceipt,
) -> SessionDispatchBundle:
    accepted, reasons = verify_session_dispatch_receipt(receipt, request, capabilities)
    if not accepted:
        raise SessionError("invalid session dispatch receipt: " + "; ".join(reasons))
    unsigned = SessionDispatchBundle(
        schema_version=SESSION_SCHEMA_VERSION,
        session_protocol_version=SESSION_PROTOCOL_VERSION,
        capabilities=capabilities,
        request=request,
        receipt=receipt,
        bundle_digest="",
    )
    return SessionDispatchBundle(
        schema_version=unsigned.schema_version,
        session_protocol_version=unsigned.session_protocol_version,
        capabilities=capabilities,
        request=request,
        receipt=receipt,
        bundle_digest=sha256_digest(_without(unsigned, "bundle_digest")),
    )


def build_reference_session_bundle(
    manifest: RunManifest,
    ledger: RunLedger,
    *,
    domain_id: str,
    mode: str = "execute",
) -> SessionDispatchBundle:
    capabilities = reference_capabilities()
    request = compile_session_dispatch_request(
        manifest,
        ledger,
        domain_id=domain_id,
        capabilities=capabilities,
        mode=mode,
    )
    package = _package_for_domain(manifest, domain_id)
    accepted, reasons = verify_session_dispatch_request(request, manifest, package, capabilities)
    if not accepted:
        raise SessionError("reference session dispatch failed verification: " + "; ".join(reasons))
    receipt = accept_reference_session_dispatch(request)
    return build_session_bundle(capabilities, request, receipt)


def verify_session_bundle(
    bundle: SessionDispatchBundle,
    manifest: RunManifest,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    package = next((item for item in manifest.packages if item.package_id == bundle.request.package_id), None)
    if package is None:
        return False, ("session bundle references unknown package",)
    accepted, cap_reasons = verify_capabilities(bundle.capabilities)
    if not accepted:
        reasons.extend(cap_reasons)
    accepted, request_reasons = verify_session_dispatch_request(
        bundle.request, manifest, package, bundle.capabilities
    )
    if not accepted:
        reasons.extend(request_reasons)
    accepted, receipt_reasons = verify_session_dispatch_receipt(
        bundle.receipt, bundle.request, bundle.capabilities
    )
    if not accepted:
        reasons.extend(receipt_reasons)
    if bundle.bundle_digest != sha256_digest(_without(bundle, "bundle_digest")):
        reasons.append("session bundle digest mismatch")
    return not reasons, tuple(reasons)


def bind_session_dispatch(
    manifest: RunManifest,
    ledger: RunLedger,
    bundle: SessionDispatchBundle,
) -> RunLedger:
    accepted, reasons = verify_session_bundle(bundle, manifest)
    if not accepted:
        raise SessionError("invalid session dispatch bundle: " + "; ".join(reasons))
    expected_attempt = next_dispatch_attempt(manifest, ledger, bundle.request.domain_id)
    if bundle.request.dispatch_attempt != expected_attempt:
        raise SessionError(
            f"session attempt is stale; expected {expected_attempt}, got {bundle.request.dispatch_attempt}"
        )
    return append_event(
        manifest,
        ledger,
        package_id=bundle.request.package_id,
        role="coordinator",
        event_type=EventType.BIND_DISPATCH.value,
        payload={
            "dispatch_id": bundle.request.dispatch_id,
            "dispatch_receipt_digest": bundle.receipt.receipt_digest,
            "dispatch_attempt": bundle.request.dispatch_attempt,
            "session_bundle_digest": bundle.bundle_digest,
        },
    )


def start_session_dispatch(
    manifest: RunManifest,
    ledger: RunLedger,
    bundle: SessionDispatchBundle,
) -> RunLedger:
    accepted, reasons = verify_session_bundle(bundle, manifest)
    if not accepted:
        raise SessionError("invalid session dispatch bundle: " + "; ".join(reasons))
    return append_event(
        manifest,
        ledger,
        package_id=bundle.request.package_id,
        role="builder",
        event_type=EventType.START.value,
        payload={
            "dispatch_id": bundle.request.dispatch_id,
            "dispatch_receipt_digest": bundle.receipt.receipt_digest,
            "dispatch_attempt": bundle.request.dispatch_attempt,
            "session_bundle_digest": bundle.bundle_digest,
        },
    )


def revoke_session_dispatch(
    manifest: RunManifest,
    ledger: RunLedger,
    bundle: SessionDispatchBundle,
    *,
    reason: str,
) -> RunLedger:
    _validate_nonempty(reason, "reason")
    accepted, reasons = verify_session_bundle(bundle, manifest)
    if not accepted:
        raise SessionError("invalid session dispatch bundle: " + "; ".join(reasons))
    return append_event(
        manifest,
        ledger,
        package_id=bundle.request.package_id,
        role="coordinator",
        event_type=EventType.REVOKE_DISPATCH.value,
        payload={
            "dispatch_id": bundle.request.dispatch_id,
            "dispatch_receipt_digest": bundle.receipt.receipt_digest,
            "dispatch_attempt": bundle.request.dispatch_attempt,
            "session_bundle_digest": bundle.bundle_digest,
            "reason": reason,
        },
    )


def build_session_result_envelope(
    bundle: SessionDispatchBundle,
    manifest: RunManifest,
    *,
    outcome: str,
    revision: str | None = None,
    blocker_kind: str | None = None,
    evidence_locators: tuple[str, ...] = (),
) -> SessionResultEnvelope:
    accepted, reasons = verify_session_bundle(bundle, manifest)
    if not accepted:
        raise SessionError("invalid session dispatch bundle: " + "; ".join(reasons))
    package = _package_for_domain(manifest, bundle.request.domain_id)
    if outcome not in {"built", "blocked", "failed"}:
        raise SessionError("session runner outcome must be built, blocked, or failed")
    if any(not isinstance(locator, str) or not locator.strip() for locator in evidence_locators):
        raise SessionError("evidence locators must be non-empty strings")
    if outcome == "built":
        if not isinstance(revision, str) or not revision.strip():
            raise SessionError("built session result requires revision")
        if blocker_kind is not None:
            raise SessionError("built session result cannot include blocker_kind")
    elif outcome == "blocked":
        if revision is not None:
            raise SessionError("blocked session result cannot include revision")
        if blocker_kind not in package.permitted_blockers:
            raise SessionError(f"blocker kind {blocker_kind} is not permitted by Work Package")
    else:
        if revision is not None or blocker_kind is not None:
            raise SessionError("failed session result cannot include revision or blocker_kind")

    result_material = {
        "dispatch_id": bundle.request.dispatch_id,
        "dispatch_attempt": bundle.request.dispatch_attempt,
        "package_id": package.package_id,
        "package_digest": package.package_digest,
        "outcome": outcome,
        "revision": revision,
        "blocker_kind": blocker_kind,
        "evidence_locators": tuple(evidence_locators),
    }
    unsigned = SessionResultEnvelope(
        schema_version=SESSION_SCHEMA_VERSION,
        session_protocol_version=SESSION_PROTOCOL_VERSION,
        dispatch_id=bundle.request.dispatch_id,
        dispatch_attempt=bundle.request.dispatch_attempt,
        run_id=manifest.run_id,
        manifest_digest=manifest.manifest_digest,
        package_id=package.package_id,
        package_digest=package.package_digest,
        adapter_id=bundle.capabilities.adapter_id,
        provider=bundle.capabilities.provider,
        external_run_id=bundle.receipt.external_run_id,
        request_digest=bundle.request.request_digest,
        receipt_digest=bundle.receipt.receipt_digest,
        session_bundle_digest=bundle.bundle_digest,
        outcome=outcome,
        revision=revision,
        blocker_kind=blocker_kind,
        evidence_locators=tuple(evidence_locators),
        result_digest=sha256_digest(result_material),
        envelope_digest="",
    )
    return SessionResultEnvelope(
        **{
            **asdict(unsigned),
            "evidence_locators": unsigned.evidence_locators,
            "envelope_digest": sha256_digest(_without(unsigned, "envelope_digest")),
        }
    )


def verify_session_result_envelope(
    envelope: SessionResultEnvelope,
    bundle: SessionDispatchBundle,
    manifest: RunManifest,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    accepted, bundle_reasons = verify_session_bundle(bundle, manifest)
    if not accepted:
        reasons.extend(bundle_reasons)
    package = next((item for item in manifest.packages if item.package_id == envelope.package_id), None)
    if package is None:
        return False, tuple(reasons + ["session result references unknown package"])

    bindings = (
        (envelope.dispatch_id, bundle.request.dispatch_id, "dispatch_id"),
        (envelope.dispatch_attempt, bundle.request.dispatch_attempt, "dispatch_attempt"),
        (envelope.run_id, manifest.run_id, "run_id"),
        (envelope.manifest_digest, manifest.manifest_digest, "manifest_digest"),
        (envelope.package_id, bundle.request.package_id, "package_id"),
        (envelope.package_digest, bundle.request.package_digest, "package_digest"),
        (envelope.adapter_id, bundle.capabilities.adapter_id, "adapter_id"),
        (envelope.provider, bundle.capabilities.provider, "provider"),
        (envelope.external_run_id, bundle.receipt.external_run_id, "external_run_id"),
        (envelope.request_digest, bundle.request.request_digest, "request_digest"),
        (envelope.receipt_digest, bundle.receipt.receipt_digest, "receipt_digest"),
        (envelope.session_bundle_digest, bundle.bundle_digest, "session_bundle_digest"),
    )
    for actual, expected, field in bindings:
        if actual != expected:
            reasons.append(f"session result {field} mismatch")

    if envelope.outcome == "built":
        if not isinstance(envelope.revision, str) or not envelope.revision.strip():
            reasons.append("built session result requires revision")
        if envelope.blocker_kind is not None:
            reasons.append("built session result cannot include blocker_kind")
    elif envelope.outcome == "blocked":
        if envelope.revision is not None:
            reasons.append("blocked session result cannot include revision")
        if envelope.blocker_kind not in package.permitted_blockers:
            reasons.append("session result blocker_kind is not permitted by Work Package")
    elif envelope.outcome == "failed":
        if envelope.revision is not None or envelope.blocker_kind is not None:
            reasons.append("failed session result cannot include revision or blocker_kind")
    else:
        reasons.append("unknown session result outcome")

    material = {
        "dispatch_id": envelope.dispatch_id,
        "dispatch_attempt": envelope.dispatch_attempt,
        "package_id": envelope.package_id,
        "package_digest": envelope.package_digest,
        "outcome": envelope.outcome,
        "revision": envelope.revision,
        "blocker_kind": envelope.blocker_kind,
        "evidence_locators": envelope.evidence_locators,
    }
    if envelope.result_digest != sha256_digest(material):
        reasons.append("session result digest mismatch")
    if envelope.envelope_digest != sha256_digest(_without(envelope, "envelope_digest")):
        reasons.append("session result envelope digest mismatch")
    return not reasons, tuple(reasons)


def submit_session_result(
    manifest: RunManifest,
    ledger: RunLedger,
    bundle: SessionDispatchBundle,
    envelope: SessionResultEnvelope,
) -> RunLedger:
    accepted, reasons = verify_session_result_envelope(envelope, bundle, manifest)
    if not accepted:
        raise SessionError("invalid session result envelope: " + "; ".join(reasons))
    if envelope.outcome == "built":
        event_type = EventType.SUBMIT_BUILT.value
    elif envelope.outcome == "blocked":
        event_type = EventType.SUBMIT_BLOCKED.value
    else:
        event_type = EventType.SUBMIT_FAILED.value
    payload: dict[str, Any] = {
        "dispatch_id": envelope.dispatch_id,
        "dispatch_attempt": envelope.dispatch_attempt,
        "session_bundle_digest": envelope.session_bundle_digest,
        "result_envelope_digest": envelope.envelope_digest,
        "result_digest": envelope.result_digest,
    }
    if envelope.revision is not None:
        payload["revision"] = envelope.revision
    if envelope.blocker_kind is not None:
        payload["blocker_kind"] = envelope.blocker_kind
    return append_event(
        manifest,
        ledger,
        package_id=envelope.package_id,
        role="builder",
        event_type=event_type,
        payload=payload,
    )


def session_bundle_to_dict(bundle: SessionDispatchBundle) -> dict[str, Any]:
    return _normal(bundle)


def session_result_to_dict(envelope: SessionResultEnvelope) -> dict[str, Any]:
    return _normal(envelope)


def write_session_bundle(bundle: SessionDispatchBundle, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(session_bundle_to_dict(bundle), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_session_result(envelope: SessionResultEnvelope, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(session_result_to_dict(envelope), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _gate_from_dict(item: dict[str, Any]) -> EvidenceGate:
    return EvidenceGate(
        id=item["id"],
        description=item["description"],
        accepted_kinds=tuple(item["accepted_kinds"]),
        minimum=int(item.get("minimum", 1)),
    )


def session_bundle_from_dict(document: dict[str, Any]) -> SessionDispatchBundle:
    try:
        capabilities = RunnerCapabilities(**document["capabilities"])
        request_raw = dict(document["request"])
        request_raw["dependencies"] = tuple(request_raw["dependencies"])
        request_raw["write_scopes"] = tuple(request_raw["write_scopes"])
        request_raw["exclusive_resources"] = tuple(request_raw["exclusive_resources"])
        request_raw["invariants"] = tuple(request_raw["invariants"])
        request_raw["forbidden_actions"] = tuple(request_raw["forbidden_actions"])
        request_raw["gates"] = tuple(_gate_from_dict(item) for item in request_raw["gates"])
        request = SessionDispatchRequest(**request_raw)
        receipt = SessionDispatchReceipt(**document["receipt"])
        return SessionDispatchBundle(
            schema_version=int(document["schema_version"]),
            session_protocol_version=document["session_protocol_version"],
            capabilities=capabilities,
            request=request,
            receipt=receipt,
            bundle_digest=document["bundle_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SessionError(f"invalid session dispatch document: {exc}") from exc


def session_result_from_dict(document: dict[str, Any]) -> SessionResultEnvelope:
    try:
        raw = dict(document)
        raw["evidence_locators"] = tuple(raw["evidence_locators"])
        return SessionResultEnvelope(**raw)
    except (KeyError, TypeError, ValueError) as exc:
        raise SessionError(f"invalid session result document: {exc}") from exc


def load_session_bundle(path: str | Path) -> SessionDispatchBundle:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError(f"could not load session dispatch: {exc}") from exc
    if not isinstance(document, dict):
        raise SessionError("session dispatch root must be an object")
    return session_bundle_from_dict(document)


def load_session_result(path: str | Path) -> SessionResultEnvelope:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SessionError(f"could not load session result: {exc}") from exc
    if not isinstance(document, dict):
        raise SessionError("session result root must be an object")
    return session_result_from_dict(document)
