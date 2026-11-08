from __future__ import annotations

from .errors import SessionError
from .ledger import (
    append_event,
    current_dispatch_binding,
    execution_frontier,
    next_dispatch_attempt,
    replay_ledger,
)
from .protocol import RunManifest
from .runner_adapter import RunnerCapabilities, reference_capabilities
from .runner_session import (
    SESSION_PROTOCOL_VERSION,
    SESSION_SCHEMA_VERSION,
    SessionDispatchBundle,
    SessionDispatchReceipt,
    SessionDispatchRequest,
    SessionResultEnvelope,
    accept_reference_session_dispatch as _accept_reference_session_dispatch,
    accept_session_dispatch as _accept_session_dispatch,
    build_session_bundle as _build_session_bundle,
    build_session_result_envelope as _build_session_result_envelope,
    compile_session_dispatch_request as _compile_session_dispatch_request,
    revoke_session_dispatch as _revoke_session_dispatch,
    start_session_dispatch as _start_session_dispatch,
    submit_session_result as _submit_session_result,
    verify_session_bundle as _verify_session_bundle,
    verify_session_dispatch_receipt as _verify_session_dispatch_receipt,
    verify_session_dispatch_request,
    verify_session_result_envelope as _verify_session_result_envelope,
)
from .state_models import EventType, PackageState, RunLedger


def _version_reasons(schema_version: int, protocol_version: str, label: str) -> list[str]:
    reasons: list[str] = []
    if schema_version != SESSION_SCHEMA_VERSION:
        reasons.append(f"unsupported {label} schema version: {schema_version}")
    if protocol_version != SESSION_PROTOCOL_VERSION:
        reasons.append(f"unsupported {label} protocol version: {protocol_version}")
    return reasons


def _active_adapter_sessions(
    manifest: RunManifest,
    ledger: RunLedger,
    *,
    adapter_id: str,
) -> int:
    states = replay_ledger(manifest, ledger)
    count = 0
    for package in manifest.packages:
        if states[package.domain_id] not in {PackageState.DISPATCHED, PackageState.ACTIVE}:
            continue
        binding = current_dispatch_binding(manifest, ledger, package.domain_id)
        if binding is not None and binding.get("adapter_id") == adapter_id:
            count += 1
    return count


def _check_parallel_capacity(
    manifest: RunManifest,
    ledger: RunLedger,
    capabilities: RunnerCapabilities,
) -> None:
    active = _active_adapter_sessions(manifest, ledger, adapter_id=capabilities.adapter_id)
    if active >= capabilities.max_parallelism:
        raise SessionError(
            f"runner {capabilities.adapter_id} is at max_parallelism "
            f"({active}/{capabilities.max_parallelism})"
        )


def compile_session_dispatch_request(
    manifest: RunManifest,
    ledger: RunLedger,
    *,
    domain_id: str,
    capabilities: RunnerCapabilities,
    mode: str = "execute",
) -> SessionDispatchRequest:
    frontier = execution_frontier(manifest, ledger)
    if domain_id not in frontier.dispatchable:
        raise SessionError(
            f"package {domain_id} is not dispatchable on the current execution frontier"
        )
    _check_parallel_capacity(manifest, ledger, capabilities)
    return _compile_session_dispatch_request(
        manifest,
        ledger,
        domain_id=domain_id,
        capabilities=capabilities,
        mode=mode,
    )


def accept_session_dispatch(
    request: SessionDispatchRequest,
    capabilities: RunnerCapabilities,
    *,
    external_run_id: str,
) -> SessionDispatchReceipt:
    reasons = _version_reasons(
        request.schema_version,
        request.session_protocol_version,
        "session dispatch request",
    )
    if reasons:
        raise SessionError("; ".join(reasons))
    return _accept_session_dispatch(request, capabilities, external_run_id=external_run_id)


def accept_reference_session_dispatch(request: SessionDispatchRequest) -> SessionDispatchReceipt:
    reasons = _version_reasons(
        request.schema_version,
        request.session_protocol_version,
        "session dispatch request",
    )
    if reasons:
        raise SessionError("; ".join(reasons))
    return _accept_reference_session_dispatch(request)


def verify_session_dispatch_receipt(
    receipt: SessionDispatchReceipt,
    request: SessionDispatchRequest,
    capabilities: RunnerCapabilities,
) -> tuple[bool, tuple[str, ...]]:
    reasons = _version_reasons(
        receipt.schema_version,
        receipt.session_protocol_version,
        "session dispatch receipt",
    )
    accepted, base_reasons = _verify_session_dispatch_receipt(receipt, request, capabilities)
    if not accepted:
        reasons.extend(base_reasons)
    return not reasons, tuple(dict.fromkeys(reasons))


def build_session_bundle(
    capabilities: RunnerCapabilities,
    request: SessionDispatchRequest,
    receipt: SessionDispatchReceipt,
) -> SessionDispatchBundle:
    accepted, reasons = verify_session_dispatch_receipt(receipt, request, capabilities)
    if not accepted:
        raise SessionError("invalid session dispatch receipt: " + "; ".join(reasons))
    bundle = _build_session_bundle(capabilities, request, receipt)
    reasons = _version_reasons(
        bundle.schema_version,
        bundle.session_protocol_version,
        "session dispatch bundle",
    )
    if reasons:
        raise SessionError("; ".join(reasons))
    return bundle


def verify_session_bundle(
    bundle: SessionDispatchBundle,
    manifest: RunManifest,
) -> tuple[bool, tuple[str, ...]]:
    reasons = _version_reasons(
        bundle.schema_version,
        bundle.session_protocol_version,
        "session dispatch bundle",
    )
    reasons.extend(
        _version_reasons(
            bundle.request.schema_version,
            bundle.request.session_protocol_version,
            "session dispatch request",
        )
    )
    reasons.extend(
        _version_reasons(
            bundle.receipt.schema_version,
            bundle.receipt.session_protocol_version,
            "session dispatch receipt",
        )
    )
    accepted, base_reasons = _verify_session_bundle(bundle, manifest)
    if not accepted:
        reasons.extend(base_reasons)
    return not reasons, tuple(dict.fromkeys(reasons))


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
    package = next(item for item in manifest.packages if item.domain_id == domain_id)
    accepted, reasons = verify_session_dispatch_request(request, manifest, package, capabilities)
    if not accepted:
        raise SessionError("reference session request failed verification: " + "; ".join(reasons))
    receipt = accept_reference_session_dispatch(request)
    bundle = build_session_bundle(capabilities, request, receipt)
    accepted, reasons = verify_session_bundle(bundle, manifest)
    if not accepted:
        raise SessionError("reference session bundle failed verification: " + "; ".join(reasons))
    return bundle


def bind_session_dispatch(
    manifest: RunManifest,
    ledger: RunLedger,
    bundle: SessionDispatchBundle,
) -> RunLedger:
    accepted, reasons = verify_session_bundle(bundle, manifest)
    if not accepted:
        raise SessionError("invalid session dispatch bundle: " + "; ".join(reasons))
    frontier = execution_frontier(manifest, ledger)
    if bundle.request.domain_id not in frontier.dispatchable:
        raise SessionError(
            f"package {bundle.request.domain_id} is not dispatchable on the current execution frontier"
        )
    _check_parallel_capacity(manifest, ledger, bundle.capabilities)
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
            "adapter_id": bundle.capabilities.adapter_id,
            "provider": bundle.capabilities.provider,
            "capability_digest": bundle.capabilities.capability_digest,
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
    return _start_session_dispatch(manifest, ledger, bundle)


def revoke_session_dispatch(
    manifest: RunManifest,
    ledger: RunLedger,
    bundle: SessionDispatchBundle,
    *,
    reason: str,
) -> RunLedger:
    accepted, reasons = verify_session_bundle(bundle, manifest)
    if not accepted:
        raise SessionError("invalid session dispatch bundle: " + "; ".join(reasons))
    return _revoke_session_dispatch(manifest, ledger, bundle, reason=reason)


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
    envelope = _build_session_result_envelope(
        bundle,
        manifest,
        outcome=outcome,
        revision=revision,
        blocker_kind=blocker_kind,
        evidence_locators=evidence_locators,
    )
    accepted, reasons = verify_session_result_envelope(envelope, bundle, manifest)
    if not accepted:
        raise SessionError("invalid session result envelope: " + "; ".join(reasons))
    return envelope


def verify_session_result_envelope(
    envelope: SessionResultEnvelope,
    bundle: SessionDispatchBundle,
    manifest: RunManifest,
) -> tuple[bool, tuple[str, ...]]:
    reasons = _version_reasons(
        envelope.schema_version,
        envelope.session_protocol_version,
        "session result envelope",
    )
    accepted, bundle_reasons = verify_session_bundle(bundle, manifest)
    if not accepted:
        reasons.extend(bundle_reasons)
    accepted, base_reasons = _verify_session_result_envelope(envelope, bundle, manifest)
    if not accepted:
        reasons.extend(base_reasons)
    return not reasons, tuple(dict.fromkeys(reasons))


def submit_session_result(
    manifest: RunManifest,
    ledger: RunLedger,
    bundle: SessionDispatchBundle,
    envelope: SessionResultEnvelope,
) -> RunLedger:
    accepted, reasons = verify_session_result_envelope(envelope, bundle, manifest)
    if not accepted:
        raise SessionError("invalid session result envelope: " + "; ".join(reasons))
    return _submit_session_result(manifest, ledger, bundle, envelope)
