from __future__ import annotations

from .errors import AdapterError
from .ledger import execution_frontier
from .protocol import RunManifest
from .runner_adapter import (
    ADAPTER_PROTOCOL_VERSION,
    ADAPTER_SCHEMA_VERSION,
    DispatchBundle,
    DispatchReceipt,
    DispatchRequest,
    RunnerCapabilities,
    RunnerResultEnvelope,
    accept_dispatch as _accept_dispatch,
    accept_reference_dispatch as _accept_reference_dispatch,
    build_dispatch_bundle as _build_dispatch_bundle,
    build_result_envelope as _build_result_envelope,
    compile_dispatch_request as _compile_dispatch_request,
    reference_capabilities,
    verify_dispatch_bundle as _verify_dispatch_bundle,
    verify_dispatch_receipt as _verify_dispatch_receipt,
    verify_dispatch_request,
    verify_result_envelope as _verify_result_envelope,
)
from .state_models import RunLedger


def _version_reasons(schema_version: int, protocol_version: str, label: str) -> list[str]:
    reasons: list[str] = []
    if schema_version != ADAPTER_SCHEMA_VERSION:
        reasons.append(f"unsupported {label} schema version: {schema_version}")
    if protocol_version != ADAPTER_PROTOCOL_VERSION:
        reasons.append(f"unsupported {label} protocol version: {protocol_version}")
    return reasons


def compile_dispatch_request(
    manifest: RunManifest,
    ledger: RunLedger,
    *,
    domain_id: str,
    capabilities: RunnerCapabilities,
    mode: str = "execute",
) -> DispatchRequest:
    frontier = execution_frontier(manifest, ledger)
    if domain_id not in frontier.dispatchable:
        raise AdapterError(
            f"package {domain_id} is not dispatchable on the current execution frontier"
        )
    return _compile_dispatch_request(
        manifest,
        ledger,
        domain_id=domain_id,
        capabilities=capabilities,
        mode=mode,
    )


def accept_dispatch(
    request: DispatchRequest,
    capabilities: RunnerCapabilities,
    *,
    external_run_id: str,
) -> DispatchReceipt:
    reasons = _version_reasons(
        request.schema_version,
        request.adapter_protocol_version,
        "dispatch request",
    )
    if reasons:
        raise AdapterError("; ".join(reasons))
    return _accept_dispatch(request, capabilities, external_run_id=external_run_id)


def accept_reference_dispatch(request: DispatchRequest) -> DispatchReceipt:
    reasons = _version_reasons(
        request.schema_version,
        request.adapter_protocol_version,
        "dispatch request",
    )
    if reasons:
        raise AdapterError("; ".join(reasons))
    return _accept_reference_dispatch(request)


def verify_dispatch_receipt(
    receipt: DispatchReceipt,
    request: DispatchRequest,
    capabilities: RunnerCapabilities,
) -> tuple[bool, tuple[str, ...]]:
    reasons = _version_reasons(
        receipt.schema_version,
        receipt.adapter_protocol_version,
        "dispatch receipt",
    )
    accepted, base_reasons = _verify_dispatch_receipt(receipt, request, capabilities)
    if not accepted:
        reasons.extend(base_reasons)
    return not reasons, tuple(dict.fromkeys(reasons))


def build_dispatch_bundle(
    capabilities: RunnerCapabilities,
    request: DispatchRequest,
    receipt: DispatchReceipt,
) -> DispatchBundle:
    accepted, reasons = verify_dispatch_receipt(receipt, request, capabilities)
    if not accepted:
        raise AdapterError("invalid dispatch receipt: " + "; ".join(reasons))
    bundle = _build_dispatch_bundle(capabilities, request, receipt)
    reasons = _version_reasons(
        bundle.schema_version,
        bundle.adapter_protocol_version,
        "dispatch bundle",
    )
    if reasons:
        raise AdapterError("; ".join(reasons))
    return bundle


def verify_dispatch_bundle(
    bundle: DispatchBundle,
    manifest: RunManifest,
) -> tuple[bool, tuple[str, ...]]:
    reasons = _version_reasons(
        bundle.schema_version,
        bundle.adapter_protocol_version,
        "dispatch bundle",
    )
    reasons.extend(
        _version_reasons(
            bundle.receipt.schema_version,
            bundle.receipt.adapter_protocol_version,
            "dispatch receipt",
        )
    )
    accepted, base_reasons = _verify_dispatch_bundle(bundle, manifest)
    if not accepted:
        reasons.extend(base_reasons)
    return not reasons, tuple(dict.fromkeys(reasons))


def build_reference_dispatch_bundle(
    manifest: RunManifest,
    ledger: RunLedger,
    *,
    domain_id: str,
    mode: str = "execute",
) -> DispatchBundle:
    capabilities = reference_capabilities()
    request = compile_dispatch_request(
        manifest,
        ledger,
        domain_id=domain_id,
        capabilities=capabilities,
        mode=mode,
    )
    package = next(item for item in manifest.packages if item.domain_id == domain_id)
    accepted, reasons = verify_dispatch_request(request, manifest, package, capabilities)
    if not accepted:
        raise AdapterError("reference dispatch request failed verification: " + "; ".join(reasons))
    receipt = accept_reference_dispatch(request)
    bundle = build_dispatch_bundle(capabilities, request, receipt)
    accepted, reasons = verify_dispatch_bundle(bundle, manifest)
    if not accepted:
        raise AdapterError("reference dispatch bundle failed verification: " + "; ".join(reasons))
    return bundle


def build_result_envelope(
    bundle: DispatchBundle,
    manifest: RunManifest,
    *,
    outcome: str,
    revision: str | None = None,
    blocker_kind: str | None = None,
    evidence_locators: tuple[str, ...] = (),
) -> RunnerResultEnvelope:
    accepted, reasons = verify_dispatch_bundle(bundle, manifest)
    if not accepted:
        raise AdapterError("invalid dispatch bundle: " + "; ".join(reasons))
    envelope = _build_result_envelope(
        bundle,
        manifest,
        outcome=outcome,
        revision=revision,
        blocker_kind=blocker_kind,
        evidence_locators=evidence_locators,
    )
    accepted, reasons = verify_result_envelope(envelope, bundle, manifest)
    if not accepted:
        raise AdapterError("invalid runner result envelope: " + "; ".join(reasons))
    return envelope


def verify_result_envelope(
    envelope: RunnerResultEnvelope,
    bundle: DispatchBundle,
    manifest: RunManifest,
) -> tuple[bool, tuple[str, ...]]:
    reasons = _version_reasons(
        envelope.schema_version,
        envelope.adapter_protocol_version,
        "runner result envelope",
    )
    accepted, bundle_reasons = verify_dispatch_bundle(bundle, manifest)
    if not accepted:
        reasons.extend(bundle_reasons)
    accepted, base_reasons = _verify_result_envelope(envelope, bundle, manifest)
    if not accepted:
        reasons.extend(base_reasons)
    return not reasons, tuple(dict.fromkeys(reasons))
