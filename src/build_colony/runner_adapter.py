from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import AdapterError
from .ledger import replay_ledger
from .models import EvidenceGate
from .protocol import RunManifest, WorkPackage, canonical_json, sha256_digest
from .state_models import PackageState, RunLedger

ADAPTER_PROTOCOL_VERSION = "0.0.4"
ADAPTER_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class RunnerCapabilities:
    adapter_id: str
    provider: str
    adapter_version: str
    modes: tuple[str, ...]
    supports_write: bool
    supports_artifact_refs: bool
    max_parallelism: int
    capability_digest: str


@dataclass(frozen=True)
class DispatchRequest:
    schema_version: int
    adapter_protocol_version: str
    dispatch_id: str
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
class DispatchReceipt:
    schema_version: int
    adapter_protocol_version: str
    dispatch_id: str
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
class DispatchBundle:
    schema_version: int
    adapter_protocol_version: str
    capabilities: RunnerCapabilities
    request: DispatchRequest
    receipt: DispatchReceipt
    bundle_digest: str


@dataclass(frozen=True)
class RunnerResultEnvelope:
    schema_version: int
    adapter_protocol_version: str
    dispatch_id: str
    run_id: str
    manifest_digest: str
    package_id: str
    package_digest: str
    adapter_id: str
    provider: str
    external_run_id: str
    request_digest: str
    receipt_digest: str
    outcome: str
    revision: str | None
    blocker_kind: str | None
    evidence_locators: tuple[str, ...]
    result_digest: str
    envelope_digest: str


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


def _validate_sha256(value: str, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise AdapterError(f"{field} must be a 64-character SHA-256 hex digest")
    if any(character not in "0123456789abcdef" for character in value.lower()):
        raise AdapterError(f"{field} must be a 64-character SHA-256 hex digest")


def _validate_nonempty(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(f"{field} must be a non-empty string")


def capabilities_digest(capabilities: RunnerCapabilities | dict[str, Any]) -> str:
    return sha256_digest(_without(capabilities, "capability_digest"))


def make_capabilities(
    *,
    adapter_id: str,
    provider: str,
    adapter_version: str,
    modes: tuple[str, ...],
    supports_write: bool,
    supports_artifact_refs: bool,
    max_parallelism: int,
) -> RunnerCapabilities:
    for value, field in (
        (adapter_id, "adapter_id"),
        (provider, "provider"),
        (adapter_version, "adapter_version"),
    ):
        _validate_nonempty(value, field)
    if not modes or any(not isinstance(mode, str) or not mode.strip() for mode in modes):
        raise AdapterError("modes must contain at least one non-empty mode")
    if len(set(modes)) != len(modes):
        raise AdapterError("modes must be unique")
    if max_parallelism < 1:
        raise AdapterError("max_parallelism must be >= 1")

    unsigned = RunnerCapabilities(
        adapter_id=adapter_id,
        provider=provider,
        adapter_version=adapter_version,
        modes=tuple(sorted(modes)),
        supports_write=bool(supports_write),
        supports_artifact_refs=bool(supports_artifact_refs),
        max_parallelism=int(max_parallelism),
        capability_digest="",
    )
    return RunnerCapabilities(
        **{
            **asdict(unsigned),
            "modes": unsigned.modes,
            "capability_digest": capabilities_digest(unsigned),
        }
    )


def reference_capabilities() -> RunnerCapabilities:
    return make_capabilities(
        adapter_id="reference-loopback",
        provider="build-colony-reference",
        adapter_version=ADAPTER_PROTOCOL_VERSION,
        modes=("execute", "reproduce"),
        supports_write=True,
        supports_artifact_refs=True,
        max_parallelism=64,
    )


def verify_capabilities(capabilities: RunnerCapabilities) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    try:
        expected = capabilities_digest(capabilities)
        _validate_sha256(capabilities.capability_digest, "capability_digest")
    except AdapterError as exc:
        reasons.append(str(exc))
    else:
        if capabilities.capability_digest != expected:
            reasons.append("capability digest mismatch")
    if not capabilities.modes:
        reasons.append("capabilities expose no execution mode")
    if capabilities.max_parallelism < 1:
        reasons.append("max_parallelism must be >= 1")
    return not reasons, tuple(reasons)


def _package_for_domain(manifest: RunManifest, domain_id: str) -> WorkPackage:
    package = next((item for item in manifest.packages if item.domain_id == domain_id), None)
    if package is None:
        raise AdapterError(f"unknown domain: {domain_id}")
    return package


def _request_seed(
    manifest: RunManifest,
    package: WorkPackage,
    capabilities: RunnerCapabilities,
    mode: str,
) -> dict[str, Any]:
    return {
        "adapter_protocol_version": ADAPTER_PROTOCOL_VERSION,
        "run_id": manifest.run_id,
        "manifest_digest": manifest.manifest_digest,
        "source_revision": manifest.source_revision,
        "package_id": package.package_id,
        "package_digest": package.package_digest,
        "adapter_id": capabilities.adapter_id,
        "provider": capabilities.provider,
        "capability_digest": capabilities.capability_digest,
        "mode": mode,
    }


def compile_dispatch_request(
    manifest: RunManifest,
    ledger: RunLedger,
    *,
    domain_id: str,
    capabilities: RunnerCapabilities,
    mode: str = "execute",
) -> DispatchRequest:
    accepted, reasons = verify_capabilities(capabilities)
    if not accepted:
        raise AdapterError("invalid runner capabilities: " + "; ".join(reasons))
    if mode not in capabilities.modes:
        raise AdapterError(f"runner does not support mode: {mode}")

    package = _package_for_domain(manifest, domain_id)
    states = replay_ledger(manifest, ledger)
    if states[domain_id] != PackageState.ISSUED:
        raise AdapterError(
            f"package {domain_id} must be issued before dispatch; current state={states[domain_id].value}"
        )
    if package.write_scopes and not capabilities.supports_write:
        raise AdapterError(f"runner {capabilities.adapter_id} cannot accept packages with write scopes")

    dispatch_id = f"bcd-{sha256_digest(_request_seed(manifest, package, capabilities, mode))[:20]}"
    unsigned = DispatchRequest(
        schema_version=ADAPTER_SCHEMA_VERSION,
        adapter_protocol_version=ADAPTER_PROTOCOL_VERSION,
        dispatch_id=dispatch_id,
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
    return DispatchRequest(
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


def verify_dispatch_request(
    request: DispatchRequest,
    manifest: RunManifest,
    package: WorkPackage,
    capabilities: RunnerCapabilities,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if request.schema_version != ADAPTER_SCHEMA_VERSION:
        reasons.append("unsupported dispatch schema version")
    if request.adapter_protocol_version != ADAPTER_PROTOCOL_VERSION:
        reasons.append("unsupported adapter protocol version")
    if request.run_id != manifest.run_id or request.manifest_digest != manifest.manifest_digest:
        reasons.append("dispatch is not bound to the supplied manifest")
    if request.source_revision != manifest.source_revision:
        reasons.append("dispatch source revision mismatch")
    if request.package_id != package.package_id or request.package_digest != package.package_digest:
        reasons.append("dispatch package identity mismatch")
    if request.domain_id != package.domain_id:
        reasons.append("dispatch domain mismatch")
    if request.adapter_id != capabilities.adapter_id or request.provider != capabilities.provider:
        reasons.append("dispatch adapter/provider mismatch")
    if request.capability_digest != capabilities.capability_digest:
        reasons.append("dispatch capability digest mismatch")
    if request.mode not in capabilities.modes:
        reasons.append("dispatch mode is not supported by capabilities")
    if package.write_scopes and not capabilities.supports_write:
        reasons.append("runner capabilities do not permit required writes")

    expected_seed = _request_seed(manifest, package, capabilities, request.mode)
    if request.dispatch_id != f"bcd-{sha256_digest(expected_seed)[:20]}":
        reasons.append("dispatch_id does not match immutable dispatch inputs")
    if request.objective != package.objective:
        reasons.append("dispatch objective differs from Work Package")
    if request.dependencies != package.dependencies:
        reasons.append("dispatch dependencies differ from Work Package")
    if request.write_scopes != package.write_scopes:
        reasons.append("dispatch write scopes differ from Work Package")
    if request.exclusive_resources != package.exclusive_resources:
        reasons.append("dispatch exclusive resources differ from Work Package")
    if request.invariants != package.invariants:
        reasons.append("dispatch invariants differ from Work Package")
    if request.forbidden_actions != package.forbidden_actions:
        reasons.append("dispatch forbidden actions differ from Work Package")
    if request.gates != package.gates:
        reasons.append("dispatch evidence gates differ from Work Package")

    expected_digest = sha256_digest(_without(request, "request_digest"))
    if request.request_digest != expected_digest:
        reasons.append("dispatch request digest mismatch")
    return not reasons, tuple(reasons)


def accept_dispatch(
    request: DispatchRequest,
    capabilities: RunnerCapabilities,
    *,
    external_run_id: str,
) -> DispatchReceipt:
    _validate_nonempty(external_run_id, "external_run_id")
    if request.adapter_id != capabilities.adapter_id or request.provider != capabilities.provider:
        raise AdapterError("request adapter/provider does not match accepting capabilities")
    if request.capability_digest != capabilities.capability_digest:
        raise AdapterError("request capability digest does not match accepting capabilities")
    expected_request_digest = sha256_digest(_without(request, "request_digest"))
    if request.request_digest != expected_request_digest:
        raise AdapterError("dispatch request digest mismatch")

    unsigned = DispatchReceipt(
        schema_version=ADAPTER_SCHEMA_VERSION,
        adapter_protocol_version=ADAPTER_PROTOCOL_VERSION,
        dispatch_id=request.dispatch_id,
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
    return DispatchReceipt(
        **{
            **asdict(unsigned),
            "receipt_digest": sha256_digest(_without(unsigned, "receipt_digest")),
        }
    )


def accept_reference_dispatch(request: DispatchRequest) -> DispatchReceipt:
    capabilities = reference_capabilities()
    if request.adapter_id != capabilities.adapter_id or request.capability_digest != capabilities.capability_digest:
        raise AdapterError("request is not addressed to the reference adapter")
    external_run_id = f"ref-{sha256_digest({'dispatch_id': request.dispatch_id})[:20]}"
    return accept_dispatch(request, capabilities, external_run_id=external_run_id)


def verify_dispatch_receipt(
    receipt: DispatchReceipt,
    request: DispatchRequest,
    capabilities: RunnerCapabilities,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if not receipt.accepted:
        reasons.append("dispatch receipt is not accepted")
    bindings = (
        (receipt.dispatch_id, request.dispatch_id, "dispatch_id"),
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
            reasons.append(f"dispatch receipt {field} mismatch")
    if not isinstance(receipt.external_run_id, str) or not receipt.external_run_id.strip():
        reasons.append("dispatch receipt external_run_id is empty")
    if receipt.receipt_digest != sha256_digest(_without(receipt, "receipt_digest")):
        reasons.append("dispatch receipt digest mismatch")
    return not reasons, tuple(reasons)


def build_dispatch_bundle(
    capabilities: RunnerCapabilities,
    request: DispatchRequest,
    receipt: DispatchReceipt,
) -> DispatchBundle:
    accepted, reasons = verify_dispatch_receipt(receipt, request, capabilities)
    if not accepted:
        raise AdapterError("invalid dispatch receipt: " + "; ".join(reasons))
    unsigned = DispatchBundle(
        schema_version=ADAPTER_SCHEMA_VERSION,
        adapter_protocol_version=ADAPTER_PROTOCOL_VERSION,
        capabilities=capabilities,
        request=request,
        receipt=receipt,
        bundle_digest="",
    )
    return DispatchBundle(
        capabilities=capabilities,
        request=request,
        receipt=receipt,
        schema_version=unsigned.schema_version,
        adapter_protocol_version=unsigned.adapter_protocol_version,
        bundle_digest=sha256_digest(_without(unsigned, "bundle_digest")),
    )


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
    package = _package_for_domain(manifest, domain_id)
    accepted, reasons = verify_dispatch_request(request, manifest, package, capabilities)
    if not accepted:
        raise AdapterError("reference dispatch request failed verification: " + "; ".join(reasons))
    receipt = accept_reference_dispatch(request)
    return build_dispatch_bundle(capabilities, request, receipt)


def verify_dispatch_bundle(
    bundle: DispatchBundle,
    manifest: RunManifest,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    package = next((item for item in manifest.packages if item.package_id == bundle.request.package_id), None)
    if package is None:
        return False, ("dispatch bundle references an unknown package",)
    accepted, capability_reasons = verify_capabilities(bundle.capabilities)
    if not accepted:
        reasons.extend(capability_reasons)
    accepted, request_reasons = verify_dispatch_request(
        bundle.request, manifest, package, bundle.capabilities
    )
    if not accepted:
        reasons.extend(request_reasons)
    accepted, receipt_reasons = verify_dispatch_receipt(
        bundle.receipt, bundle.request, bundle.capabilities
    )
    if not accepted:
        reasons.extend(receipt_reasons)
    if bundle.bundle_digest != sha256_digest(_without(bundle, "bundle_digest")):
        reasons.append("dispatch bundle digest mismatch")
    return not reasons, tuple(reasons)


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
    package = _package_for_domain(manifest, bundle.request.domain_id)
    if outcome not in {"built", "blocked", "failed"}:
        raise AdapterError("runner outcome must be built, blocked, or failed")
    if any(not isinstance(locator, str) or not locator.strip() for locator in evidence_locators):
        raise AdapterError("evidence locators must be non-empty strings")
    if outcome == "built":
        if not isinstance(revision, str) or not revision.strip():
            raise AdapterError("built runner result requires revision")
        if blocker_kind is not None:
            raise AdapterError("built runner result cannot include blocker_kind")
    elif outcome == "blocked":
        if revision is not None:
            raise AdapterError("blocked runner result cannot include revision")
        if blocker_kind not in package.permitted_blockers:
            raise AdapterError(f"blocker kind {blocker_kind} is not permitted by Work Package")
    else:
        if revision is not None or blocker_kind is not None:
            raise AdapterError("failed runner result cannot include revision or blocker_kind")

    result_material = {
        "dispatch_id": bundle.request.dispatch_id,
        "package_id": package.package_id,
        "package_digest": package.package_digest,
        "outcome": outcome,
        "revision": revision,
        "blocker_kind": blocker_kind,
        "evidence_locators": tuple(evidence_locators),
    }
    result_digest = sha256_digest(result_material)
    unsigned = RunnerResultEnvelope(
        schema_version=ADAPTER_SCHEMA_VERSION,
        adapter_protocol_version=ADAPTER_PROTOCOL_VERSION,
        dispatch_id=bundle.request.dispatch_id,
        run_id=manifest.run_id,
        manifest_digest=manifest.manifest_digest,
        package_id=package.package_id,
        package_digest=package.package_digest,
        adapter_id=bundle.capabilities.adapter_id,
        provider=bundle.capabilities.provider,
        external_run_id=bundle.receipt.external_run_id,
        request_digest=bundle.request.request_digest,
        receipt_digest=bundle.receipt.receipt_digest,
        outcome=outcome,
        revision=revision,
        blocker_kind=blocker_kind,
        evidence_locators=tuple(evidence_locators),
        result_digest=result_digest,
        envelope_digest="",
    )
    return RunnerResultEnvelope(
        **{
            **asdict(unsigned),
            "evidence_locators": unsigned.evidence_locators,
            "envelope_digest": sha256_digest(_without(unsigned, "envelope_digest")),
        }
    )


def verify_result_envelope(
    envelope: RunnerResultEnvelope,
    bundle: DispatchBundle,
    manifest: RunManifest,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    accepted, bundle_reasons = verify_dispatch_bundle(bundle, manifest)
    if not accepted:
        reasons.extend(bundle_reasons)
    package = next((item for item in manifest.packages if item.package_id == envelope.package_id), None)
    if package is None:
        return False, tuple(reasons + ["result envelope references unknown package"])

    bindings = (
        (envelope.dispatch_id, bundle.request.dispatch_id, "dispatch_id"),
        (envelope.run_id, manifest.run_id, "run_id"),
        (envelope.manifest_digest, manifest.manifest_digest, "manifest_digest"),
        (envelope.package_id, bundle.request.package_id, "package_id"),
        (envelope.package_digest, bundle.request.package_digest, "package_digest"),
        (envelope.adapter_id, bundle.capabilities.adapter_id, "adapter_id"),
        (envelope.provider, bundle.capabilities.provider, "provider"),
        (envelope.external_run_id, bundle.receipt.external_run_id, "external_run_id"),
        (envelope.request_digest, bundle.request.request_digest, "request_digest"),
        (envelope.receipt_digest, bundle.receipt.receipt_digest, "receipt_digest"),
    )
    for actual, expected, field in bindings:
        if actual != expected:
            reasons.append(f"result envelope {field} mismatch")

    if envelope.outcome == "built":
        if not isinstance(envelope.revision, str) or not envelope.revision.strip():
            reasons.append("built result envelope requires revision")
        if envelope.blocker_kind is not None:
            reasons.append("built result envelope cannot include blocker_kind")
    elif envelope.outcome == "blocked":
        if envelope.revision is not None:
            reasons.append("blocked result envelope cannot include revision")
        if envelope.blocker_kind not in package.permitted_blockers:
            reasons.append("result envelope blocker_kind is not permitted by Work Package")
    elif envelope.outcome == "failed":
        if envelope.revision is not None or envelope.blocker_kind is not None:
            reasons.append("failed result envelope cannot include revision or blocker_kind")
    else:
        reasons.append("unknown result envelope outcome")

    result_material = {
        "dispatch_id": envelope.dispatch_id,
        "package_id": envelope.package_id,
        "package_digest": envelope.package_digest,
        "outcome": envelope.outcome,
        "revision": envelope.revision,
        "blocker_kind": envelope.blocker_kind,
        "evidence_locators": envelope.evidence_locators,
    }
    if envelope.result_digest != sha256_digest(result_material):
        reasons.append("result envelope result_digest mismatch")
    if envelope.envelope_digest != sha256_digest(_without(envelope, "envelope_digest")):
        reasons.append("result envelope digest mismatch")
    return not reasons, tuple(reasons)


def dispatch_binding_payload(bundle: DispatchBundle) -> dict[str, Any]:
    return {
        "dispatch_id": bundle.request.dispatch_id,
        "dispatch_receipt_digest": bundle.receipt.receipt_digest,
    }


def builder_start_payload(bundle: DispatchBundle) -> dict[str, Any]:
    return dispatch_binding_payload(bundle)


def builder_submission_payload(envelope: RunnerResultEnvelope) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "dispatch_id": envelope.dispatch_id,
        "result_envelope_digest": envelope.envelope_digest,
        "result_digest": envelope.result_digest,
    }
    if envelope.outcome == "built":
        payload["revision"] = envelope.revision
    elif envelope.outcome == "blocked":
        payload["blocker_kind"] = envelope.blocker_kind
    return payload


def _capabilities_from_dict(item: dict[str, Any]) -> RunnerCapabilities:
    return RunnerCapabilities(
        adapter_id=item["adapter_id"],
        provider=item["provider"],
        adapter_version=item["adapter_version"],
        modes=tuple(item["modes"]),
        supports_write=bool(item["supports_write"]),
        supports_artifact_refs=bool(item["supports_artifact_refs"]),
        max_parallelism=int(item["max_parallelism"]),
        capability_digest=item["capability_digest"],
    )


def _request_from_dict(item: dict[str, Any]) -> DispatchRequest:
    gates = tuple(
        EvidenceGate(
            id=gate["id"],
            description=gate["description"],
            accepted_kinds=tuple(gate["accepted_kinds"]),
            minimum=int(gate.get("minimum", 1)),
        )
        for gate in item["gates"]
    )
    return DispatchRequest(
        schema_version=int(item["schema_version"]),
        adapter_protocol_version=item["adapter_protocol_version"],
        dispatch_id=item["dispatch_id"],
        run_id=item["run_id"],
        manifest_digest=item["manifest_digest"],
        source_revision=item["source_revision"],
        package_id=item["package_id"],
        package_digest=item["package_digest"],
        domain_id=item["domain_id"],
        adapter_id=item["adapter_id"],
        provider=item["provider"],
        capability_digest=item["capability_digest"],
        mode=item["mode"],
        objective=item["objective"],
        dependencies=tuple(item["dependencies"]),
        write_scopes=tuple(item["write_scopes"]),
        exclusive_resources=tuple(item["exclusive_resources"]),
        invariants=tuple(item["invariants"]),
        forbidden_actions=tuple(item["forbidden_actions"]),
        gates=gates,
        request_digest=item["request_digest"],
    )


def _receipt_from_dict(item: dict[str, Any]) -> DispatchReceipt:
    return DispatchReceipt(**item)


def dispatch_bundle_to_dict(bundle: DispatchBundle) -> dict[str, Any]:
    return _normal(bundle)


def dispatch_bundle_from_document(document: dict[str, Any]) -> DispatchBundle:
    try:
        capabilities = _capabilities_from_dict(document["capabilities"])
        request = _request_from_dict(document["request"])
        receipt = _receipt_from_dict(document["receipt"])
        return DispatchBundle(
            schema_version=int(document["schema_version"]),
            adapter_protocol_version=document["adapter_protocol_version"],
            capabilities=capabilities,
            request=request,
            receipt=receipt,
            bundle_digest=document["bundle_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AdapterError(f"invalid dispatch bundle document: {exc}") from exc


def result_envelope_to_dict(envelope: RunnerResultEnvelope) -> dict[str, Any]:
    return _normal(envelope)


def result_envelope_from_document(document: dict[str, Any]) -> RunnerResultEnvelope:
    try:
        return RunnerResultEnvelope(
            schema_version=int(document["schema_version"]),
            adapter_protocol_version=document["adapter_protocol_version"],
            dispatch_id=document["dispatch_id"],
            run_id=document["run_id"],
            manifest_digest=document["manifest_digest"],
            package_id=document["package_id"],
            package_digest=document["package_digest"],
            adapter_id=document["adapter_id"],
            provider=document["provider"],
            external_run_id=document["external_run_id"],
            request_digest=document["request_digest"],
            receipt_digest=document["receipt_digest"],
            outcome=document["outcome"],
            revision=document.get("revision"),
            blocker_kind=document.get("blocker_kind"),
            evidence_locators=tuple(document.get("evidence_locators", [])),
            result_digest=document["result_digest"],
            envelope_digest=document["envelope_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AdapterError(f"invalid result envelope document: {exc}") from exc


def load_json_document(path: str | Path, *, label: str) -> dict[str, Any]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterError(f"could not load {label}: {exc}") from exc
    if not isinstance(document, dict):
        raise AdapterError(f"{label} root must be an object")
    return document


def write_dispatch_bundle(bundle: DispatchBundle, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(dispatch_bundle_to_dict(bundle), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_result_envelope(envelope: RunnerResultEnvelope, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(result_envelope_to_dict(envelope), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
