from __future__ import annotations

import json
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import PoolError
from .ledger import current_dispatch_binding, execution_frontier, next_dispatch_attempt, replay_ledger
from .protocol import RunManifest, WorkPackage, sha256_digest
from .runner_adapter import RunnerCapabilities, make_capabilities, verify_capabilities
from .runner_session import SessionDispatchRequest
from .runner_session_strict import compile_session_dispatch_request
from .state_models import PackageState, RunLedger

POOL_PROTOCOL_VERSION = "0.0.8"
POOL_SCHEMA_VERSION = 1
BUSY_STATES = frozenset({PackageState.DISPATCHED, PackageState.ACTIVE})


@dataclass(frozen=True)
class RunnerRegistry:
    schema_version: int
    pool_protocol_version: str
    runners: tuple[RunnerCapabilities, ...]
    registry_digest: str


@dataclass(frozen=True)
class DeferredDispatch:
    domain_id: str
    reason: str


@dataclass(frozen=True)
class PoolAssignment:
    ordinal: int
    domain_id: str
    package_id: str
    package_digest: str
    adapter_id: str
    provider: str
    capability_digest: str
    mode: str
    dispatch_attempt: int
    lease_id: str
    assignment_digest: str


@dataclass(frozen=True)
class DispatchPlan:
    schema_version: int
    pool_protocol_version: str
    plan_id: str
    run_id: str
    manifest_digest: str
    ledger_head_digest: str
    registry_digest: str
    mode: str
    assignments: tuple[PoolAssignment, ...]
    deferred: tuple[DeferredDispatch, ...]
    plan_digest: str


@dataclass(frozen=True)
class ReferencePoolSessionRunner:
    """Deterministic session-aware runner used only for pool conformance tests."""

    _capabilities: RunnerCapabilities

    def capabilities(self) -> RunnerCapabilities:
        return self._capabilities

    def dispatch(self, request):
        from .runner_session_strict import accept_session_dispatch

        if request.adapter_id != self._capabilities.adapter_id:
            raise PoolError("reference pool runner received request for another adapter")
        external_run_id = f"refpool-{sha256_digest({'dispatch_id': request.dispatch_id})[:20]}"
        return accept_session_dispatch(
            request,
            self._capabilities,
            external_run_id=external_run_id,
        )


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


def make_registry(runners: tuple[RunnerCapabilities, ...]) -> RunnerRegistry:
    if not runners:
        raise PoolError("runner registry must contain at least one runner")
    ids = [runner.adapter_id for runner in runners]
    if len(ids) != len(set(ids)):
        raise PoolError("runner registry adapter_id values must be unique")
    for runner in runners:
        accepted, reasons = verify_capabilities(runner)
        if not accepted:
            raise PoolError(
                f"invalid runner capabilities {runner.adapter_id}: " + "; ".join(reasons)
            )
    ordered = tuple(sorted(runners, key=lambda item: item.adapter_id))
    unsigned = RunnerRegistry(
        schema_version=POOL_SCHEMA_VERSION,
        pool_protocol_version=POOL_PROTOCOL_VERSION,
        runners=ordered,
        registry_digest="",
    )
    return RunnerRegistry(
        schema_version=unsigned.schema_version,
        pool_protocol_version=unsigned.pool_protocol_version,
        runners=unsigned.runners,
        registry_digest=sha256_digest(_without(unsigned, "registry_digest")),
    )


def reference_pool_registry(*, slots: int = 4, max_parallelism: int = 1) -> RunnerRegistry:
    if slots < 1:
        raise PoolError("reference pool slots must be >= 1")
    if max_parallelism < 1:
        raise PoolError("reference pool max_parallelism must be >= 1")
    return make_registry(
        tuple(
            make_capabilities(
                adapter_id=f"reference-pool-{index:02d}",
                provider="build-colony-reference-pool",
                adapter_version=POOL_PROTOCOL_VERSION,
                modes=("execute", "reproduce"),
                supports_write=True,
                supports_artifact_refs=True,
                max_parallelism=max_parallelism,
            )
            for index in range(1, slots + 1)
        )
    )


def verify_registry(registry: RunnerRegistry) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if registry.schema_version != POOL_SCHEMA_VERSION:
        reasons.append(f"unsupported runner registry schema version: {registry.schema_version}")
    if registry.pool_protocol_version != POOL_PROTOCOL_VERSION:
        reasons.append(f"unsupported runner pool protocol version: {registry.pool_protocol_version}")
    if not registry.runners:
        reasons.append("runner registry is empty")
    ids: set[str] = set()
    for runner in registry.runners:
        if runner.adapter_id in ids:
            reasons.append(f"duplicate runner adapter_id: {runner.adapter_id}")
        ids.add(runner.adapter_id)
        accepted, cap_reasons = verify_capabilities(runner)
        if not accepted:
            reasons.extend(f"{runner.adapter_id}: {reason}" for reason in cap_reasons)
    if tuple(sorted(registry.runners, key=lambda item: item.adapter_id)) != registry.runners:
        reasons.append("runner registry is not in canonical adapter_id order")
    if registry.registry_digest != sha256_digest(_without(registry, "registry_digest")):
        reasons.append("runner registry digest mismatch")
    return not reasons, tuple(dict.fromkeys(reasons))


def _packages(manifest: RunManifest) -> dict[str, WorkPackage]:
    return {package.domain_id: package for package in manifest.packages}


def active_runner_counts(manifest: RunManifest, ledger: RunLedger) -> dict[str, int]:
    states = replay_ledger(manifest, ledger)
    counts: dict[str, int] = {}
    for package in manifest.packages:
        domain_id = package.domain_id
        if states[domain_id] not in BUSY_STATES:
            continue
        binding = current_dispatch_binding(manifest, ledger, domain_id)
        if binding is None:
            raise PoolError(f"busy package {domain_id} has no dispatch binding")
        adapter_id = binding.get("adapter_id")
        capability_digest = binding.get("capability_digest")
        if not isinstance(adapter_id, str) or not adapter_id:
            raise PoolError(
                f"busy package {domain_id} lacks pool adapter identity; refusing capacity guess"
            )
        if not isinstance(capability_digest, str) or len(capability_digest) != 64:
            raise PoolError(
                f"busy package {domain_id} lacks pool capability identity; refusing capacity guess"
            )
        counts[adapter_id] = counts.get(adapter_id, 0) + 1
    return counts


def _compatible(package: WorkPackage, runner: RunnerCapabilities, mode: str) -> bool:
    return mode in runner.modes and (not package.write_scopes or runner.supports_write)


def _plan_seed(
    manifest: RunManifest,
    ledger: RunLedger,
    registry: RunnerRegistry,
    mode: str,
) -> dict[str, Any]:
    return {
        "pool_protocol_version": POOL_PROTOCOL_VERSION,
        "run_id": manifest.run_id,
        "manifest_digest": manifest.manifest_digest,
        "ledger_head_digest": ledger.head_event_digest,
        "registry_digest": registry.registry_digest,
        "mode": mode,
    }


def _assignment(
    *,
    ordinal: int,
    plan_id: str,
    ledger_head_digest: str,
    package: WorkPackage,
    runner: RunnerCapabilities,
    mode: str,
    dispatch_attempt: int,
) -> PoolAssignment:
    lease_material = {
        "plan_id": plan_id,
        "ledger_head_digest": ledger_head_digest,
        "package_id": package.package_id,
        "package_digest": package.package_digest,
        "adapter_id": runner.adapter_id,
        "provider": runner.provider,
        "capability_digest": runner.capability_digest,
        "mode": mode,
        "dispatch_attempt": dispatch_attempt,
    }
    lease_id = f"bcl-{sha256_digest(lease_material)[:20]}"
    unsigned = PoolAssignment(
        ordinal=ordinal,
        domain_id=package.domain_id,
        package_id=package.package_id,
        package_digest=package.package_digest,
        adapter_id=runner.adapter_id,
        provider=runner.provider,
        capability_digest=runner.capability_digest,
        mode=mode,
        dispatch_attempt=dispatch_attempt,
        lease_id=lease_id,
        assignment_digest="",
    )
    return PoolAssignment(
        **{
            **asdict(unsigned),
            "assignment_digest": sha256_digest(_without(unsigned, "assignment_digest")),
        }
    )


def plan_dispatches(
    manifest: RunManifest,
    ledger: RunLedger,
    registry: RunnerRegistry,
    *,
    mode: str = "execute",
) -> DispatchPlan:
    accepted, reasons = verify_registry(registry)
    if not accepted:
        raise PoolError("invalid runner registry: " + "; ".join(reasons))
    if not isinstance(mode, str) or not mode.strip():
        raise PoolError("pool mode must be a non-empty string")

    frontier = execution_frontier(manifest, ledger)
    package_by_domain = _packages(manifest)
    ordered_domains = sorted(
        frontier.dispatchable,
        key=lambda domain_id: (package_by_domain[domain_id].wave, domain_id),
    )
    active = active_runner_counts(manifest, ledger)
    planned: dict[str, int] = {}
    runners = tuple(sorted(registry.runners, key=lambda item: item.adapter_id))
    plan_id = f"bcp-{sha256_digest(_plan_seed(manifest, ledger, registry, mode))[:20]}"

    assignments: list[PoolAssignment] = []
    deferred: list[DeferredDispatch] = []
    for domain_id in ordered_domains:
        package = package_by_domain[domain_id]
        compatible = [runner for runner in runners if _compatible(package, runner, mode)]
        if not compatible:
            deferred.append(DeferredDispatch(domain_id=domain_id, reason="no_compatible_runner"))
            continue
        selected = next(
            (
                runner
                for runner in compatible
                if active.get(runner.adapter_id, 0) + planned.get(runner.adapter_id, 0)
                < runner.max_parallelism
            ),
            None,
        )
        if selected is None:
            deferred.append(DeferredDispatch(domain_id=domain_id, reason="capacity_exhausted"))
            continue
        planned[selected.adapter_id] = planned.get(selected.adapter_id, 0) + 1
        assignments.append(
            _assignment(
                ordinal=len(assignments) + 1,
                plan_id=plan_id,
                ledger_head_digest=ledger.head_event_digest,
                package=package,
                runner=selected,
                mode=mode,
                dispatch_attempt=next_dispatch_attempt(manifest, ledger, domain_id),
            )
        )

    unsigned = DispatchPlan(
        schema_version=POOL_SCHEMA_VERSION,
        pool_protocol_version=POOL_PROTOCOL_VERSION,
        plan_id=plan_id,
        run_id=manifest.run_id,
        manifest_digest=manifest.manifest_digest,
        ledger_head_digest=ledger.head_event_digest,
        registry_digest=registry.registry_digest,
        mode=mode,
        assignments=tuple(assignments),
        deferred=tuple(deferred),
        plan_digest="",
    )
    return DispatchPlan(
        **{
            **asdict(unsigned),
            "assignments": unsigned.assignments,
            "deferred": unsigned.deferred,
            "plan_digest": sha256_digest(_without(unsigned, "plan_digest")),
        }
    )


def verify_dispatch_plan(
    plan: DispatchPlan,
    manifest: RunManifest,
    ledger: RunLedger,
    registry: RunnerRegistry,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if plan.schema_version != POOL_SCHEMA_VERSION:
        reasons.append(f"unsupported dispatch plan schema version: {plan.schema_version}")
    if plan.pool_protocol_version != POOL_PROTOCOL_VERSION:
        reasons.append(f"unsupported dispatch plan protocol version: {plan.pool_protocol_version}")
    if plan.run_id != manifest.run_id or plan.manifest_digest != manifest.manifest_digest:
        reasons.append("dispatch plan is not bound to supplied manifest")
    if plan.ledger_head_digest != ledger.head_event_digest:
        reasons.append("dispatch plan is stale for current ledger head")
    if plan.registry_digest != registry.registry_digest:
        reasons.append("dispatch plan registry digest mismatch")
    if plan.plan_digest != sha256_digest(_without(plan, "plan_digest")):
        reasons.append("dispatch plan digest mismatch")
    try:
        expected = plan_dispatches(manifest, ledger, registry, mode=plan.mode)
    except PoolError as exc:
        reasons.append(str(exc))
    else:
        if plan != expected:
            reasons.append("dispatch plan differs from deterministic replan")
    return not reasons, tuple(dict.fromkeys(reasons))


def assignment_for_domain(plan: DispatchPlan, domain_id: str) -> PoolAssignment:
    assignment = next((item for item in plan.assignments if item.domain_id == domain_id), None)
    if assignment is None:
        raise PoolError(f"domain is not assigned by dispatch plan: {domain_id}")
    return assignment


def compile_assignment_request(
    plan: DispatchPlan,
    manifest: RunManifest,
    ledger: RunLedger,
    registry: RunnerRegistry,
    *,
    domain_id: str,
) -> SessionDispatchRequest:
    accepted, reasons = verify_dispatch_plan(plan, manifest, ledger, registry)
    if not accepted:
        raise PoolError("invalid/stale dispatch plan: " + "; ".join(reasons))
    assignment = assignment_for_domain(plan, domain_id)
    runner = next(
        (item for item in registry.runners if item.adapter_id == assignment.adapter_id),
        None,
    )
    if runner is None:
        raise PoolError(f"assigned runner no longer exists: {assignment.adapter_id}")
    request = compile_session_dispatch_request(
        manifest,
        ledger,
        domain_id=domain_id,
        capabilities=runner,
        mode=assignment.mode,
    )
    bindings = (
        (request.package_id, assignment.package_id, "package_id"),
        (request.package_digest, assignment.package_digest, "package_digest"),
        (request.adapter_id, assignment.adapter_id, "adapter_id"),
        (request.provider, assignment.provider, "provider"),
        (request.capability_digest, assignment.capability_digest, "capability_digest"),
        (request.mode, assignment.mode, "mode"),
        (request.dispatch_attempt, assignment.dispatch_attempt, "dispatch_attempt"),
    )
    for actual, expected, field in bindings:
        if actual != expected:
            raise PoolError(f"compiled session request {field} differs from assignment")
    return request


def registry_to_dict(registry: RunnerRegistry) -> dict[str, Any]:
    return _normal(registry)


def plan_to_dict(plan: DispatchPlan) -> dict[str, Any]:
    return _normal(plan)


def registry_from_document(document: dict[str, Any]) -> RunnerRegistry:
    try:
        runners = tuple(
            RunnerCapabilities(
                adapter_id=item["adapter_id"],
                provider=item["provider"],
                adapter_version=item["adapter_version"],
                modes=tuple(item["modes"]),
                supports_write=bool(item["supports_write"]),
                supports_artifact_refs=bool(item["supports_artifact_refs"]),
                max_parallelism=int(item["max_parallelism"]),
                capability_digest=item["capability_digest"],
            )
            for item in document["runners"]
        )
        return RunnerRegistry(
            schema_version=int(document["schema_version"]),
            pool_protocol_version=document["pool_protocol_version"],
            runners=runners,
            registry_digest=document["registry_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PoolError(f"invalid runner registry document: {exc}") from exc


def plan_from_document(document: dict[str, Any]) -> DispatchPlan:
    try:
        assignments = tuple(
            PoolAssignment(
                ordinal=int(item["ordinal"]),
                domain_id=item["domain_id"],
                package_id=item["package_id"],
                package_digest=item["package_digest"],
                adapter_id=item["adapter_id"],
                provider=item["provider"],
                capability_digest=item["capability_digest"],
                mode=item["mode"],
                dispatch_attempt=int(item["dispatch_attempt"]),
                lease_id=item["lease_id"],
                assignment_digest=item["assignment_digest"],
            )
            for item in document["assignments"]
        )
        deferred = tuple(
            DeferredDispatch(domain_id=item["domain_id"], reason=item["reason"])
            for item in document["deferred"]
        )
        return DispatchPlan(
            schema_version=int(document["schema_version"]),
            pool_protocol_version=document["pool_protocol_version"],
            plan_id=document["plan_id"],
            run_id=document["run_id"],
            manifest_digest=document["manifest_digest"],
            ledger_head_digest=document["ledger_head_digest"],
            registry_digest=document["registry_digest"],
            mode=document["mode"],
            assignments=assignments,
            deferred=deferred,
            plan_digest=document["plan_digest"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PoolError(f"invalid dispatch plan document: {exc}") from exc


def load_pool_document(path: str | Path, *, label: str) -> dict[str, Any]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PoolError(f"could not load {label}: {exc}") from exc
    if not isinstance(document, dict):
        raise PoolError(f"{label} root must be an object")
    return document
