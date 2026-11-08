from __future__ import annotations

from .protocol import RunManifest, WorkPackage
from .state_models import ExecutionFrontier, PackageState

TERMINAL_OR_RELEASED = {
    PackageState.INTEGRATED,
    PackageState.EXTERNALLY_BLOCKED,
}

ATTENTION_STATES = {
    PackageState.FAILED,
    PackageState.REJECTED,
}


def initial_states(manifest: RunManifest) -> dict[str, PackageState]:
    return {package.domain_id: PackageState.PENDING for package in manifest.packages}


def _packages_by_domain(manifest: RunManifest) -> dict[str, WorkPackage]:
    return {package.domain_id: package for package in manifest.packages}


def next_integratable(manifest: RunManifest, states: dict[str, PackageState]) -> str | None:
    if any(state in ATTENTION_STATES for state in states.values()):
        return None

    candidates: list[WorkPackage] = []
    for package in manifest.packages:
        if states[package.domain_id] != PackageState.VERIFIED:
            continue
        if any(states[dependency] != PackageState.INTEGRATED for dependency in package.dependencies):
            continue
        if any(states[predecessor] not in TERMINAL_OR_RELEASED for predecessor in package.serialize_after):
            continue
        candidates.append(package)

    if not candidates:
        return None
    candidates.sort(key=lambda package: (package.wave, package.domain_id))
    return candidates[0].domain_id


def build_frontier(manifest: RunManifest, states: dict[str, PackageState]) -> ExecutionFrontier:
    domains = set(_packages_by_domain(manifest))
    if set(states) != domains:
        missing = sorted(domains - set(states))
        unknown = sorted(set(states) - domains)
        raise ValueError(f"state/domain mismatch; missing={missing}, unknown={unknown}")

    ready: list[str] = []
    dispatchable: list[str] = []
    active: list[str] = []
    waiting_dependencies: list[str] = []
    waiting_serialization: list[str] = []
    dependency_blocked: list[str] = []
    attention: list[str] = []
    verified_waiting: list[str] = []
    integrated: list[str] = []
    externally_blocked: list[str] = []

    for domain_id, state in states.items():
        if state in ATTENTION_STATES:
            attention.append(domain_id)
        elif state == PackageState.INTEGRATED:
            integrated.append(domain_id)
        elif state == PackageState.EXTERNALLY_BLOCKED:
            externally_blocked.append(domain_id)
        elif state == PackageState.VERIFIED:
            verified_waiting.append(domain_id)
        elif state == PackageState.ISSUED:
            dispatchable.append(domain_id)
        elif state != PackageState.PENDING:
            active.append(domain_id)

    global_attention = bool(attention)

    for package in manifest.packages:
        domain_id = package.domain_id
        if states[domain_id] != PackageState.PENDING:
            continue

        dependency_states = [states[dependency] for dependency in package.dependencies]
        if any(state in ATTENTION_STATES for state in dependency_states):
            attention.append(domain_id)
            continue
        if any(state == PackageState.EXTERNALLY_BLOCKED for state in dependency_states):
            dependency_blocked.append(domain_id)
            continue
        if any(state != PackageState.INTEGRATED for state in dependency_states):
            waiting_dependencies.append(domain_id)
            continue

        serialization_states = [states[predecessor] for predecessor in package.serialize_after]
        if any(state in ATTENTION_STATES for state in serialization_states):
            attention.append(domain_id)
            continue
        if any(state not in TERMINAL_OR_RELEASED for state in serialization_states):
            waiting_serialization.append(domain_id)
            continue

        if not global_attention:
            ready.append(domain_id)

    return ExecutionFrontier(
        ready=tuple(sorted(set(ready))),
        dispatchable=() if global_attention else tuple(sorted(set(dispatchable))),
        active=tuple(sorted(set(active))),
        waiting_dependencies=tuple(sorted(set(waiting_dependencies))),
        waiting_serialization=tuple(sorted(set(waiting_serialization))),
        dependency_blocked=tuple(sorted(set(dependency_blocked))),
        attention_required=tuple(sorted(set(attention))),
        verified_waiting_integration=tuple(sorted(set(verified_waiting))),
        integrated=tuple(sorted(set(integrated))),
        externally_blocked=tuple(sorted(set(externally_blocked))),
        next_integratable=next_integratable(manifest, states) if not global_attention else None,
    )
