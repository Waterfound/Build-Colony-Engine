from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import ProfileError
from .models import BlockerKind, Domain, EvidenceGate, Profile, unique


def _tuple_strings(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ProfileError(f"{field} must be a list of non-empty strings")
    return tuple(value)


def profile_from_dict(data: dict[str, Any]) -> Profile:
    try:
        project = data["project"]
        profile_version = data["profile_version"]
        goal = data["goal"]
        raw_domains = data["domains"]
    except KeyError as exc:
        raise ProfileError(f"missing required profile field: {exc.args[0]}") from exc

    if not all(isinstance(value, str) and value.strip() for value in (project, profile_version, goal)):
        raise ProfileError("project, profile_version, and goal must be non-empty strings")
    if not isinstance(raw_domains, list) or not raw_domains:
        raise ProfileError("domains must be a non-empty list")

    domains: list[Domain] = []
    for index, raw in enumerate(raw_domains):
        if not isinstance(raw, dict):
            raise ProfileError(f"domains[{index}] must be an object")
        try:
            domain_id = raw["id"]
            objective = raw["objective"]
        except KeyError as exc:
            raise ProfileError(f"domains[{index}] missing field: {exc.args[0]}") from exc
        if not isinstance(domain_id, str) or not domain_id.strip():
            raise ProfileError(f"domains[{index}].id must be a non-empty string")
        if not isinstance(objective, str) or not objective.strip():
            raise ProfileError(f"domains[{index}].objective must be a non-empty string")

        gates: list[EvidenceGate] = []
        for gate_index, gate in enumerate(raw.get("gates", [])):
            if not isinstance(gate, dict):
                raise ProfileError(f"domains[{index}].gates[{gate_index}] must be an object")
            try:
                gates.append(
                    EvidenceGate(
                        id=gate["id"],
                        description=gate["description"],
                        accepted_kinds=_tuple_strings(gate["accepted_kinds"], "accepted_kinds"),
                        minimum=int(gate.get("minimum", 1)),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ProfileError(f"invalid gate in domain {domain_id}: {exc}") from exc

        if not gates:
            raise ProfileError(f"domain {domain_id} must declare at least one evidence gate")

        blockers: list[BlockerKind] = []
        for blocker in raw.get("permitted_blockers", []):
            try:
                blockers.append(BlockerKind(blocker))
            except ValueError as exc:
                raise ProfileError(f"domain {domain_id} has unknown blocker kind: {blocker}") from exc

        domains.append(
            Domain(
                id=domain_id,
                objective=objective,
                dependencies=_tuple_strings(raw.get("dependencies", []), "dependencies"),
                write_scopes=_tuple_strings(raw.get("write_scopes", []), "write_scopes"),
                exclusive_resources=_tuple_strings(raw.get("exclusive_resources", []), "exclusive_resources"),
                gates=tuple(gates),
                permitted_blockers=tuple(blockers),
            )
        )

    if not unique(domain.id for domain in domains):
        raise ProfileError("domain ids must be unique")

    ids = {domain.id for domain in domains}
    for domain in domains:
        missing = set(domain.dependencies) - ids
        if missing:
            raise ProfileError(f"domain {domain.id} has unknown dependencies: {sorted(missing)}")
        if domain.id in domain.dependencies:
            raise ProfileError(f"domain {domain.id} cannot depend on itself")

    profile = Profile(
        project=project,
        profile_version=profile_version,
        goal=goal,
        invariants=_tuple_strings(data.get("invariants", []), "invariants"),
        forbidden_actions=_tuple_strings(data.get("forbidden_actions", []), "forbidden_actions"),
        domains=tuple(domains),
    )
    _assert_acyclic(profile)
    return profile


def _assert_acyclic(profile: Profile) -> None:
    dependencies = {domain.id: set(domain.dependencies) for domain in profile.domains}
    remaining = set(dependencies)
    while remaining:
        roots = sorted(domain for domain in remaining if not (dependencies[domain] & remaining))
        if not roots:
            cycle = ", ".join(sorted(remaining))
            raise ProfileError(f"dependency graph contains a cycle among: {cycle}")
        remaining.difference_update(roots)


def load_profile(path: str | Path) -> Profile:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"could not load profile: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileError("profile root must be an object")
    return profile_from_dict(data)
