from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import ProtocolError
from .models import Domain, EvidenceGate, Profile
from .scheduler import Schedule, build_schedule

PROTOCOL_VERSION = "0.0.2"
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class RoleContract:
    id: str
    role: str
    permissions: tuple[str, ...]
    prohibitions: tuple[str, ...]


@dataclass(frozen=True)
class WorkPackage:
    package_id: str
    run_id: str
    domain_id: str
    wave: int
    objective: str
    dependencies: tuple[str, ...]
    serialize_after: tuple[str, ...]
    write_scopes: tuple[str, ...]
    exclusive_resources: tuple[str, ...]
    gates: tuple[EvidenceGate, ...]
    permitted_blockers: tuple[str, ...]
    invariants: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    role_contract_ids: tuple[str, ...]
    package_digest: str


@dataclass(frozen=True)
class RunManifest:
    schema_version: int
    protocol_version: str
    run_id: str
    project: str
    profile_version: str
    profile_digest: str
    source_revision: str
    schedule: tuple[tuple[str, ...], ...]
    role_contracts: tuple[RoleContract, ...]
    packages: tuple[WorkPackage, ...]
    manifest_digest: str


ROLE_CONTRACTS: tuple[RoleContract, ...] = (
    RoleContract(
        id="coordinator/v0.0.2",
        role="coordinator",
        permissions=(
            "compile immutable run manifests",
            "schedule declared work packages",
            "route results between separated roles",
        ),
        prohibitions=(
            "modify project implementation as coordinator",
            "self-verify builder evidence",
            "integrate revisions",
            "override profile gates or authority boundaries",
        ),
    ),
    RoleContract(
        id="builder/v0.0.2",
        role="builder",
        permissions=(
            "modify only the work package declared write scopes",
            "use only declared exclusive resources while assigned",
            "run tests and produce evidence",
            "emit built blocked or failed worker results",
        ),
        prohibitions=(
            "modify undeclared write scopes",
            "verify or approve own result",
            "integrate own revision",
            "change the run manifest profile or authority boundaries",
        ),
    ),
    RoleContract(
        id="verifier/v0.0.2",
        role="verifier",
        permissions=(
            "inspect worker results and declared evidence",
            "reproduce evidence independently",
            "accept or reject declared evidence gates",
        ),
        prohibitions=(
            "modify the builder implementation under verification",
            "integrate revisions",
            "weaken evidence gates",
            "change the run manifest or profile",
        ),
    ),
    RoleContract(
        id="integrator/v0.0.2",
        role="integrator",
        permissions=(
            "integrate independently verified revisions in manifest order",
            "run cross-package integration checks",
        ),
        prohibitions=(
            "integrate non-verified work",
            "rewrite worker evidence or verifier verdicts",
            "override dependency or serialization order",
            "change profile authority boundaries",
        ),
    ),
)

ROLE_CONTRACT_IDS = tuple(contract.id for contract in ROLE_CONTRACTS)


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


def canonical_json(value: Any) -> str:
    return json.dumps(_normal(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _profile_payload(profile: Profile) -> dict[str, Any]:
    return _normal(profile)


def profile_digest(profile: Profile) -> str:
    return sha256_digest(_profile_payload(profile))


def _conflicts(left: Domain, right: Domain) -> bool:
    return bool(
        set(left.write_scopes) & set(right.write_scopes)
        or set(left.exclusive_resources) & set(right.exclusive_resources)
    )


def serialization_predecessors(profile: Profile, schedule: Schedule) -> dict[str, tuple[str, ...]]:
    by_id = {domain.id: domain for domain in profile.domains}
    ordered: list[tuple[int, str]] = [
        (wave_number, domain_id)
        for wave_number, wave in enumerate(schedule.waves, start=1)
        for domain_id in wave
    ]
    predecessors: dict[str, tuple[str, ...]] = {}
    for wave_number, domain_id in ordered:
        domain = by_id[domain_id]
        before = sorted(
            prior_id
            for prior_wave, prior_id in ordered
            if prior_wave < wave_number
            and prior_id not in domain.dependencies
            and _conflicts(by_id[prior_id], domain)
        )
        predecessors[domain_id] = tuple(before)
    return predecessors


def _package_payload(package: WorkPackage | dict[str, Any]) -> dict[str, Any]:
    payload = _normal(package)
    payload.pop("package_digest", None)
    return payload


def _manifest_payload(manifest: RunManifest | dict[str, Any]) -> dict[str, Any]:
    payload = _normal(manifest)
    payload.pop("manifest_digest", None)
    return payload


def _run_seed(
    *,
    project: str,
    profile_version: str,
    profile_sha256: str,
    source_revision: str,
    schedule: tuple[tuple[str, ...], ...],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "project": project,
        "profile_version": profile_version,
        "profile_digest": profile_sha256,
        "source_revision": source_revision,
        "schedule": schedule,
    }


def compile_run(profile: Profile, source_revision: str) -> RunManifest:
    if not isinstance(source_revision, str) or not source_revision.strip():
        raise ProtocolError("source_revision must be a non-empty immutable source identifier")

    schedule = build_schedule(profile)
    p_digest = profile_digest(profile)
    seed = _run_seed(
        project=profile.project,
        profile_version=profile.profile_version,
        profile_sha256=p_digest,
        source_revision=source_revision,
        schedule=schedule.waves,
    )
    run_id = f"bc2-{sha256_digest(seed)[:16]}"
    serialize_after = serialization_predecessors(profile, schedule)

    packages: list[WorkPackage] = []
    for wave_number, wave in enumerate(schedule.waves, start=1):
        for domain_id in wave:
            domain = next(item for item in profile.domains if item.id == domain_id)
            unsigned = WorkPackage(
                package_id=f"{run_id}:{domain.id}",
                run_id=run_id,
                domain_id=domain.id,
                wave=wave_number,
                objective=domain.objective,
                dependencies=domain.dependencies,
                serialize_after=serialize_after[domain.id],
                write_scopes=domain.write_scopes,
                exclusive_resources=domain.exclusive_resources,
                gates=domain.gates,
                permitted_blockers=tuple(blocker.value for blocker in domain.permitted_blockers),
                invariants=profile.invariants,
                forbidden_actions=profile.forbidden_actions,
                role_contract_ids=ROLE_CONTRACT_IDS,
                package_digest="",
            )
            packages.append(
                WorkPackage(
                    **{
                        **asdict(unsigned),
                        "gates": unsigned.gates,
                        "package_digest": sha256_digest(_package_payload(unsigned)),
                    }
                )
            )

    unsigned_manifest = RunManifest(
        schema_version=SCHEMA_VERSION,
        protocol_version=PROTOCOL_VERSION,
        run_id=run_id,
        project=profile.project,
        profile_version=profile.profile_version,
        profile_digest=p_digest,
        source_revision=source_revision,
        schedule=schedule.waves,
        role_contracts=ROLE_CONTRACTS,
        packages=tuple(packages),
        manifest_digest="",
    )
    return RunManifest(
        **{
            **asdict(unsigned_manifest),
            "role_contracts": unsigned_manifest.role_contracts,
            "packages": unsigned_manifest.packages,
            "schedule": unsigned_manifest.schedule,
            "manifest_digest": sha256_digest(_manifest_payload(unsigned_manifest)),
        }
    )


def manifest_to_dict(manifest: RunManifest) -> dict[str, Any]:
    return _normal(manifest)


def write_manifest(manifest: RunManifest, path: str | Path) -> None:
    Path(path).write_text(
        json.dumps(manifest_to_dict(manifest), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def load_manifest_document(path: str | Path) -> dict[str, Any]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"could not load run manifest: {exc}") from exc
    if not isinstance(document, dict):
        raise ProtocolError("run manifest root must be an object")
    return document


def verify_manifest_document(
    document: dict[str, Any],
    profile: Profile | None = None,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    required = {
        "schema_version",
        "protocol_version",
        "run_id",
        "project",
        "profile_version",
        "profile_digest",
        "source_revision",
        "schedule",
        "role_contracts",
        "packages",
        "manifest_digest",
    }
    missing = sorted(required - set(document))
    if missing:
        return False, (f"manifest missing fields: {missing}",)

    if document.get("schema_version") != SCHEMA_VERSION:
        reasons.append(f"unsupported schema_version: {document.get('schema_version')}")
    if document.get("protocol_version") != PROTOCOL_VERSION:
        reasons.append(f"unsupported protocol_version: {document.get('protocol_version')}")
    if not isinstance(document.get("source_revision"), str) or not document["source_revision"].strip():
        reasons.append("source_revision must be non-empty")

    expected_contracts = _normal(ROLE_CONTRACTS)
    if document.get("role_contracts") != expected_contracts:
        reasons.append("role contracts differ from the frozen protocol contracts")

    packages = document.get("packages")
    if not isinstance(packages, list):
        reasons.append("packages must be a list")
        packages = []
    else:
        ids: set[str] = set()
        domains: set[str] = set()
        for index, package in enumerate(packages):
            if not isinstance(package, dict):
                reasons.append(f"packages[{index}] must be an object")
                continue
            package_id = package.get("package_id")
            domain_id = package.get("domain_id")
            if not isinstance(package_id, str) or not package_id:
                reasons.append(f"packages[{index}] has invalid package_id")
            elif package_id in ids:
                reasons.append(f"duplicate package_id: {package_id}")
            else:
                ids.add(package_id)
            if not isinstance(domain_id, str) or not domain_id:
                reasons.append(f"packages[{index}] has invalid domain_id")
            elif domain_id in domains:
                reasons.append(f"duplicate domain_id: {domain_id}")
            else:
                domains.add(domain_id)
            expected_package_digest = sha256_digest(_package_payload(package))
            if package.get("package_digest") != expected_package_digest:
                reasons.append(f"package digest mismatch: {domain_id or index}")
            if package.get("run_id") != document.get("run_id"):
                reasons.append(f"package run_id mismatch: {domain_id or index}")
            if package.get("role_contract_ids") != list(ROLE_CONTRACT_IDS):
                reasons.append(f"package role contracts mismatch: {domain_id or index}")

    try:
        schedule = tuple(tuple(item for item in wave) for wave in document.get("schedule", []))
        seed = _run_seed(
            project=document["project"],
            profile_version=document["profile_version"],
            profile_sha256=document["profile_digest"],
            source_revision=document["source_revision"],
            schedule=schedule,
        )
        expected_run_id = f"bc2-{sha256_digest(seed)[:16]}"
        if document.get("run_id") != expected_run_id:
            reasons.append("run_id does not match immutable run inputs")
    except (TypeError, KeyError):
        reasons.append("manifest run seed is malformed")

    expected_manifest_digest = sha256_digest(_manifest_payload(document))
    if document.get("manifest_digest") != expected_manifest_digest:
        reasons.append("manifest digest mismatch")

    if profile is not None and not reasons:
        try:
            expected = manifest_to_dict(compile_run(profile, document["source_revision"]))
        except ProtocolError as exc:
            reasons.append(str(exc))
        else:
            if document != expected:
                reasons.append("manifest does not exactly match the supplied profile and source revision")

    return not reasons, tuple(reasons)
