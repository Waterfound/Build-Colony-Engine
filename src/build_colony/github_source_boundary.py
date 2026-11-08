from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .errors import RemotePoolError
from .github_push_transport import GitHubPushIntent, verify_github_push_intent
from .protocol import sha256_digest

SOURCE_BOUNDARY_PROTOCOL_VERSION = "0.0.9"
SOURCE_BOUNDARY_SCHEMA_VERSION = 1
REMOTE_INTENT_PATH = ".build-colony/remote-intent.json"


@dataclass(frozen=True)
class GitHubSourceBoundaryEvidence:
    schema_version: int
    protocol_version: str
    intent_id: str
    intent_digest: str
    repository: str
    branch: str
    source_revision: str
    trigger_sha: str
    commit_distance: int
    changed_paths: tuple[str, ...]
    boundary_digest: str


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


def _require_sha(value: str, field: str) -> None:
    if not isinstance(value, str) or len(value) != 40:
        raise RemotePoolError(f"{field} must be a 40-character Git commit SHA")
    if any(ch not in "0123456789abcdef" for ch in value.lower()):
        raise RemotePoolError(f"{field} must be a 40-character Git commit SHA")


def _git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "git command failed").strip()
        raise RemotePoolError(f"git {' '.join(args)} failed: {detail}")
    return completed


def inspect_github_source_boundary(
    intent: GitHubPushIntent,
    *,
    repo_root: str | Path = ".",
    trigger_sha: str,
) -> GitHubSourceBoundaryEvidence:
    accepted, reasons = verify_github_push_intent(intent)
    if not accepted:
        raise RemotePoolError("invalid GitHub push intent: " + "; ".join(reasons))
    _require_sha(trigger_sha, "trigger_sha")
    root = Path(repo_root).resolve()
    if not (root / ".git").exists():
        raise RemotePoolError("repo_root is not a Git working tree")

    head = _git(root, "rev-parse", "HEAD").stdout.strip().lower()
    if head != trigger_sha.lower():
        raise RemotePoolError(
            f"checked-out HEAD does not match trigger SHA: expected {trigger_sha.lower()}, got {head}"
        )

    _git(root, "cat-file", "-e", f"{intent.source_revision}^{{commit}}")
    ancestor = _git(
        root,
        "merge-base",
        "--is-ancestor",
        intent.source_revision,
        trigger_sha,
        check=False,
    )
    if ancestor.returncode != 0:
        raise RemotePoolError("intent source_revision is not an ancestor of trigger SHA")

    distance_raw = _git(
        root,
        "rev-list",
        "--count",
        f"{intent.source_revision}..{trigger_sha}",
    ).stdout.strip()
    try:
        distance = int(distance_raw)
    except ValueError as exc:
        raise RemotePoolError("could not parse Git launch commit distance") from exc
    if distance != 1:
        raise RemotePoolError(
            f"remote launch must be exactly one commit above source_revision; got {distance}"
        )

    changed = tuple(
        sorted(
            path.strip()
            for path in _git(
                root,
                "diff",
                "--name-only",
                "--no-renames",
                intent.source_revision,
                trigger_sha,
            ).stdout.splitlines()
            if path.strip()
        )
    )
    if changed != (REMOTE_INTENT_PATH,):
        raise RemotePoolError(
            "remote launch delta must contain only "
            f"{REMOTE_INTENT_PATH}; got {list(changed)}"
        )

    unsigned = GitHubSourceBoundaryEvidence(
        schema_version=SOURCE_BOUNDARY_SCHEMA_VERSION,
        protocol_version=SOURCE_BOUNDARY_PROTOCOL_VERSION,
        intent_id=intent.intent_id,
        intent_digest=intent.intent_digest,
        repository=intent.repository,
        branch=intent.branch,
        source_revision=intent.source_revision,
        trigger_sha=trigger_sha.lower(),
        commit_distance=distance,
        changed_paths=changed,
        boundary_digest="",
    )
    return GitHubSourceBoundaryEvidence(
        **{
            **asdict(unsigned),
            "changed_paths": unsigned.changed_paths,
            "boundary_digest": sha256_digest(_without(unsigned, "boundary_digest")),
        }
    )


def verify_source_boundary_evidence(
    evidence: GitHubSourceBoundaryEvidence,
    intent: GitHubPushIntent,
    *,
    expected_trigger_sha: str | None = None,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if evidence.schema_version != SOURCE_BOUNDARY_SCHEMA_VERSION:
        reasons.append("unsupported source-boundary schema version")
    if evidence.protocol_version != SOURCE_BOUNDARY_PROTOCOL_VERSION:
        reasons.append("unsupported source-boundary protocol version")
    bindings = (
        (evidence.intent_id, intent.intent_id, "intent_id"),
        (evidence.intent_digest, intent.intent_digest, "intent_digest"),
        (evidence.repository, intent.repository, "repository"),
        (evidence.branch, intent.branch, "branch"),
        (evidence.source_revision, intent.source_revision, "source_revision"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            reasons.append(f"source-boundary {label} mismatch")
    if evidence.commit_distance != 1:
        reasons.append("source-boundary launch commit distance is not exactly one")
    if evidence.changed_paths != (REMOTE_INTENT_PATH,):
        reasons.append("source-boundary changed paths exceed remote-intent metadata")
    if expected_trigger_sha is not None and evidence.trigger_sha != expected_trigger_sha.lower():
        reasons.append("source-boundary trigger SHA mismatch")
    if evidence.boundary_digest != sha256_digest(_without(evidence, "boundary_digest")):
        reasons.append("source-boundary digest mismatch")
    return not reasons, tuple(dict.fromkeys(reasons))


def source_boundary_to_dict(evidence: GitHubSourceBoundaryEvidence) -> dict[str, Any]:
    return _normal(evidence)


def write_source_boundary_evidence(
    evidence: GitHubSourceBoundaryEvidence,
    path: str | Path,
) -> None:
    Path(path).write_text(
        json.dumps(source_boundary_to_dict(evidence), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def source_boundary_from_document(document: dict[str, Any]) -> GitHubSourceBoundaryEvidence:
    try:
        raw = dict(document)
        raw["schema_version"] = int(raw["schema_version"])
        raw["commit_distance"] = int(raw["commit_distance"])
        raw["changed_paths"] = tuple(raw["changed_paths"])
        return GitHubSourceBoundaryEvidence(**raw)
    except (KeyError, TypeError, ValueError) as exc:
        raise RemotePoolError(f"invalid source-boundary document: {exc}") from exc


def load_source_boundary_evidence(path: str | Path) -> GitHubSourceBoundaryEvidence:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RemotePoolError(f"could not load source-boundary evidence: {exc}") from exc
    if not isinstance(document, dict):
        raise RemotePoolError("source-boundary root must be an object")
    return source_boundary_from_document(document)
