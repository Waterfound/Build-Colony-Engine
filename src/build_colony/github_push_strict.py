from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

from .errors import RemotePoolError
from .github_push_transport import (
    GitHubPushIntent,
    GitHubPushReceipt,
    execute_github_push_intent,
    verify_github_push_intent,
)
from .github_source_boundary import (
    GitHubSourceBoundaryEvidence,
    inspect_github_source_boundary,
    write_source_boundary_evidence,
)


def load_verified_github_push_intent(path: str | Path) -> GitHubPushIntent:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        intent = GitHubPushIntent(**document)
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise RemotePoolError(f"could not load GitHub push intent: {exc}") from exc
    accepted, reasons = verify_github_push_intent(intent)
    if not accepted:
        raise RemotePoolError("invalid GitHub push intent: " + "; ".join(reasons))
    return intent


def execute_github_push_intent_strict(
    intent_path: str | Path,
    *,
    repo_root: str | Path = ".",
    output_dir: str | Path,
    env: Mapping[str, str] | None = None,
) -> tuple[GitHubPushReceipt, GitHubSourceBoundaryEvidence]:
    environment = dict(os.environ if env is None else env)
    trigger_sha = environment.get("GITHUB_SHA", "")
    if not trigger_sha:
        raise RemotePoolError("runner environment missing GITHUB_SHA")
    intent = load_verified_github_push_intent(intent_path)
    boundary = inspect_github_source_boundary(
        intent,
        repo_root=repo_root,
        trigger_sha=trigger_sha,
    )
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    write_source_boundary_evidence(boundary, output / "source-boundary.json")
    receipt = execute_github_push_intent(
        intent_path,
        repo_root=repo_root,
        output_dir=output_dir,
        env=environment,
    )
    if receipt.github_sha != boundary.trigger_sha:
        raise RemotePoolError("remote receipt trigger SHA differs from source-boundary evidence")
    if receipt.intent_id != boundary.intent_id or receipt.intent_digest != boundary.intent_digest:
        raise RemotePoolError("remote receipt intent differs from source-boundary evidence")
    return receipt, boundary
