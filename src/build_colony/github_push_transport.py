from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict, dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .errors import AdapterError
from .ledger import append_event
from .profile import load_profile
from .protocol import canonical_json, compile_run, manifest_to_dict, sha256_digest
from .runner_adapter import make_capabilities
from .runner_session_strict import (
    accept_session_dispatch,
    bind_session_dispatch,
    build_session_bundle,
    build_session_result_envelope,
    compile_session_dispatch_request,
    start_session_dispatch,
    submit_session_result,
)
from .state_models import EventType, ledger_to_dict, new_ledger

GITHUB_PUSH_PROTOCOL_VERSION = "0.0.7"
GITHUB_PUSH_SCHEMA_VERSION = 1
GITHUB_PUSH_TRANSPORT_ID = "github-actions-push"
GITHUB_PUSH_PROVIDER = "github-actions"
SUPPORTED_TASK_KINDS = frozenset({"conformance_probe"})


@dataclass(frozen=True)
class GitHubPushIntent:
    schema_version: int
    protocol_version: str
    intent_id: str
    transport_id: str
    repository: str
    branch: str
    profile_path: str
    source_revision: str
    domain_id: str
    task_kind: str
    intent_digest: str


@dataclass(frozen=True)
class GitHubPushReceipt:
    schema_version: int
    protocol_version: str
    transport_id: str
    intent_id: str
    intent_digest: str
    repository: str
    branch: str
    github_run_id: str
    github_run_attempt: str
    github_sha: str
    runner_os: str
    python_version: str
    run_id: str
    manifest_digest: str
    package_id: str
    package_digest: str
    dispatch_id: str
    dispatch_attempt: int
    session_bundle_digest: str
    outcome: str
    result_digest: str
    result_envelope_digest: str
    probe_log_digest: str
    ledger_head_digest: str
    receipt_digest: str


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


def _without(value: Any, *fields_to_remove: str) -> dict[str, Any]:
    payload = _normal(value)
    for name in fields_to_remove:
        payload.pop(name, None)
    return payload


def _require_nonempty(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AdapterError(f"{field} must be a non-empty string")


def _require_sha(value: str, field: str) -> None:
    if not isinstance(value, str) or len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value.lower()):
        raise AdapterError(f"{field} must be a 40-character Git commit SHA")


def _validate_profile_path(profile_path: str) -> None:
    _require_nonempty(profile_path, "profile_path")
    path = PurePosixPath(profile_path)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "profiles":
        raise AdapterError("profile_path must be a repository-relative path under profiles/")
    if path.suffix != ".json":
        raise AdapterError("profile_path must reference a JSON profile")


def make_github_push_intent(
    *,
    repository: str,
    branch: str,
    profile_path: str,
    source_revision: str,
    domain_id: str,
    task_kind: str = "conformance_probe",
) -> GitHubPushIntent:
    for value, field in ((repository, "repository"), (branch, "branch"), (domain_id, "domain_id")):
        _require_nonempty(value, field)
    if "/" not in repository or repository.startswith("/") or repository.endswith("/"):
        raise AdapterError("repository must use owner/name form")
    if not branch.startswith("colony-run/"):
        raise AdapterError("remote runner branch must start with colony-run/")
    _validate_profile_path(profile_path)
    _require_sha(source_revision, "source_revision")
    if task_kind not in SUPPORTED_TASK_KINDS:
        raise AdapterError(f"unsupported task_kind: {task_kind}")

    seed = {
        "protocol_version": GITHUB_PUSH_PROTOCOL_VERSION,
        "transport_id": GITHUB_PUSH_TRANSPORT_ID,
        "repository": repository,
        "branch": branch,
        "profile_path": profile_path,
        "source_revision": source_revision.lower(),
        "domain_id": domain_id,
        "task_kind": task_kind,
    }
    intent_id = f"bcg-{sha256_digest(seed)[:20]}"
    unsigned = GitHubPushIntent(
        schema_version=GITHUB_PUSH_SCHEMA_VERSION,
        protocol_version=GITHUB_PUSH_PROTOCOL_VERSION,
        intent_id=intent_id,
        transport_id=GITHUB_PUSH_TRANSPORT_ID,
        repository=repository,
        branch=branch,
        profile_path=profile_path,
        source_revision=source_revision.lower(),
        domain_id=domain_id,
        task_kind=task_kind,
        intent_digest="",
    )
    return GitHubPushIntent(
        **{
            **asdict(unsigned),
            "intent_digest": sha256_digest(_without(unsigned, "intent_digest")),
        }
    )


def verify_github_push_intent(intent: GitHubPushIntent) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    try:
        expected = make_github_push_intent(
            repository=intent.repository,
            branch=intent.branch,
            profile_path=intent.profile_path,
            source_revision=intent.source_revision,
            domain_id=intent.domain_id,
            task_kind=intent.task_kind,
        )
    except AdapterError as exc:
        return False, (str(exc),)
    if intent.schema_version != GITHUB_PUSH_SCHEMA_VERSION:
        reasons.append("unsupported GitHub push intent schema version")
    if intent.protocol_version != GITHUB_PUSH_PROTOCOL_VERSION:
        reasons.append("unsupported GitHub push protocol version")
    if intent.transport_id != GITHUB_PUSH_TRANSPORT_ID:
        reasons.append("unexpected transport_id")
    if intent.intent_id != expected.intent_id:
        reasons.append("intent_id does not match immutable intent inputs")
    if intent.intent_digest != expected.intent_digest:
        reasons.append("intent digest mismatch")
    return not reasons, tuple(reasons)


def github_actions_capabilities():
    return make_capabilities(
        adapter_id=GITHUB_PUSH_TRANSPORT_ID,
        provider=GITHUB_PUSH_PROVIDER,
        adapter_version=GITHUB_PUSH_PROTOCOL_VERSION,
        modes=("remote-probe",),
        supports_write=False,
        supports_artifact_refs=True,
        max_parallelism=20,
    )


def _load_intent(path: str | Path) -> GitHubPushIntent:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        intent = GitHubPushIntent(**payload)
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise AdapterError(f"could not load GitHub push intent: {exc}") from exc
    accepted, reasons = verify_github_push_intent(intent)
    if not accepted:
        raise AdapterError("invalid GitHub push intent: " + "; ".join(reasons))
    return intent


def write_github_push_intent(intent: GitHubPushIntent, path: str | Path) -> None:
    Path(path).write_text(json.dumps(_normal(intent), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _require_runner_environment(intent: GitHubPushIntent, env: Mapping[str, str]) -> None:
    repository = env.get("GITHUB_REPOSITORY", "")
    branch = env.get("GITHUB_REF_NAME", "")
    if repository != intent.repository:
        raise AdapterError(f"runner repository mismatch: expected {intent.repository}, got {repository}")
    if branch != intent.branch:
        raise AdapterError(f"runner branch mismatch: expected {intent.branch}, got {branch}")
    for field in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "RUNNER_OS"):
        if not env.get(field):
            raise AdapterError(f"runner environment missing {field}")
    _require_sha(env["GITHUB_SHA"], "GITHUB_SHA")


def _receipt_digest(receipt: GitHubPushReceipt) -> str:
    return sha256_digest(_without(receipt, "receipt_digest"))


def verify_github_push_receipt(
    intent: GitHubPushIntent,
    receipt: GitHubPushReceipt,
    *,
    expected_run_id: str | None = None,
    expected_sha: str | None = None,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    accepted, intent_reasons = verify_github_push_intent(intent)
    if not accepted:
        reasons.extend(intent_reasons)
    if receipt.schema_version != GITHUB_PUSH_SCHEMA_VERSION:
        reasons.append("unsupported GitHub push receipt schema version")
    if receipt.protocol_version != GITHUB_PUSH_PROTOCOL_VERSION:
        reasons.append("unsupported GitHub push receipt protocol version")
    bindings = (
        (receipt.transport_id, GITHUB_PUSH_TRANSPORT_ID, "transport_id"),
        (receipt.intent_id, intent.intent_id, "intent_id"),
        (receipt.intent_digest, intent.intent_digest, "intent_digest"),
        (receipt.repository, intent.repository, "repository"),
        (receipt.branch, intent.branch, "branch"),
    )
    for actual, expected, label in bindings:
        if actual != expected:
            reasons.append(f"receipt {label} mismatch")
    if expected_run_id is not None and receipt.github_run_id != str(expected_run_id):
        reasons.append("receipt GitHub run id mismatch")
    if expected_sha is not None and receipt.github_sha != expected_sha:
        reasons.append("receipt GitHub trigger SHA mismatch")
    if receipt.outcome not in {"built", "failed"}:
        reasons.append("unsupported remote receipt outcome")
    for value, label in (
        (receipt.intent_digest, "intent_digest"),
        (receipt.manifest_digest, "manifest_digest"),
        (receipt.package_digest, "package_digest"),
        (receipt.session_bundle_digest, "session_bundle_digest"),
        (receipt.result_digest, "result_digest"),
        (receipt.result_envelope_digest, "result_envelope_digest"),
        (receipt.probe_log_digest, "probe_log_digest"),
        (receipt.ledger_head_digest, "ledger_head_digest"),
        (receipt.receipt_digest, "receipt_digest"),
    ):
        if not isinstance(value, str) or len(value) != 64:
            reasons.append(f"receipt {label} is not a SHA-256 digest")
    if receipt.receipt_digest != _receipt_digest(receipt):
        reasons.append("receipt digest mismatch")
    return not reasons, tuple(dict.fromkeys(reasons))


def load_github_push_receipt(path: str | Path) -> GitHubPushReceipt:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return GitHubPushReceipt(**payload)
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise AdapterError(f"could not load GitHub push receipt: {exc}") from exc


def execute_github_push_intent(
    intent_path: str | Path,
    *,
    repo_root: str | Path = ".",
    output_dir: str | Path,
    env: Mapping[str, str] | None = None,
) -> GitHubPushReceipt:
    intent = _load_intent(intent_path)
    environment = dict(os.environ if env is None else env)
    _require_runner_environment(intent, environment)
    root = Path(repo_root).resolve()
    profile_file = (root / intent.profile_path).resolve()
    if root not in profile_file.parents:
        raise AdapterError("resolved profile path escapes repository root")

    profile = load_profile(profile_file)
    manifest = compile_run(profile, intent.source_revision)
    package = next((item for item in manifest.packages if item.domain_id == intent.domain_id), None)
    if package is None:
        raise AdapterError(f"remote intent references unknown domain: {intent.domain_id}")
    if package.write_scopes:
        raise AdapterError("GitHub push conformance runner is read-only; Work Package has write scopes")

    ledger = new_ledger(manifest)
    ledger = append_event(
        manifest,
        ledger,
        package_id=package.package_id,
        role="coordinator",
        event_type=EventType.ISSUE.value,
    )

    capabilities = github_actions_capabilities()
    request = compile_session_dispatch_request(
        manifest,
        ledger,
        domain_id=intent.domain_id,
        capabilities=capabilities,
        mode="remote-probe",
    )
    external_run_id = f"gha-{environment['GITHUB_RUN_ID']}-{environment['GITHUB_RUN_ATTEMPT']}"
    dispatch_receipt = accept_session_dispatch(request, capabilities, external_run_id=external_run_id)
    bundle = build_session_bundle(capabilities, request, dispatch_receipt)
    ledger = bind_session_dispatch(manifest, ledger, bundle)
    ledger = start_session_dispatch(manifest, ledger, bundle)

    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log_text = completed.stdout or ""
    log_digest = sha256_digest({"stdout": log_text, "exit_code": completed.returncode})
    evidence = (
        f"github-actions-run:{environment['GITHUB_RUN_ID']}",
        f"remote-probe-log-sha256:{log_digest}",
    )
    if completed.returncode == 0:
        result = build_session_result_envelope(
            bundle,
            manifest,
            outcome="built",
            revision=environment["GITHUB_SHA"].lower(),
            evidence_locators=evidence,
        )
        outcome = "built"
    else:
        result = build_session_result_envelope(
            bundle,
            manifest,
            outcome="failed",
            evidence_locators=evidence,
        )
        outcome = "failed"
    ledger = submit_session_result(manifest, ledger, bundle, result)

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / "probe.log").write_text(log_text, encoding="utf-8")
    (output / "manifest.json").write_text(json.dumps(manifest_to_dict(manifest), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "session-bundle.json").write_text(json.dumps(_normal(bundle), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "result-envelope.json").write_text(json.dumps(_normal(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "ledger.json").write_text(json.dumps(ledger_to_dict(ledger), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    unsigned = GitHubPushReceipt(
        schema_version=GITHUB_PUSH_SCHEMA_VERSION,
        protocol_version=GITHUB_PUSH_PROTOCOL_VERSION,
        transport_id=GITHUB_PUSH_TRANSPORT_ID,
        intent_id=intent.intent_id,
        intent_digest=intent.intent_digest,
        repository=intent.repository,
        branch=intent.branch,
        github_run_id=environment["GITHUB_RUN_ID"],
        github_run_attempt=environment["GITHUB_RUN_ATTEMPT"],
        github_sha=environment["GITHUB_SHA"].lower(),
        runner_os=environment["RUNNER_OS"],
        python_version=sys.version.split()[0],
        run_id=manifest.run_id,
        manifest_digest=manifest.manifest_digest,
        package_id=package.package_id,
        package_digest=package.package_digest,
        dispatch_id=request.dispatch_id,
        dispatch_attempt=request.dispatch_attempt,
        session_bundle_digest=bundle.bundle_digest,
        outcome=outcome,
        result_digest=result.result_digest,
        result_envelope_digest=result.envelope_digest,
        probe_log_digest=log_digest,
        ledger_head_digest=ledger.head_event_digest,
        receipt_digest="",
    )
    receipt = GitHubPushReceipt(**{**asdict(unsigned), "receipt_digest": _receipt_digest(unsigned)})
    (output / "receipt.json").write_text(json.dumps(_normal(receipt), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


__all__ = [
    "GITHUB_PUSH_PROTOCOL_VERSION",
    "GitHubPushIntent",
    "GitHubPushReceipt",
    "execute_github_push_intent",
    "github_actions_capabilities",
    "load_github_push_receipt",
    "make_github_push_intent",
    "verify_github_push_intent",
    "verify_github_push_receipt",
    "write_github_push_intent",
]
