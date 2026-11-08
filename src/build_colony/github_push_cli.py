from __future__ import annotations

import argparse
import json
from pathlib import Path

from .errors import AdapterError, RemotePoolError
from .github_push_strict import (
    execute_github_push_intent_strict,
    load_verified_github_push_intent,
)
from .github_push_transport import (
    GitHubPushIntent,
    load_github_push_receipt,
    make_github_push_intent,
    verify_github_push_intent,
    verify_github_push_receipt,
    write_github_push_intent,
)
from .github_source_boundary import (
    inspect_github_source_boundary,
    write_source_boundary_evidence,
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


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="build-colony-github-push")
    sub = parser.add_subparsers(dest="command", required=True)

    intent = sub.add_parser("intent", help="create a deterministic GitHub push remote-runner intent")
    intent.add_argument("--repository", required=True)
    intent.add_argument("--branch", required=True)
    intent.add_argument("--profile-path", required=True)
    intent.add_argument("--source-revision", required=True)
    intent.add_argument("--domain", required=True)
    intent.add_argument("--task-kind", default="conformance_probe")
    intent.add_argument("--output", required=True)

    check_intent = sub.add_parser("check-intent", help="verify a remote-runner intent")
    check_intent.add_argument("intent")

    source_check = sub.add_parser(
        "source-check",
        help="prove that the launch commit differs from source_revision only by remote intent metadata",
    )
    source_check.add_argument("intent")
    source_check.add_argument("--repo-root", default=".")
    source_check.add_argument("--trigger-sha", required=True)
    source_check.add_argument("--output", required=True)

    execute = sub.add_parser(
        "execute",
        help="execute a source-boundary-validated intent on the GitHub-hosted runner",
    )
    execute.add_argument("intent")
    execute.add_argument("--repo-root", default=".")
    execute.add_argument("--output-dir", required=True)

    check_receipt = sub.add_parser("check-receipt", help="verify a returned GitHub push receipt")
    check_receipt.add_argument("intent")
    check_receipt.add_argument("receipt")
    check_receipt.add_argument("--expected-run-id")
    check_receipt.add_argument("--expected-sha")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "intent":
            intent = make_github_push_intent(
                repository=args.repository,
                branch=args.branch,
                profile_path=args.profile_path,
                source_revision=args.source_revision,
                domain_id=args.domain,
                task_kind=args.task_kind,
            )
            write_github_push_intent(intent, args.output)
            print(json.dumps({"intent_id": intent.intent_id, "intent_digest": intent.intent_digest}, sort_keys=True))
            return 0

        if args.command == "check-intent":
            intent = _load_intent(args.intent)
            print(json.dumps({"accepted": True, "intent_id": intent.intent_id}, sort_keys=True))
            return 0

        if args.command == "source-check":
            intent = load_verified_github_push_intent(args.intent)
            boundary = inspect_github_source_boundary(
                intent,
                repo_root=args.repo_root,
                trigger_sha=args.trigger_sha,
            )
            write_source_boundary_evidence(boundary, args.output)
            print(
                json.dumps(
                    {
                        "accepted": True,
                        "boundary_digest": boundary.boundary_digest,
                        "source_revision": boundary.source_revision,
                        "trigger_sha": boundary.trigger_sha,
                        "changed_paths": list(boundary.changed_paths),
                    },
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "execute":
            receipt, boundary = execute_github_push_intent_strict(
                args.intent,
                repo_root=args.repo_root,
                output_dir=args.output_dir,
            )
            print(
                json.dumps(
                    {
                        "outcome": receipt.outcome,
                        "receipt_digest": receipt.receipt_digest,
                        "source_boundary_digest": boundary.boundary_digest,
                    },
                    sort_keys=True,
                )
            )
            return 0 if receipt.outcome == "built" else 1

        if args.command == "check-receipt":
            intent = _load_intent(args.intent)
            receipt = load_github_push_receipt(args.receipt)
            accepted, reasons = verify_github_push_receipt(
                intent,
                receipt,
                expected_run_id=args.expected_run_id,
                expected_sha=args.expected_sha,
            )
            print(json.dumps({"accepted": accepted, "reasons": list(reasons)}, sort_keys=True))
            return 0 if accepted else 1
    except (AdapterError, RemotePoolError) as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}, sort_keys=True))
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
