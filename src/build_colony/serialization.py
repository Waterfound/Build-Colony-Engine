from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import VerificationError
from .models import Blocker, BlockerKind, Evidence, WorkerResult


def _evidence_from_dict(raw: dict[str, Any]) -> Evidence:
    try:
        return Evidence(
            gate=str(raw.get("gate", "")),
            kind=str(raw["kind"]),
            locator=str(raw["locator"]),
            sha256=str(raw["sha256"]) if raw.get("sha256") is not None else None,
            note=str(raw["note"]) if raw.get("note") is not None else None,
        )
    except KeyError as exc:
        raise VerificationError(f"evidence missing required field: {exc.args[0]}") from exc


def worker_results_from_dict(data: dict[str, Any]) -> dict[str, WorkerResult]:
    raw_results = data.get("results")
    if not isinstance(raw_results, list):
        raise VerificationError("results document must contain a results list")
    parsed: dict[str, WorkerResult] = {}
    for index, raw in enumerate(raw_results):
        if not isinstance(raw, dict):
            raise VerificationError(f"results[{index}] must be an object")
        try:
            domain_id = str(raw["domain_id"])
            outcome = str(raw["outcome"])
        except KeyError as exc:
            raise VerificationError(f"results[{index}] missing field: {exc.args[0]}") from exc
        if domain_id in parsed:
            raise VerificationError(f"duplicate result for domain: {domain_id}")

        evidence = tuple(_evidence_from_dict(item) for item in raw.get("evidence", []))
        blocker = None
        if raw.get("blocker") is not None:
            blocker_raw = raw["blocker"]
            if not isinstance(blocker_raw, dict):
                raise VerificationError(f"results[{index}].blocker must be an object")
            try:
                blocker = Blocker(
                    kind=BlockerKind(blocker_raw["kind"]),
                    detail=str(blocker_raw["detail"]),
                    evidence=tuple(_evidence_from_dict(item) for item in blocker_raw.get("evidence", [])),
                )
            except (KeyError, ValueError) as exc:
                raise VerificationError(f"invalid blocker for domain {domain_id}: {exc}") from exc
        try:
            parsed[domain_id] = WorkerResult(
                domain_id=domain_id,
                outcome=outcome,
                evidence=evidence,
                blocker=blocker,
                revision=str(raw["revision"]) if raw.get("revision") is not None else None,
            )
        except ValueError as exc:
            raise VerificationError(f"invalid worker result for domain {domain_id}: {exc}") from exc
    return parsed


def load_worker_results(path: str | Path) -> dict[str, WorkerResult]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VerificationError(f"could not load worker results: {exc}") from exc
    if not isinstance(data, dict):
        raise VerificationError("results root must be an object")
    return worker_results_from_dict(data)
