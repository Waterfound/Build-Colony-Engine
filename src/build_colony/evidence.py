from __future__ import annotations

import hashlib
from pathlib import Path

from .models import Domain, Evidence, VerificationResult, WorkerResult


NON_PROBATIVE_KINDS = {"claim", "narrative", "self_report"}


class EvidenceVerifier:
    """Independently validates the structure and, when possible, bytes of evidence."""

    def __init__(self, artifact_root: str | Path | None = None) -> None:
        self.artifact_root = Path(artifact_root).resolve() if artifact_root is not None else None

    def verify(self, domain: Domain, result: WorkerResult) -> VerificationResult:
        if result.domain_id != domain.id:
            return VerificationResult(
                domain_id=domain.id,
                accepted=False,
                status="rejected",
                reasons=(f"worker result is for {result.domain_id}, expected {domain.id}",),
            )

        if result.outcome == "failed":
            return VerificationResult(
                domain_id=domain.id,
                accepted=False,
                status="failed",
                reasons=("worker reported failure",),
            )

        if result.outcome == "blocked":
            blocker = result.blocker
            assert blocker is not None
            if blocker.kind not in domain.permitted_blockers:
                return VerificationResult(
                    domain_id=domain.id,
                    accepted=False,
                    status="rejected",
                    reasons=(f"blocker kind {blocker.kind.value} is not permitted by the profile",),
                )
            if not blocker.detail.strip():
                return VerificationResult(
                    domain_id=domain.id,
                    accepted=False,
                    status="rejected",
                    reasons=("blocker detail cannot be empty",),
                )
            if not blocker.evidence:
                return VerificationResult(
                    domain_id=domain.id,
                    accepted=False,
                    status="rejected",
                    reasons=("external blocker requires independent evidence",),
                )
            blocker_reasons = self._validate_evidence(blocker.evidence)
            if blocker_reasons:
                return VerificationResult(
                    domain_id=domain.id,
                    accepted=False,
                    status="rejected",
                    reasons=tuple(blocker_reasons),
                )
            return VerificationResult(
                domain_id=domain.id,
                accepted=True,
                status="externally_blocked",
                reasons=(f"verified declared blocker: {blocker.kind.value}",),
            )

        malformed = self._validate_evidence(result.evidence)
        if malformed:
            return VerificationResult(
                domain_id=domain.id,
                accepted=False,
                status="rejected",
                reasons=tuple(malformed),
            )

        satisfied: list[str] = []
        reasons: list[str] = []
        for gate in domain.gates:
            matches = [
                evidence
                for evidence in result.evidence
                if evidence.gate == gate.id
                and evidence.kind in gate.accepted_kinds
                and evidence.kind not in NON_PROBATIVE_KINDS
            ]
            if len(matches) < gate.minimum:
                reasons.append(
                    f"gate {gate.id} requires {gate.minimum} evidence item(s) of kind "
                    f"{list(gate.accepted_kinds)}; found {len(matches)}"
                )
            else:
                satisfied.append(gate.id)

        if reasons:
            return VerificationResult(
                domain_id=domain.id,
                accepted=False,
                status="rejected",
                reasons=tuple(reasons),
                satisfied_gates=tuple(satisfied),
            )

        return VerificationResult(
            domain_id=domain.id,
            accepted=True,
            status="verified",
            satisfied_gates=tuple(satisfied),
        )

    def _validate_evidence(self, evidence_items: tuple[Evidence, ...]) -> list[str]:
        reasons: list[str] = []
        for evidence in evidence_items:
            if evidence.kind in NON_PROBATIVE_KINDS:
                reasons.append(f"non-probative evidence kind is not accepted: {evidence.kind}")
                continue
            if not evidence.locator.strip():
                reasons.append("evidence locator cannot be empty")
                continue
            if evidence.sha256 is not None:
                digest = evidence.sha256.lower()
                if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                    reasons.append(f"invalid sha256 for evidence {evidence.locator}")
                    continue
                if self.artifact_root is not None:
                    path = (self.artifact_root / evidence.locator).resolve()
                    try:
                        path.relative_to(self.artifact_root)
                    except ValueError:
                        reasons.append(f"evidence escapes artifact root: {evidence.locator}")
                        continue
                    if not path.is_file():
                        reasons.append(f"evidence artifact does not exist: {evidence.locator}")
                        continue
                    actual = hashlib.sha256(path.read_bytes()).hexdigest()
                    if actual != digest:
                        reasons.append(f"sha256 mismatch for evidence {evidence.locator}")
        return reasons
