from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .evidence import EvidenceVerifier
from .errors import VerificationError
from .models import (
    ColonyAssessment,
    ColonyVerdict,
    IntegrationItem,
    Profile,
    VerificationResult,
    WorkerResult,
)
from .scheduler import Schedule, build_schedule


class ColonyEngine:
    """Deterministic orchestration kernel for Build Colony."""

    def __init__(self, profile: Profile, artifact_root: str | Path | None = None) -> None:
        self.profile = profile
        self.schedule: Schedule = build_schedule(profile)
        self.verifier = EvidenceVerifier(artifact_root=artifact_root)
        self._domains = {domain.id: domain for domain in profile.domains}

    def plan(self) -> Schedule:
        return self.schedule

    def verify(self, results: Mapping[str, WorkerResult]) -> dict[str, VerificationResult]:
        unknown = sorted(set(results) - set(self._domains))
        if unknown:
            raise VerificationError(f"results contain unknown domains: {unknown}")

        verdicts: dict[str, VerificationResult] = {}
        for wave in self.schedule.waves:
            for domain_id in wave:
                domain = self._domains[domain_id]
                dependency_verdicts = [verdicts[dependency] for dependency in domain.dependencies]

                failed_dependencies = [
                    verdict.domain_id
                    for verdict in dependency_verdicts
                    if verdict.status in {"failed", "rejected", "dependency_failed"}
                ]
                if failed_dependencies:
                    verdicts[domain_id] = VerificationResult(
                        domain_id=domain_id,
                        accepted=False,
                        status="dependency_failed",
                        reasons=(f"failed dependency: {sorted(failed_dependencies)}",),
                    )
                    continue

                externally_blocked_dependencies = [
                    verdict.domain_id
                    for verdict in dependency_verdicts
                    if verdict.status in {"externally_blocked", "dependency_blocked"}
                ]
                if externally_blocked_dependencies:
                    verdicts[domain_id] = VerificationResult(
                        domain_id=domain_id,
                        accepted=False,
                        status="dependency_blocked",
                        reasons=(
                            f"unreachable until external blocker clears in: "
                            f"{sorted(externally_blocked_dependencies)}",
                        ),
                    )
                    continue

                waiting_dependencies = [
                    verdict.domain_id
                    for verdict in dependency_verdicts
                    if verdict.status in {"pending", "dependency_waiting"}
                ]
                if waiting_dependencies:
                    verdicts[domain_id] = VerificationResult(
                        domain_id=domain_id,
                        accepted=False,
                        status="dependency_waiting",
                        reasons=(f"waiting for dependency: {sorted(waiting_dependencies)}",),
                    )
                    continue

                result = results.get(domain_id)
                if result is None:
                    verdicts[domain_id] = VerificationResult(
                        domain_id=domain_id,
                        accepted=False,
                        status="pending",
                        reasons=("no worker result supplied",),
                    )
                else:
                    verdicts[domain_id] = self.verifier.verify(domain, result)
        return verdicts

    def integration_plan(
        self,
        results: Mapping[str, WorkerResult],
        verdicts: Mapping[str, VerificationResult] | None = None,
    ) -> tuple[IntegrationItem, ...]:
        checked = dict(verdicts or self.verify(results))
        items: list[IntegrationItem] = []
        for wave_number, wave in enumerate(self.schedule.waves, start=1):
            for domain_id in sorted(wave):
                verdict = checked[domain_id]
                if verdict.accepted and verdict.status == "verified":
                    result = results[domain_id]
                    items.append(
                        IntegrationItem(
                            domain_id=domain_id,
                            revision=result.revision,
                            wave=wave_number,
                        )
                    )
        return tuple(items)

    def assess(
        self,
        results: Mapping[str, WorkerResult],
        verdicts: Mapping[str, VerificationResult] | None = None,
    ) -> ColonyAssessment:
        checked = dict(verdicts or self.verify(results))
        reached = sorted(
            domain_id for domain_id, verdict in checked.items()
            if verdict.accepted and verdict.status == "verified"
        )
        blocked = sorted(
            domain_id for domain_id, verdict in checked.items()
            if verdict.accepted and verdict.status == "externally_blocked"
        )
        dependency_blocked = sorted(
            domain_id for domain_id, verdict in checked.items()
            if verdict.status == "dependency_blocked"
        )
        pending = sorted(
            domain_id for domain_id, verdict in checked.items()
            if verdict.status in {"pending", "dependency_waiting"}
        )
        failed = sorted(
            domain_id for domain_id, verdict in checked.items()
            if verdict.status in {"failed", "rejected", "dependency_failed"}
        )

        if failed:
            verdict = ColonyVerdict.ATTENTION_REQUIRED
            note = "At least one domain failed independent verification or is downstream of a failed domain."
        elif pending:
            verdict = ColonyVerdict.CONTINUE
            note = "Reachable work remains. Continue only according to the dependency schedule."
        else:
            verdict = ColonyVerdict.REACHABLE_CEILINGS_REACHED
            note = (
                "All currently reachable ceilings are independently verified; remaining unreachable work "
                "is blocked only by verified/profile-permitted external constraints. This is not a "
                "declaration of project completion."
            )

        return ColonyAssessment(
            verdict=verdict,
            reached=tuple(reached),
            externally_blocked=tuple(blocked),
            dependency_blocked=tuple(dependency_blocked),
            pending=tuple(pending),
            failed=tuple(failed),
            project_complete=False,
            note=note,
        )
