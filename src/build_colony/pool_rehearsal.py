from __future__ import annotations

from dataclasses import dataclass

from .errors import PoolError
from .pool_attempt import PoolDispatchAttempt, bind_dispatch_attempt, verify_dispatch_attempt
from .protocol import RunManifest
from .runner_pool import DispatchPlan, RunnerRegistry
from .runner_session import SessionResultEnvelope
from .runner_session_strict import (
    build_session_result_envelope,
    start_session_dispatch,
    submit_session_result,
)
from .state_models import RunLedger


@dataclass(frozen=True)
class PoolRehearsalResult:
    completed_domains: tuple[str, ...]
    result_envelopes: tuple[SessionResultEnvelope, ...]
    ledger: RunLedger


def complete_reference_attempt(
    attempt: PoolDispatchAttempt,
    plan: DispatchPlan,
    manifest: RunManifest,
    planning_ledger: RunLedger,
    registry: RunnerRegistry,
) -> PoolRehearsalResult:
    accepted, reasons = verify_dispatch_attempt(
        attempt, plan, manifest, planning_ledger, registry
    )
    if not accepted:
        raise PoolError("cannot rehearse invalid pool attempt: " + "; ".join(reasons))
    if not attempt.complete:
        raise PoolError("cannot rehearse incomplete pool attempt")

    updated = bind_dispatch_attempt(attempt, plan, manifest, planning_ledger, registry)
    envelopes: list[SessionResultEnvelope] = []
    completed: list[str] = []
    for entry in sorted(attempt.entries, key=lambda item: item.ordinal):
        bundle = entry.bundle
        domain_id = bundle.request.domain_id
        updated = start_session_dispatch(manifest, updated, bundle)
        envelope = build_session_result_envelope(
            bundle,
            manifest,
            outcome="built",
            revision=f"reference-pool/{domain_id}/attempt-{bundle.request.dispatch_attempt}",
            evidence_locators=("reference:session-pool-rehearsal",),
        )
        updated = submit_session_result(manifest, updated, bundle, envelope)
        envelopes.append(envelope)
        completed.append(domain_id)
    return PoolRehearsalResult(
        completed_domains=tuple(completed),
        result_envelopes=tuple(envelopes),
        ledger=updated,
    )
