from dataclasses import replace
import unittest

from build_colony.errors import SessionError, StateError
from build_colony.ledger import append_event, next_dispatch_attempt, replay_ledger
from build_colony.models import BlockerKind, Domain, EvidenceGate, Profile
from build_colony.protocol import compile_run
from build_colony.runner_adapter import make_capabilities
from build_colony.runner_session_strict import (
    accept_session_dispatch,
    bind_session_dispatch,
    build_reference_session_bundle,
    build_session_bundle,
    build_session_result_envelope,
    compile_session_dispatch_request,
    revoke_session_dispatch,
    start_session_dispatch,
    submit_session_result,
    verify_session_bundle,
    verify_session_result_envelope,
)
from build_colony.state_models import EventType, PackageState, new_ledger


class RunnerSessionTests(unittest.TestCase):
    def setUp(self):
        gate = EvidenceGate(id="g", description="gate", accepted_kinds=("test",))
        self.profile = Profile(
            project="session-fixture",
            profile_version="1",
            goal="exercise retry-aware runner sessions",
            invariants=("preserve invariant",),
            forbidden_actions=("do not bypass verification",),
            domains=(
                Domain(
                    id="a",
                    objective="a",
                    write_scopes=("src/a",),
                    gates=(gate,),
                    permitted_blockers=(BlockerKind.HARDWARE,),
                ),
            ),
        )
        self.manifest = compile_run(self.profile, "source-session-1")
        self.package = self.manifest.packages[0]
        ledger = new_ledger(self.manifest)
        self.issued = append_event(
            self.manifest,
            ledger,
            package_id=self.package.package_id,
            role="coordinator",
            event_type=EventType.ISSUE.value,
        )

    def test_same_unbound_attempt_is_deterministic(self):
        first = build_reference_session_bundle(self.manifest, self.issued, domain_id="a")
        second = build_reference_session_bundle(self.manifest, self.issued, domain_id="a")
        self.assertEqual(first, second)
        self.assertEqual(first.request.dispatch_attempt, 1)
        self.assertTrue(verify_session_bundle(first, self.manifest)[0])

    def test_bind_start_submit_happy_path(self):
        bundle = build_reference_session_bundle(self.manifest, self.issued, domain_id="a")
        ledger = bind_session_dispatch(self.manifest, self.issued, bundle)
        self.assertEqual(replay_ledger(self.manifest, ledger)["a"], PackageState.DISPATCHED)
        ledger = start_session_dispatch(self.manifest, ledger, bundle)
        envelope = build_session_result_envelope(
            bundle,
            self.manifest,
            outcome="built",
            revision="revision-a-1",
            evidence_locators=("test:primary",),
        )
        ledger = submit_session_result(self.manifest, ledger, bundle, envelope)
        self.assertEqual(replay_ledger(self.manifest, ledger)["a"], PackageState.SUBMITTED_BUILT)

    def test_revoke_before_start_advances_attempt(self):
        first = build_reference_session_bundle(self.manifest, self.issued, domain_id="a")
        ledger = bind_session_dispatch(self.manifest, self.issued, first)
        ledger = revoke_session_dispatch(self.manifest, ledger, first, reason="runner unavailable")
        self.assertEqual(replay_ledger(self.manifest, ledger)["a"], PackageState.ISSUED)
        self.assertEqual(next_dispatch_attempt(self.manifest, ledger, "a"), 2)

        second = build_reference_session_bundle(self.manifest, ledger, domain_id="a")
        self.assertEqual(second.request.dispatch_attempt, 2)
        self.assertNotEqual(first.request.dispatch_id, second.request.dispatch_id)
        self.assertNotEqual(first.receipt.external_run_id, second.receipt.external_run_id)
        self.assertNotEqual(first.bundle_digest, second.bundle_digest)

    def test_active_dispatch_can_be_revoked_explicitly(self):
        first = build_reference_session_bundle(self.manifest, self.issued, domain_id="a")
        ledger = bind_session_dispatch(self.manifest, self.issued, first)
        ledger = start_session_dispatch(self.manifest, ledger, first)
        ledger = revoke_session_dispatch(self.manifest, ledger, first, reason="runner lost after start")
        self.assertEqual(replay_ledger(self.manifest, ledger)["a"], PackageState.ISSUED)
        self.assertEqual(next_dispatch_attempt(self.manifest, ledger, "a"), 2)

    def test_stale_result_from_revoked_attempt_is_rejected(self):
        first = build_reference_session_bundle(self.manifest, self.issued, domain_id="a")
        ledger = bind_session_dispatch(self.manifest, self.issued, first)
        ledger = start_session_dispatch(self.manifest, ledger, first)
        ledger = revoke_session_dispatch(self.manifest, ledger, first, reason="replace runner")

        second = build_reference_session_bundle(self.manifest, ledger, domain_id="a")
        ledger = bind_session_dispatch(self.manifest, ledger, second)
        ledger = start_session_dispatch(self.manifest, ledger, second)

        stale = build_session_result_envelope(
            first,
            self.manifest,
            outcome="built",
            revision="stale-revision",
            evidence_locators=("test:stale",),
        )
        with self.assertRaises(StateError):
            submit_session_result(self.manifest, ledger, first, stale)

        current = build_session_result_envelope(
            second,
            self.manifest,
            outcome="built",
            revision="current-revision",
            evidence_locators=("test:current",),
        )
        ledger = submit_session_result(self.manifest, ledger, second, current)
        self.assertEqual(replay_ledger(self.manifest, ledger)["a"], PackageState.SUBMITTED_BUILT)

    def test_old_attempt_cannot_be_rebound_after_revocation(self):
        first = build_reference_session_bundle(self.manifest, self.issued, domain_id="a")
        ledger = bind_session_dispatch(self.manifest, self.issued, first)
        ledger = revoke_session_dispatch(self.manifest, ledger, first, reason="retry")
        with self.assertRaises(StateError):
            append_event(
                self.manifest,
                ledger,
                package_id=self.package.package_id,
                role="coordinator",
                event_type=EventType.BIND_DISPATCH.value,
                payload={
                    "dispatch_id": first.request.dispatch_id,
                    "dispatch_receipt_digest": first.receipt.receipt_digest,
                    "dispatch_attempt": 1,
                    "session_bundle_digest": first.bundle_digest,
                },
            )

    def test_result_attempt_tampering_is_detected(self):
        bundle = build_reference_session_bundle(self.manifest, self.issued, domain_id="a")
        envelope = build_session_result_envelope(
            bundle,
            self.manifest,
            outcome="built",
            revision="revision-a",
            evidence_locators=("test:primary",),
        )
        tampered = replace(envelope, dispatch_attempt=2)
        accepted, reasons = verify_session_result_envelope(tampered, bundle, self.manifest)
        self.assertFalse(accepted)
        self.assertTrue(any("dispatch_attempt" in reason or "digest mismatch" in reason for reason in reasons))

    def test_session_protocol_version_tampering_is_rejected(self):
        bundle = build_reference_session_bundle(self.manifest, self.issued, domain_id="a")
        tampered = replace(bundle, session_protocol_version="0.0.4")
        accepted, reasons = verify_session_bundle(tampered, self.manifest)
        self.assertFalse(accepted)
        self.assertTrue(any("protocol version" in reason for reason in reasons))

    def test_revocation_does_not_permit_blocker_policy_bypass(self):
        first = build_reference_session_bundle(self.manifest, self.issued, domain_id="a")
        ledger = bind_session_dispatch(self.manifest, self.issued, first)
        ledger = revoke_session_dispatch(self.manifest, ledger, first, reason="retry")
        second = build_reference_session_bundle(self.manifest, ledger, domain_id="a")
        with self.assertRaises(SessionError):
            build_session_result_envelope(
                second,
                self.manifest,
                outcome="blocked",
                blocker_kind="authority",
                evidence_locators=("constraint:not-authorized",),
            )

    def test_attention_freeze_blocks_session_dispatch(self):
        gate = EvidenceGate(id="g", description="gate", accepted_kinds=("test",))
        profile = Profile(
            project="attention-fixture",
            profile_version="1",
            goal="freeze new sessions after failure",
            invariants=(),
            forbidden_actions=(),
            domains=(
                Domain(id="a", objective="a", gates=(gate,)),
                Domain(id="b", objective="b", gates=(gate,)),
            ),
        )
        manifest = compile_run(profile, "attention-source")
        packages = {package.domain_id: package for package in manifest.packages}
        ledger = new_ledger(manifest)
        for domain in ("a", "b"):
            ledger = append_event(
                manifest,
                ledger,
                package_id=packages[domain].package_id,
                role="coordinator",
                event_type=EventType.ISSUE.value,
            )

        first = build_reference_session_bundle(manifest, ledger, domain_id="a")
        ledger = bind_session_dispatch(manifest, ledger, first)
        ledger = start_session_dispatch(manifest, ledger, first)
        failed = build_session_result_envelope(first, manifest, outcome="failed")
        ledger = submit_session_result(manifest, ledger, first, failed)

        with self.assertRaises(SessionError):
            build_reference_session_bundle(manifest, ledger, domain_id="b")

    def test_max_parallelism_is_rechecked_at_bind(self):
        gate = EvidenceGate(id="g", description="gate", accepted_kinds=("test",))
        profile = Profile(
            project="capacity-fixture",
            profile_version="1",
            goal="enforce adapter capacity",
            invariants=(),
            forbidden_actions=(),
            domains=(
                Domain(id="a", objective="a", gates=(gate,)),
                Domain(id="b", objective="b", gates=(gate,)),
            ),
        )
        manifest = compile_run(profile, "capacity-source")
        packages = {package.domain_id: package for package in manifest.packages}
        ledger = new_ledger(manifest)
        for domain in ("a", "b"):
            ledger = append_event(
                manifest,
                ledger,
                package_id=packages[domain].package_id,
                role="coordinator",
                event_type=EventType.ISSUE.value,
            )

        caps = make_capabilities(
            adapter_id="single-slot",
            provider="fixture",
            adapter_version="1",
            modes=("execute",),
            supports_write=True,
            supports_artifact_refs=True,
            max_parallelism=1,
        )
        request_a = compile_session_dispatch_request(
            manifest, ledger, domain_id="a", capabilities=caps
        )
        receipt_a = accept_session_dispatch(request_a, caps, external_run_id="run-a")
        bundle_a = build_session_bundle(caps, request_a, receipt_a)

        request_b = compile_session_dispatch_request(
            manifest, ledger, domain_id="b", capabilities=caps
        )
        receipt_b = accept_session_dispatch(request_b, caps, external_run_id="run-b")
        bundle_b = build_session_bundle(caps, request_b, receipt_b)

        ledger = bind_session_dispatch(manifest, ledger, bundle_a)
        with self.assertRaises(SessionError):
            bind_session_dispatch(manifest, ledger, bundle_b)

        ledger = revoke_session_dispatch(manifest, ledger, bundle_a, reason="release slot")
        ledger = bind_session_dispatch(manifest, ledger, bundle_b)
        self.assertEqual(replay_ledger(manifest, ledger)["b"], PackageState.DISPATCHED)


if __name__ == "__main__":
    unittest.main()
