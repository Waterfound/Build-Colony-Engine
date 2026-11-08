from dataclasses import replace
import unittest

from build_colony.errors import StateError
from build_colony.ledger import append_event, execution_frontier, replay_ledger, verify_ledger
from build_colony.models import BlockerKind, Domain, EvidenceGate, Profile
from build_colony.protocol import compile_run
from build_colony.state_models import EventType, PackageState, new_ledger


RESULT_DIGEST = "a" * 64
OTHER_RESULT_DIGEST = "c" * 64
VERIFY_DIGEST = "b" * 64
RECEIPT_DIGEST = "d" * 64
OTHER_RECEIPT_DIGEST = "f" * 64
ENVELOPE_DIGEST = "e" * 64


class StateMachineTests(unittest.TestCase):
    def setUp(self):
        gate = EvidenceGate(id="g", description="gate", accepted_kinds=("test",))
        self.profile = Profile(
            project="state-fixture",
            profile_version="1",
            goal="exercise state machine",
            invariants=("preserve invariant",),
            forbidden_actions=("do not bypass roles",),
            domains=(
                Domain(
                    id="a",
                    objective="a",
                    write_scopes=("shared",),
                    gates=(gate,),
                    permitted_blockers=(BlockerKind.HARDWARE,),
                ),
                Domain(id="b", objective="b", write_scopes=("other",), gates=(gate,)),
                Domain(id="c", objective="c", write_scopes=("shared",), gates=(gate,)),
                Domain(id="d", objective="d", dependencies=("b",), gates=(gate,)),
                Domain(id="e", objective="e", dependencies=("a",), gates=(gate,)),
            ),
        )
        self.manifest = compile_run(self.profile, "source-state-1")
        self.packages = {package.domain_id: package.package_id for package in self.manifest.packages}

    def _dispatch_id(self, domain):
        return f"dispatch-{domain}"

    def _event(self, ledger, domain, role, event_type, payload=None):
        return append_event(
            self.manifest,
            ledger,
            package_id=self.packages[domain],
            role=role,
            event_type=event_type,
            payload=payload,
        )

    def _issue_and_bind(self, ledger, domain):
        ledger = self._event(ledger, domain, "coordinator", EventType.ISSUE.value)
        ledger = self._event(
            ledger,
            domain,
            "coordinator",
            EventType.BIND_DISPATCH.value,
            {
                "dispatch_id": self._dispatch_id(domain),
                "dispatch_receipt_digest": RECEIPT_DIGEST,
            },
        )
        return ledger

    def _start(self, ledger, domain):
        return self._event(
            ledger,
            domain,
            "builder",
            EventType.START.value,
            {
                "dispatch_id": self._dispatch_id(domain),
                "dispatch_receipt_digest": RECEIPT_DIGEST,
            },
        )

    def _submit_built(self, ledger, domain):
        revision = f"revision-{domain}"
        ledger = self._issue_and_bind(ledger, domain)
        ledger = self._start(ledger, domain)
        ledger = self._event(
            ledger,
            domain,
            "builder",
            EventType.SUBMIT_BUILT.value,
            {
                "dispatch_id": self._dispatch_id(domain),
                "result_envelope_digest": ENVELOPE_DIGEST,
                "result_digest": RESULT_DIGEST,
                "revision": revision,
            },
        )
        ledger = self._event(
            ledger,
            domain,
            "verifier",
            EventType.VERIFY_ACCEPT.value,
            {"verification_digest": VERIFY_DIGEST, "result_digest": RESULT_DIGEST},
        )
        return ledger

    def _integrate(self, ledger, domain):
        return self._event(
            ledger,
            domain,
            "integrator",
            EventType.INTEGRATE.value,
            {"revision": f"revision-{domain}"},
        )

    def test_initial_frontier_respects_dependencies_and_serialization(self):
        frontier = execution_frontier(self.manifest, new_ledger(self.manifest))
        self.assertEqual(frontier.ready, ("a", "b"))
        self.assertEqual(frontier.dispatchable, ())
        self.assertEqual(frontier.waiting_serialization, ("c",))
        self.assertEqual(frontier.waiting_dependencies, ("d", "e"))

    def test_issued_package_becomes_dispatchable_not_active(self):
        ledger = self._event(new_ledger(self.manifest), "a", "coordinator", EventType.ISSUE.value)
        frontier = execution_frontier(self.manifest, ledger)
        self.assertIn("a", frontier.dispatchable)
        self.assertNotIn("a", frontier.active)

    def test_role_separation_blocks_builder_from_issuing(self):
        ledger = new_ledger(self.manifest)
        with self.assertRaises(StateError):
            self._event(ledger, "a", "builder", EventType.ISSUE.value)

    def test_builder_cannot_start_before_dispatch_is_bound(self):
        ledger = self._event(new_ledger(self.manifest), "a", "coordinator", EventType.ISSUE.value)
        with self.assertRaises(StateError):
            self._start(ledger, "a")

    def test_builder_start_must_match_bound_receipt(self):
        ledger = self._issue_and_bind(new_ledger(self.manifest), "a")
        with self.assertRaises(StateError):
            self._event(
                ledger,
                "a",
                "builder",
                EventType.START.value,
                {
                    "dispatch_id": self._dispatch_id("a"),
                    "dispatch_receipt_digest": OTHER_RECEIPT_DIGEST,
                },
            )

    def test_dependency_waits_for_integration_not_only_verification(self):
        ledger = self._submit_built(new_ledger(self.manifest), "b")
        frontier = execution_frontier(self.manifest, ledger)
        self.assertIn("d", frontier.waiting_dependencies)
        self.assertEqual(frontier.next_integratable, "b")
        ledger = self._integrate(ledger, "b")
        frontier = execution_frontier(self.manifest, ledger)
        self.assertIn("d", frontier.ready)

    def test_shared_scope_waits_for_predecessor_integration(self):
        ledger = self._submit_built(new_ledger(self.manifest), "a")
        frontier = execution_frontier(self.manifest, ledger)
        self.assertIn("c", frontier.waiting_serialization)
        ledger = self._integrate(ledger, "a")
        frontier = execution_frontier(self.manifest, ledger)
        self.assertIn("c", frontier.ready)
        self.assertIn("e", frontier.ready)

    def test_external_blocker_releases_serialization_but_blocks_semantic_dependency(self):
        ledger = self._issue_and_bind(new_ledger(self.manifest), "a")
        ledger = self._start(ledger, "a")
        ledger = self._event(
            ledger,
            "a",
            "builder",
            EventType.SUBMIT_BLOCKED.value,
            {
                "dispatch_id": self._dispatch_id("a"),
                "result_envelope_digest": ENVELOPE_DIGEST,
                "result_digest": RESULT_DIGEST,
                "blocker_kind": "hardware",
            },
        )
        ledger = self._event(
            ledger,
            "a",
            "verifier",
            EventType.VERIFY_BLOCKER.value,
            {
                "verification_digest": VERIFY_DIGEST,
                "result_digest": RESULT_DIGEST,
                "blocker_kind": "hardware",
            },
        )
        frontier = execution_frontier(self.manifest, ledger)
        self.assertIn("c", frontier.ready)
        self.assertIn("e", frontier.dependency_blocked)

    def test_unpermitted_blocker_kind_is_rejected(self):
        ledger = self._issue_and_bind(new_ledger(self.manifest), "a")
        ledger = self._start(ledger, "a")
        with self.assertRaises(StateError):
            self._event(
                ledger,
                "a",
                "builder",
                EventType.SUBMIT_BLOCKED.value,
                {
                    "dispatch_id": self._dispatch_id("a"),
                    "result_envelope_digest": ENVELOPE_DIGEST,
                    "result_digest": RESULT_DIGEST,
                    "blocker_kind": "data",
                },
            )

    def test_submission_must_match_bound_dispatch(self):
        ledger = self._issue_and_bind(new_ledger(self.manifest), "a")
        ledger = self._start(ledger, "a")
        with self.assertRaises(StateError):
            self._event(
                ledger,
                "a",
                "builder",
                EventType.SUBMIT_BUILT.value,
                {
                    "dispatch_id": "dispatch-other",
                    "result_envelope_digest": ENVELOPE_DIGEST,
                    "result_digest": RESULT_DIGEST,
                    "revision": "revision-a",
                },
            )

    def test_verifier_must_bind_to_submitted_result_digest(self):
        ledger = self._issue_and_bind(new_ledger(self.manifest), "a")
        ledger = self._start(ledger, "a")
        ledger = self._event(
            ledger,
            "a",
            "builder",
            EventType.SUBMIT_BUILT.value,
            {
                "dispatch_id": self._dispatch_id("a"),
                "result_envelope_digest": ENVELOPE_DIGEST,
                "result_digest": RESULT_DIGEST,
                "revision": "revision-a",
            },
        )
        with self.assertRaises(StateError):
            self._event(
                ledger,
                "a",
                "verifier",
                EventType.VERIFY_ACCEPT.value,
                {"verification_digest": VERIFY_DIGEST, "result_digest": OTHER_RESULT_DIGEST},
            )

    def test_verifier_blocker_kind_must_match_builder_submission(self):
        ledger = self._issue_and_bind(new_ledger(self.manifest), "a")
        ledger = self._start(ledger, "a")
        ledger = self._event(
            ledger,
            "a",
            "builder",
            EventType.SUBMIT_BLOCKED.value,
            {
                "dispatch_id": self._dispatch_id("a"),
                "result_envelope_digest": ENVELOPE_DIGEST,
                "result_digest": RESULT_DIGEST,
                "blocker_kind": "hardware",
            },
        )
        with self.assertRaises(StateError):
            self._event(
                ledger,
                "a",
                "verifier",
                EventType.VERIFY_BLOCKER.value,
                {
                    "verification_digest": VERIFY_DIGEST,
                    "result_digest": RESULT_DIGEST,
                    "blocker_kind": "data",
                },
            )

    def test_serialized_integrator_rejects_out_of_order_verified_package(self):
        ledger = new_ledger(self.manifest)
        ledger = self._submit_built(ledger, "a")
        ledger = self._submit_built(ledger, "b")
        frontier = execution_frontier(self.manifest, ledger)
        self.assertEqual(frontier.next_integratable, "a")
        with self.assertRaises(StateError):
            self._integrate(ledger, "b")

    def test_integrator_must_use_exact_submitted_revision(self):
        ledger = self._submit_built(new_ledger(self.manifest), "a")
        with self.assertRaises(StateError):
            self._event(
                ledger,
                "a",
                "integrator",
                EventType.INTEGRATE.value,
                {"revision": "different-revision"},
            )

    def test_result_digest_is_required(self):
        ledger = self._issue_and_bind(new_ledger(self.manifest), "a")
        ledger = self._start(ledger, "a")
        with self.assertRaises(StateError):
            self._event(ledger, "a", "builder", EventType.SUBMIT_BUILT.value, {})

    def test_tampered_event_chain_is_rejected(self):
        ledger = self._submit_built(new_ledger(self.manifest), "a")
        events = list(ledger.events)
        events[2] = replace(
            events[2],
            payload_json='{"dispatch_id":"dispatch-a","dispatch_receipt_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}',
        )
        tampered = replace(ledger, events=tuple(events))
        accepted, reasons = verify_ledger(self.manifest, tampered)
        self.assertFalse(accepted)
        self.assertTrue(any("digest mismatch" in reason for reason in reasons))

    def test_failed_package_stops_new_frontier_work(self):
        ledger = self._issue_and_bind(new_ledger(self.manifest), "a")
        ledger = self._start(ledger, "a")
        ledger = self._event(
            ledger,
            "a",
            "builder",
            EventType.SUBMIT_FAILED.value,
            {
                "dispatch_id": self._dispatch_id("a"),
                "result_envelope_digest": ENVELOPE_DIGEST,
                "result_digest": RESULT_DIGEST,
            },
        )
        frontier = execution_frontier(self.manifest, ledger)
        self.assertIn("a", frontier.attention_required)
        self.assertEqual(frontier.ready, ())

    def test_replay_returns_final_states(self):
        ledger = self._submit_built(new_ledger(self.manifest), "a")
        ledger = self._integrate(ledger, "a")
        states = replay_ledger(self.manifest, ledger)
        self.assertEqual(states["a"], PackageState.INTEGRATED)
        self.assertEqual(states["b"], PackageState.PENDING)


if __name__ == "__main__":
    unittest.main()
