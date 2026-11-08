import unittest

from build_colony.errors import StateError
from build_colony.ledger import append_event, execution_frontier
from build_colony.models import Domain, EvidenceGate, Profile
from build_colony.protocol import compile_run
from build_colony.state_models import EventType, new_ledger


class DispatchFreezeTests(unittest.TestCase):
    def setUp(self):
        gate = EvidenceGate(id="g", description="gate", accepted_kinds=("test",))
        profile = Profile(
            project="dispatch-freeze",
            profile_version="1",
            goal="prove attention freezes not-yet-dispatched work",
            invariants=("attention freezes new dispatch",),
            forbidden_actions=("dispatch through attention",),
            domains=(
                Domain(id="a", objective="a", gates=(gate,)),
                Domain(id="b", objective="b", gates=(gate,)),
            ),
        )
        self.manifest = compile_run(profile, "source-freeze-1")
        self.packages = {package.domain_id: package for package in self.manifest.packages}

    def _event(self, ledger, domain, role, event_type, payload=None):
        return append_event(
            self.manifest,
            ledger,
            package_id=self.packages[domain].package_id,
            role=role,
            event_type=event_type,
            payload=payload or {},
        )

    def test_attention_removes_already_issued_package_from_dispatchable_frontier(self):
        ledger = new_ledger(self.manifest)
        ledger = self._event(ledger, "a", "coordinator", EventType.ISSUE.value)
        ledger = self._event(ledger, "b", "coordinator", EventType.ISSUE.value)

        ledger = self._event(
            ledger,
            "a",
            "coordinator",
            EventType.BIND_DISPATCH.value,
            {"dispatch_id": "dispatch-a", "dispatch_receipt_digest": "d" * 64},
        )
        ledger = self._event(
            ledger,
            "a",
            "builder",
            EventType.START.value,
            {"dispatch_id": "dispatch-a", "dispatch_receipt_digest": "d" * 64},
        )
        ledger = self._event(
            ledger,
            "a",
            "builder",
            EventType.SUBMIT_FAILED.value,
            {
                "dispatch_id": "dispatch-a",
                "result_envelope_digest": "e" * 64,
                "result_digest": "a" * 64,
            },
        )

        frontier = execution_frontier(self.manifest, ledger)
        self.assertIn("a", frontier.attention_required)
        self.assertEqual(frontier.dispatchable, ())

        with self.assertRaises(StateError):
            self._event(
                ledger,
                "b",
                "coordinator",
                EventType.BIND_DISPATCH.value,
                {"dispatch_id": "dispatch-b", "dispatch_receipt_digest": "f" * 64},
            )


if __name__ == "__main__":
    unittest.main()
