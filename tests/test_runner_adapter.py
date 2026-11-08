from dataclasses import replace
import unittest

from build_colony.errors import AdapterError, StateError
from build_colony.ledger import append_event, replay_ledger
from build_colony.models import BlockerKind, Domain, EvidenceGate, Profile
from build_colony.protocol import compile_run
from build_colony.runner_adapter import (
    accept_reference_dispatch,
    build_dispatch_bundle,
    build_reference_dispatch_bundle,
    build_result_envelope,
    builder_start_payload,
    builder_submission_payload,
    compile_dispatch_request,
    dispatch_binding_payload,
    make_capabilities,
    reference_capabilities,
    verify_dispatch_bundle,
    verify_dispatch_receipt,
    verify_result_envelope,
)
from build_colony.state_models import EventType, PackageState, new_ledger


class RunnerAdapterTests(unittest.TestCase):
    def setUp(self):
        gate = EvidenceGate(id="g", description="gate", accepted_kinds=("test",))
        self.profile = Profile(
            project="adapter-fixture",
            profile_version="1",
            goal="exercise adapters",
            invariants=("preserve invariant",),
            forbidden_actions=("do not escalate authority",),
            domains=(
                Domain(
                    id="a",
                    objective="write a",
                    write_scopes=("src/a",),
                    gates=(gate,),
                    permitted_blockers=(BlockerKind.HARDWARE,),
                ),
                Domain(id="b", objective="write b", write_scopes=("src/b",), gates=(gate,)),
            ),
        )
        self.manifest = compile_run(self.profile, "source-adapter-1")
        self.packages = {package.domain_id: package for package in self.manifest.packages}

    def _issued_ledger(self, domain="a"):
        ledger = new_ledger(self.manifest)
        package = self.packages[domain]
        return append_event(
            self.manifest,
            ledger,
            package_id=package.package_id,
            role="coordinator",
            event_type=EventType.ISSUE.value,
            payload={},
        )

    def test_dispatch_requires_issued_package(self):
        with self.assertRaises(AdapterError):
            compile_dispatch_request(
                self.manifest,
                new_ledger(self.manifest),
                domain_id="a",
                capabilities=reference_capabilities(),
            )

    def test_reference_dispatch_is_deterministic(self):
        ledger = self._issued_ledger()
        first = build_reference_dispatch_bundle(self.manifest, ledger, domain_id="a")
        second = build_reference_dispatch_bundle(self.manifest, ledger, domain_id="a")
        self.assertEqual(first, second)
        self.assertTrue(first.request.dispatch_id.startswith("bcd-"))
        self.assertTrue(first.receipt.external_run_id.startswith("ref-"))

    def test_runner_without_write_capability_is_rejected(self):
        capabilities = make_capabilities(
            adapter_id="readonly",
            provider="fixture",
            adapter_version="1",
            modes=("execute",),
            supports_write=False,
            supports_artifact_refs=True,
            max_parallelism=1,
        )
        with self.assertRaises(AdapterError):
            compile_dispatch_request(
                self.manifest,
                self._issued_ledger(),
                domain_id="a",
                capabilities=capabilities,
            )

    def test_receipt_is_bound_to_request_and_capabilities(self):
        ledger = self._issued_ledger()
        capabilities = reference_capabilities()
        request = compile_dispatch_request(
            self.manifest,
            ledger,
            domain_id="a",
            capabilities=capabilities,
        )
        receipt = accept_reference_dispatch(request)
        accepted, reasons = verify_dispatch_receipt(receipt, request, capabilities)
        self.assertTrue(accepted, reasons)

        tampered = replace(receipt, package_id=self.packages["b"].package_id)
        accepted, reasons = verify_dispatch_receipt(tampered, request, capabilities)
        self.assertFalse(accepted)
        self.assertTrue(any("package_id mismatch" in reason or "digest mismatch" in reason for reason in reasons))

    def test_fully_rehashed_bundle_cannot_move_to_another_manifest_package(self):
        bundle = build_reference_dispatch_bundle(self.manifest, self._issued_ledger(), domain_id="a")
        tampered_request = replace(
            bundle.request,
            package_id=self.packages["b"].package_id,
            package_digest=self.packages["b"].package_digest,
        )
        tampered_request = replace(
            tampered_request,
            request_digest=__import__("build_colony.protocol", fromlist=["sha256_digest"]).sha256_digest(
                {key: value for key, value in tampered_request.__dict__.items() if key != "request_digest"}
            ),
        )
        tampered_receipt = accept_reference_dispatch(tampered_request)
        tampered_bundle = build_dispatch_bundle(bundle.capabilities, tampered_request, tampered_receipt)
        accepted, reasons = verify_dispatch_bundle(tampered_bundle, self.manifest)
        self.assertFalse(accepted)
        self.assertTrue(any("domain mismatch" in reason or "objective" in reason or "package" in reason for reason in reasons))

    def test_dispatch_bundle_binds_into_state_machine(self):
        ledger = self._issued_ledger()
        bundle = build_reference_dispatch_bundle(self.manifest, ledger, domain_id="a")
        ledger = append_event(
            self.manifest,
            ledger,
            package_id=self.packages["a"].package_id,
            role="coordinator",
            event_type=EventType.BIND_DISPATCH.value,
            payload=dispatch_binding_payload(bundle),
        )
        self.assertEqual(replay_ledger(self.manifest, ledger)["a"], PackageState.DISPATCHED)

        ledger = append_event(
            self.manifest,
            ledger,
            package_id=self.packages["a"].package_id,
            role="builder",
            event_type=EventType.START.value,
            payload=builder_start_payload(bundle),
        )
        self.assertEqual(replay_ledger(self.manifest, ledger)["a"], PackageState.ACTIVE)

    def test_start_rejects_receipt_from_another_dispatch(self):
        ledger = self._issued_ledger("a")
        bundle_a = build_reference_dispatch_bundle(self.manifest, ledger, domain_id="a")
        ledger = append_event(
            self.manifest,
            ledger,
            package_id=self.packages["a"].package_id,
            role="coordinator",
            event_type=EventType.BIND_DISPATCH.value,
            payload=dispatch_binding_payload(bundle_a),
        )
        bad_payload = dict(builder_start_payload(bundle_a))
        bad_payload["dispatch_receipt_digest"] = "f" * 64
        with self.assertRaises(StateError):
            append_event(
                self.manifest,
                ledger,
                package_id=self.packages["a"].package_id,
                role="builder",
                event_type=EventType.START.value,
                payload=bad_payload,
            )

    def test_result_envelope_binds_result_to_dispatch_and_package(self):
        bundle = build_reference_dispatch_bundle(self.manifest, self._issued_ledger(), domain_id="a")
        envelope = build_result_envelope(
            bundle,
            self.manifest,
            outcome="built",
            revision="revision-a",
            evidence_locators=("artifact:test-a",),
        )
        accepted, reasons = verify_result_envelope(envelope, bundle, self.manifest)
        self.assertTrue(accepted, reasons)
        payload = builder_submission_payload(envelope)
        self.assertEqual(payload["dispatch_id"], bundle.request.dispatch_id)
        self.assertEqual(payload["revision"], "revision-a")

    def test_result_envelope_cannot_be_reused_for_another_package(self):
        bundle = build_reference_dispatch_bundle(self.manifest, self._issued_ledger(), domain_id="a")
        envelope = build_result_envelope(
            bundle,
            self.manifest,
            outcome="built",
            revision="revision-a",
            evidence_locators=("artifact:test-a",),
        )
        tampered = replace(
            envelope,
            package_id=self.packages["b"].package_id,
            package_digest=self.packages["b"].package_digest,
        )
        accepted, _ = verify_result_envelope(tampered, bundle, self.manifest)
        self.assertFalse(accepted)

    def test_blocked_envelope_must_use_permitted_blocker(self):
        bundle = build_reference_dispatch_bundle(self.manifest, self._issued_ledger(), domain_id="a")
        blocked = build_result_envelope(
            bundle,
            self.manifest,
            outcome="blocked",
            blocker_kind="hardware",
            evidence_locators=("constraint:host-unavailable",),
        )
        accepted, reasons = verify_result_envelope(blocked, bundle, self.manifest)
        self.assertTrue(accepted, reasons)
        with self.assertRaises(AdapterError):
            build_result_envelope(
                bundle,
                self.manifest,
                outcome="blocked",
                blocker_kind="data",
            )


if __name__ == "__main__":
    unittest.main()
