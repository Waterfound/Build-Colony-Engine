from dataclasses import asdict, replace
import base64
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from build_colony.attestation import (
    append_attested_event,
    attestation_statement_bytes,
    make_attestation,
    make_trust_policy,
    make_trusted_signer,
    verify_attested_ledger,
)
from build_colony.errors import PoolError
from build_colony.ledger import append_event, replay_ledger
from build_colony.models import Domain, EvidenceGate, Profile
from build_colony.pool_attempt import (
    bind_dispatch_attempt,
    bind_dispatch_attempt_attested,
    build_binding_intents,
    build_dispatch_attempt,
    build_reference_dispatch_attempt,
)
from build_colony.pool_rehearsal import complete_reference_attempt
from build_colony.protocol import compile_run, sha256_digest
from build_colony.runner_pool import (
    ReferencePoolSessionRunner,
    plan_dispatches,
    reference_pool_registry,
    verify_dispatch_plan,
)
from build_colony.runner_session_strict import revoke_session_dispatch
from build_colony.state_models import EventType, PackageState, new_ledger


class RejectingRunner:
    def __init__(self, capabilities):
        self._capabilities = capabilities

    def capabilities(self):
        return self._capabilities

    def dispatch(self, request):
        raise RuntimeError("provider unavailable")


class RunnerPoolTests(unittest.TestCase):
    def _profile(self, domains=("a", "b", "c", "d")):
        gate = EvidenceGate(id="g", description="gate", accepted_kinds=("test",))
        return Profile(
            project="pool-fixture",
            profile_version="1",
            goal="exercise deterministic session-aware pool execution",
            invariants=("parallelism must not expand authority",),
            forbidden_actions=("bypass verification",),
            domains=tuple(
                Domain(
                    id=domain_id,
                    objective=domain_id,
                    write_scopes=(f"src/{domain_id}",),
                    gates=(gate,),
                )
                for domain_id in domains
            ),
        )

    def _issued(self, manifest):
        ledger = new_ledger(manifest)
        packages = {package.domain_id: package for package in manifest.packages}
        for domain_id in sorted(packages):
            ledger = append_event(
                manifest,
                ledger,
                package_id=packages[domain_id].package_id,
                role="coordinator",
                event_type=EventType.ISSUE.value,
                payload={},
            )
        return ledger

    def test_two_slot_pool_reuses_capacity_across_two_waves(self):
        manifest = compile_run(self._profile(), "pool-source-1")
        ledger = self._issued(manifest)
        registry = reference_pool_registry(slots=2, max_parallelism=1)

        first = plan_dispatches(manifest, ledger, registry)
        self.assertEqual([item.domain_id for item in first.assignments], ["a", "b"])
        self.assertEqual(
            [(item.domain_id, item.reason) for item in first.deferred],
            [("c", "capacity_exhausted"), ("d", "capacity_exhausted")],
        )
        self.assertEqual(first, plan_dispatches(manifest, ledger, registry))
        self.assertTrue(all(item.dispatch_attempt == 1 for item in first.assignments))

        attempt1 = build_reference_dispatch_attempt(first, manifest, ledger, registry)
        wave1 = complete_reference_attempt(attempt1, first, manifest, ledger, registry)
        states = replay_ledger(manifest, wave1.ledger)
        self.assertEqual(states["a"], PackageState.SUBMITTED_BUILT)
        self.assertEqual(states["b"], PackageState.SUBMITTED_BUILT)

        second = plan_dispatches(manifest, wave1.ledger, registry)
        self.assertEqual([item.domain_id for item in second.assignments], ["c", "d"])
        self.assertEqual(second.deferred, ())
        attempt2 = build_reference_dispatch_attempt(second, manifest, wave1.ledger, registry)
        wave2 = complete_reference_attempt(
            attempt2, second, manifest, wave1.ledger, registry
        )
        final_states = replay_ledger(manifest, wave2.ledger)
        self.assertTrue(
            all(final_states[domain] == PackageState.SUBMITTED_BUILT for domain in ("a", "b", "c", "d"))
        )

    def test_partial_provider_failure_is_fail_closed_and_same_plan_recovers(self):
        manifest = compile_run(self._profile(("a", "b")), "pool-source-2")
        ledger = self._issued(manifest)
        registry = reference_pool_registry(slots=2, max_parallelism=1)
        plan = plan_dispatches(manifest, ledger, registry)
        adapters = {
            caps.adapter_id: ReferencePoolSessionRunner(caps) for caps in registry.runners
        }
        rejected = plan.assignments[1].adapter_id
        rejected_caps = next(item for item in registry.runners if item.adapter_id == rejected)
        adapters[rejected] = RejectingRunner(rejected_caps)

        before_head = ledger.head_event_digest
        before_events = ledger.events
        failed = build_dispatch_attempt(plan, manifest, ledger, registry, adapters)
        self.assertFalse(failed.complete)
        self.assertEqual(len(failed.failures), 1)
        self.assertIn("runner_exception:RuntimeError", failed.failures[0].reason)
        self.assertEqual(ledger.head_event_digest, before_head)
        self.assertEqual(ledger.events, before_events)
        with self.assertRaises(PoolError):
            bind_dispatch_attempt(failed, plan, manifest, ledger, registry)
        self.assertEqual(ledger.head_event_digest, before_head)
        self.assertEqual(ledger.events, before_events)

        adapters[rejected] = ReferencePoolSessionRunner(rejected_caps)
        recovered = build_dispatch_attempt(plan, manifest, ledger, registry, adapters)
        self.assertTrue(recovered.complete)
        self.assertEqual(recovered.plan_id, failed.plan_id)
        bound = bind_dispatch_attempt(recovered, plan, manifest, ledger, registry)
        states = replay_ledger(manifest, bound)
        self.assertTrue(all(state == PackageState.DISPATCHED for state in states.values()))

    def test_retry_changes_session_attempt_and_pool_lease(self):
        manifest = compile_run(self._profile(("a",)), "pool-source-retry")
        ledger = self._issued(manifest)
        registry = reference_pool_registry(slots=1, max_parallelism=1)

        first_plan = plan_dispatches(manifest, ledger, registry)
        first_attempt = build_reference_dispatch_attempt(first_plan, manifest, ledger, registry)
        bound = bind_dispatch_attempt(first_attempt, first_plan, manifest, ledger, registry)
        bundle = first_attempt.entries[0].bundle
        revoked = revoke_session_dispatch(
            manifest, bound, bundle, reason="replace runner after bounded failure"
        )

        second_plan = plan_dispatches(manifest, revoked, registry)
        self.assertEqual(second_plan.assignments[0].dispatch_attempt, 2)
        self.assertNotEqual(
            first_plan.assignments[0].lease_id,
            second_plan.assignments[0].lease_id,
        )
        second_attempt = build_reference_dispatch_attempt(
            second_plan, manifest, revoked, registry
        )
        self.assertNotEqual(
            first_attempt.entries[0].bundle.request.dispatch_id,
            second_attempt.entries[0].bundle.request.dispatch_id,
        )

    def test_fully_rehashed_assignment_substitution_fails_deterministic_replan(self):
        manifest = compile_run(self._profile(("a", "b")), "pool-source-tamper")
        ledger = self._issued(manifest)
        registry = reference_pool_registry(slots=2, max_parallelism=1)
        plan = plan_dispatches(manifest, ledger, registry)

        original = plan.assignments[0]
        unsigned = replace(original, domain_id="b", assignment_digest="")
        assignment_digest = sha256_digest(
            {key: value for key, value in asdict(unsigned).items() if key != "assignment_digest"}
        )
        forged_assignment = replace(unsigned, assignment_digest=assignment_digest)
        forged_unsigned = replace(
            plan,
            assignments=(forged_assignment,) + plan.assignments[1:],
            plan_digest="",
        )
        forged_digest = sha256_digest(
            {key: value for key, value in asdict(forged_unsigned).items() if key != "plan_digest"}
        )
        forged = replace(forged_unsigned, plan_digest=forged_digest)
        accepted, reasons = verify_dispatch_plan(forged, manifest, ledger, registry)
        self.assertFalse(accepted)
        self.assertTrue(any("deterministic replan" in reason for reason in reasons))

    def test_attested_pool_binding_preserves_strong_ledger_assurance(self):
        manifest = compile_run(self._profile(("a", "b")), "pool-source-attested")
        packages = {package.domain_id: package for package in manifest.packages}

        private = Ed25519PrivateKey.generate()
        public_bytes = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        signer = make_trusted_signer(
            signer_id="pool-coordinator",
            role="coordinator",
            public_key_b64=base64.b64encode(public_bytes).decode("ascii"),
            allowed_events=(EventType.ISSUE.value, EventType.BIND_DISPATCH.value),
        )
        policy = make_trust_policy(manifest, (signer,))

        ledger = new_ledger(manifest)
        for domain_id in ("a", "b"):
            package_id = packages[domain_id].package_id
            payload = {}
            statement = attestation_statement_bytes(
                manifest,
                policy,
                signer_id="pool-coordinator",
                package_id=package_id,
                role="coordinator",
                action=EventType.ISSUE.value,
                payload=payload,
            )
            attestation = make_attestation(
                manifest,
                policy,
                signer_id="pool-coordinator",
                package_id=package_id,
                role="coordinator",
                action=EventType.ISSUE.value,
                payload=payload,
                signature_b64=base64.b64encode(private.sign(statement)).decode("ascii"),
            )
            ledger = append_attested_event(
                manifest, ledger, policy, attestation, payload=payload
            )

        registry = reference_pool_registry(slots=2, max_parallelism=1)
        plan = plan_dispatches(manifest, ledger, registry)
        attempt = build_reference_dispatch_attempt(plan, manifest, ledger, registry)
        intents = build_binding_intents(attempt, plan, manifest, ledger, registry)
        attestations = {}
        for intent in intents:
            statement = attestation_statement_bytes(
                manifest,
                policy,
                signer_id="pool-coordinator",
                package_id=intent.package_id,
                role=intent.role,
                action=intent.action,
                payload=intent.payload,
            )
            attestations[intent.domain_id] = make_attestation(
                manifest,
                policy,
                signer_id="pool-coordinator",
                package_id=intent.package_id,
                role=intent.role,
                action=intent.action,
                payload=intent.payload,
                signature_b64=base64.b64encode(private.sign(statement)).decode("ascii"),
            )

        bound = bind_dispatch_attempt_attested(
            attempt, plan, manifest, ledger, registry, policy, attestations
        )
        accepted, reasons = verify_attested_ledger(manifest, bound, policy)
        self.assertTrue(accepted, reasons)
        self.assertTrue(
            all(state == PackageState.DISPATCHED for state in replay_ledger(manifest, bound).values())
        )

        swapped = dict(attestations)
        swapped["a"] = attestations["b"]
        with self.assertRaises(PoolError):
            bind_dispatch_attempt_attested(
                attempt, plan, manifest, ledger, registry, policy, swapped
            )


if __name__ == "__main__":
    unittest.main()
