import base64
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from build_colony.attestation import (
    AttestationError,
    ActorAttestation,
    append_attested_event,
    attestation_statement_bytes,
    make_attestation,
    make_trust_policy,
    make_trusted_signer,
    verify_attestation,
    verify_attested_ledger,
    verify_trust_policy,
)
from build_colony.ledger import append_event
from build_colony.models import Domain, EvidenceGate, Profile
from build_colony.protocol import compile_run
from build_colony.state_models import EventType, new_ledger


class AttestationTests(unittest.TestCase):
    def setUp(self):
        gate = EvidenceGate(id="g", description="gate", accepted_kinds=("test",))
        profile = Profile(
            project="attestation-fixture",
            profile_version="1",
            goal="authenticate role-separated ledger events",
            invariants=("separate roles",),
            forbidden_actions=("do not impersonate actors",),
            domains=(Domain(id="a", objective="a", gates=(gate,)),),
        )
        self.manifest = compile_run(profile, "attestation-source")
        self.package = self.manifest.packages[0]
        self.private_keys = {}
        signers = []
        allowed = {
            "coordinator": (EventType.ISSUE.value, EventType.BIND_DISPATCH.value),
            "builder": (EventType.START.value, EventType.SUBMIT_BUILT.value),
            "verifier": (EventType.VERIFY_ACCEPT.value,),
            "integrator": (EventType.INTEGRATE.value,),
        }
        for role, events in allowed.items():
            private = Ed25519PrivateKey.generate()
            public_bytes = private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            signer_id = f"{role}-fixture"
            self.private_keys[signer_id] = private
            signers.append(
                make_trusted_signer(
                    signer_id=signer_id,
                    role=role,
                    public_key_b64=base64.b64encode(public_bytes).decode("ascii"),
                    allowed_events=events,
                )
            )
        self.policy = make_trust_policy(self.manifest, tuple(signers))

    def _attest(self, *, signer_id, role, action, payload):
        statement = attestation_statement_bytes(
            self.manifest,
            self.policy,
            signer_id=signer_id,
            package_id=self.package.package_id,
            role=role,
            action=action,
            payload=payload,
        )
        signature = self.private_keys[signer_id].sign(statement)
        return make_attestation(
            self.manifest,
            self.policy,
            signer_id=signer_id,
            package_id=self.package.package_id,
            role=role,
            action=action,
            payload=payload,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )

    def _append(self, ledger, *, signer_id, role, action, payload):
        attestation = self._attest(
            signer_id=signer_id,
            role=role,
            action=action,
            payload=payload,
        )
        return append_attested_event(
            self.manifest,
            ledger,
            self.policy,
            attestation,
            payload=payload,
        )

    def test_full_role_separated_attested_ledger(self):
        ledger = new_ledger(self.manifest)
        ledger = self._append(
            ledger,
            signer_id="coordinator-fixture",
            role="coordinator",
            action=EventType.ISSUE.value,
            payload={},
        )
        bind_payload = {
            "dispatch_id": "dispatch-1",
            "dispatch_receipt_digest": "a" * 64,
        }
        ledger = self._append(
            ledger,
            signer_id="coordinator-fixture",
            role="coordinator",
            action=EventType.BIND_DISPATCH.value,
            payload=bind_payload,
        )
        ledger = self._append(
            ledger,
            signer_id="builder-fixture",
            role="builder",
            action=EventType.START.value,
            payload=bind_payload,
        )
        result_payload = {
            "dispatch_id": "dispatch-1",
            "result_envelope_digest": "b" * 64,
            "result_digest": "c" * 64,
            "revision": "revision-a",
        }
        ledger = self._append(
            ledger,
            signer_id="builder-fixture",
            role="builder",
            action=EventType.SUBMIT_BUILT.value,
            payload=result_payload,
        )
        verify_payload = {
            "verification_digest": "d" * 64,
            "result_digest": "c" * 64,
        }
        ledger = self._append(
            ledger,
            signer_id="verifier-fixture",
            role="verifier",
            action=EventType.VERIFY_ACCEPT.value,
            payload=verify_payload,
        )
        ledger = self._append(
            ledger,
            signer_id="integrator-fixture",
            role="integrator",
            action=EventType.INTEGRATE.value,
            payload={"revision": "revision-a"},
        )

        accepted, reasons = verify_attested_ledger(self.manifest, ledger, self.policy)
        self.assertTrue(accepted, reasons)

    def test_legacy_unsigned_ledger_is_not_attested(self):
        ledger = append_event(
            self.manifest,
            new_ledger(self.manifest),
            package_id=self.package.package_id,
            role="coordinator",
            event_type=EventType.ISSUE.value,
            payload={},
        )
        accepted, reasons = verify_attested_ledger(self.manifest, ledger, self.policy)
        self.assertFalse(accepted)
        self.assertTrue(any("no actor_attestation" in reason for reason in reasons))

    def test_wrong_private_key_signature_is_rejected(self):
        payload = {}
        statement = attestation_statement_bytes(
            self.manifest,
            self.policy,
            signer_id="coordinator-fixture",
            package_id=self.package.package_id,
            role="coordinator",
            action=EventType.ISSUE.value,
            payload=payload,
        )
        attacker = Ed25519PrivateKey.generate()
        forged = make_attestation(
            self.manifest,
            self.policy,
            signer_id="coordinator-fixture",
            package_id=self.package.package_id,
            role="coordinator",
            action=EventType.ISSUE.value,
            payload=payload,
            signature_b64=base64.b64encode(attacker.sign(statement)).decode("ascii"),
        )
        accepted, reasons = verify_attestation(
            forged, self.manifest, self.policy, payload=payload
        )
        self.assertFalse(accepted)
        self.assertTrue(any("signature verification failed" in reason for reason in reasons))

    def test_signer_cannot_cross_role_boundary(self):
        with self.assertRaises(AttestationError):
            attestation_statement_bytes(
                self.manifest,
                self.policy,
                signer_id="coordinator-fixture",
                package_id=self.package.package_id,
                role="builder",
                action=EventType.START.value,
                payload={
                    "dispatch_id": "x",
                    "dispatch_receipt_digest": "a" * 64,
                },
            )

    def test_signer_cannot_emit_undeclared_event_in_own_role(self):
        with self.assertRaises(AttestationError):
            attestation_statement_bytes(
                self.manifest,
                self.policy,
                signer_id="coordinator-fixture",
                package_id=self.package.package_id,
                role="coordinator",
                action=EventType.REVOKE_DISPATCH.value,
                payload={},
            )

    def test_payload_change_breaks_attestation(self):
        attestation = self._attest(
            signer_id="integrator-fixture",
            role="integrator",
            action=EventType.INTEGRATE.value,
            payload={"revision": "revision-a"},
        )
        accepted, reasons = verify_attestation(
            attestation,
            self.manifest,
            self.policy,
            payload={"revision": "revision-b"},
        )
        self.assertFalse(accepted)
        self.assertTrue(any("payload digest mismatch" in reason for reason in reasons))

    def test_policy_is_bound_to_exact_manifest(self):
        other = compile_run(
            Profile(
                project="other",
                profile_version="1",
                goal="other",
                invariants=(),
                forbidden_actions=(),
                domains=(
                    Domain(
                        id="a",
                        objective="a",
                        gates=(EvidenceGate(id="g", description="g", accepted_kinds=("test",)),),
                    ),
                ),
            ),
            "other-source",
        )
        accepted, reasons = verify_trust_policy(self.policy, other)
        self.assertFalse(accepted)
        self.assertTrue(any("not bound" in reason for reason in reasons))

    def test_attestation_document_contains_no_private_key_material(self):
        attestation = self._attest(
            signer_id="coordinator-fixture",
            role="coordinator",
            action=EventType.ISSUE.value,
            payload={},
        )
        document = json.dumps(attestation.__dict__, sort_keys=True)
        self.assertNotIn("private", document.lower())
        self.assertNotIn("seed", document.lower())


if __name__ == "__main__":
    unittest.main()
