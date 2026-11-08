from dataclasses import asdict
import unittest

from build_colony.errors import AdapterError
from build_colony.github_push_transport import (
    GITHUB_PUSH_PROTOCOL_VERSION,
    GITHUB_PUSH_TRANSPORT_ID,
    GitHubPushReceipt,
    github_actions_capabilities,
    make_github_push_intent,
    verify_github_push_intent,
    verify_github_push_receipt,
)
from build_colony.protocol import sha256_digest


REVISION = "1" * 40
DIGEST = "a" * 64


class GitHubPushTransportTests(unittest.TestCase):
    def _intent(self, branch="colony-run/pilot-001"):
        return make_github_push_intent(
            repository="Waterfound/Build-Colony-Engine",
            branch=branch,
            profile_path="profiles/build-colony.remote-probe.json",
            source_revision=REVISION,
            domain_id="remote-conformance",
        )

    def _receipt(self, intent):
        unsigned = GitHubPushReceipt(
            schema_version=1,
            protocol_version=GITHUB_PUSH_PROTOCOL_VERSION,
            transport_id=GITHUB_PUSH_TRANSPORT_ID,
            intent_id=intent.intent_id,
            intent_digest=intent.intent_digest,
            repository=intent.repository,
            branch=intent.branch,
            github_run_id="12345",
            github_run_attempt="1",
            github_sha="2" * 40,
            runner_os="Linux",
            python_version="3.13.7",
            run_id="bcr-test",
            manifest_digest=DIGEST,
            package_id="bcp-test",
            package_digest="b" * 64,
            dispatch_id="bcs-test",
            dispatch_attempt=1,
            session_bundle_digest="c" * 64,
            outcome="built",
            result_digest="d" * 64,
            result_envelope_digest="e" * 64,
            probe_log_digest="f" * 64,
            ledger_head_digest="1" * 64,
            receipt_digest="",
        )
        material = asdict(unsigned)
        material.pop("receipt_digest")
        return GitHubPushReceipt(**{**asdict(unsigned), "receipt_digest": sha256_digest(material)})

    def test_intent_is_deterministic(self):
        first = self._intent()
        second = self._intent()
        self.assertEqual(first, second)
        self.assertTrue(verify_github_push_intent(first)[0])

    def test_branch_changes_transport_identity(self):
        first = self._intent("colony-run/pilot-a")
        second = self._intent("colony-run/pilot-b")
        self.assertNotEqual(first.intent_id, second.intent_id)
        self.assertNotEqual(first.intent_digest, second.intent_digest)

    def test_non_colony_branch_is_rejected(self):
        with self.assertRaises(AdapterError):
            self._intent("main")

    def test_profile_path_traversal_is_rejected(self):
        with self.assertRaises(AdapterError):
            make_github_push_intent(
                repository="Waterfound/Build-Colony-Engine",
                branch="colony-run/pilot",
                profile_path="profiles/../secrets.json",
                source_revision=REVISION,
                domain_id="remote-conformance",
            )

    def test_reference_github_capabilities_are_read_only(self):
        capabilities = github_actions_capabilities()
        self.assertFalse(capabilities.supports_write)
        self.assertIn("remote-probe", capabilities.modes)

    def test_receipt_can_be_bound_to_observed_github_run(self):
        intent = self._intent()
        receipt = self._receipt(intent)
        accepted, reasons = verify_github_push_receipt(
            intent,
            receipt,
            expected_run_id="12345",
            expected_sha="2" * 40,
        )
        self.assertTrue(accepted, reasons)
        accepted, reasons = verify_github_push_receipt(
            intent,
            receipt,
            expected_run_id="99999",
            expected_sha="2" * 40,
        )
        self.assertFalse(accepted)
        self.assertTrue(any("run id mismatch" in reason for reason in reasons))


if __name__ == "__main__":
    unittest.main()
