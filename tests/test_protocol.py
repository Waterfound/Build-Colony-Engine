import copy
import tempfile
import unittest
from pathlib import Path

from build_colony.errors import ProtocolError
from build_colony.models import Domain, EvidenceGate, Profile
from build_colony.protocol import (
    ROLE_CONTRACTS,
    compile_run,
    load_manifest_document,
    manifest_to_dict,
    sha256_digest,
    verify_manifest_document,
    write_manifest,
)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        gate = EvidenceGate(id="test", description="test gate", accepted_kinds=("test",))
        self.profile = Profile(
            project="fixture",
            profile_version="1",
            goal="exercise execution protocol",
            invariants=("preserve invariant",),
            forbidden_actions=("do not bypass verifier",),
            domains=(
                Domain(id="a", objective="build a", write_scopes=("shared",), gates=(gate,)),
                Domain(id="b", objective="build b", write_scopes=("other",), gates=(gate,)),
                Domain(id="c", objective="build c", write_scopes=("shared",), gates=(gate,)),
                Domain(id="d", objective="build d", dependencies=("b",), gates=(gate,)),
            ),
        )

    def test_compile_is_deterministic_for_same_inputs(self):
        first = compile_run(self.profile, "source-123")
        second = compile_run(self.profile, "source-123")
        self.assertEqual(first, second)
        self.assertEqual(first.run_id, second.run_id)
        self.assertEqual(first.manifest_digest, second.manifest_digest)

    def test_source_revision_changes_run_identity(self):
        first = compile_run(self.profile, "source-123")
        second = compile_run(self.profile, "source-456")
        self.assertNotEqual(first.run_id, second.run_id)
        self.assertNotEqual(first.manifest_digest, second.manifest_digest)

    def test_conflicting_write_scope_becomes_serialization_edge(self):
        manifest = compile_run(self.profile, "source-123")
        packages = {package.domain_id: package for package in manifest.packages}
        self.assertEqual(packages["c"].serialize_after, ("a",))
        self.assertNotIn("b", packages["c"].serialize_after)

    def test_manifest_detects_simple_tampering(self):
        document = manifest_to_dict(compile_run(self.profile, "source-123"))
        document["packages"][0]["objective"] = "tampered"
        accepted, reasons = verify_manifest_document(document)
        self.assertFalse(accepted)
        self.assertTrue(any("digest mismatch" in reason for reason in reasons))

    def test_profile_equivalence_detects_rehashed_tampering(self):
        document = manifest_to_dict(compile_run(self.profile, "source-123"))
        package = document["packages"][0]
        package["objective"] = "tampered and rehashed"
        package_payload = dict(package)
        package_payload.pop("package_digest")
        package["package_digest"] = sha256_digest(package_payload)
        manifest_payload = copy.deepcopy(document)
        manifest_payload.pop("manifest_digest")
        document["manifest_digest"] = sha256_digest(manifest_payload)

        accepted_without_profile, reasons_without_profile = verify_manifest_document(document)
        self.assertTrue(accepted_without_profile, reasons_without_profile)

        accepted_with_profile, reasons_with_profile = verify_manifest_document(document, profile=self.profile)
        self.assertFalse(accepted_with_profile)
        self.assertIn(
            "manifest does not exactly match the supplied profile and source revision",
            reasons_with_profile,
        )

    def test_role_contracts_cannot_be_redefined_and_rehashed(self):
        document = manifest_to_dict(compile_run(self.profile, "source-123"))
        document["role_contracts"][0]["permissions"].append("integrate revisions")
        manifest_payload = copy.deepcopy(document)
        manifest_payload.pop("manifest_digest")
        document["manifest_digest"] = sha256_digest(manifest_payload)
        accepted, reasons = verify_manifest_document(document)
        self.assertFalse(accepted)
        self.assertIn("role contracts differ from the frozen protocol contracts", reasons)
        self.assertEqual(len(ROLE_CONTRACTS), 4)

    def test_manifest_round_trip(self):
        manifest = compile_run(self.profile, "source-123")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "run.json"
            write_manifest(manifest, path)
            document = load_manifest_document(path)
            accepted, reasons = verify_manifest_document(document, profile=self.profile)
            self.assertTrue(accepted, reasons)

    def test_source_revision_is_required(self):
        with self.assertRaises(ProtocolError):
            compile_run(self.profile, "")


if __name__ == "__main__":
    unittest.main()
