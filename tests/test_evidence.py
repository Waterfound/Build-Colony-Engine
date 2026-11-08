import hashlib
import tempfile
import unittest
from pathlib import Path

from build_colony.evidence import EvidenceVerifier
from build_colony.models import Blocker, BlockerKind, Domain, Evidence, EvidenceGate, WorkerResult


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.domain = Domain(
            id="a",
            objective="a",
            gates=(EvidenceGate(id="g", description="g", accepted_kinds=("test", "hash")),),
            permitted_blockers=(BlockerKind.HARDWARE,),
        )

    def test_rejects_worker_claim(self):
        result = WorkerResult(
            domain_id="a",
            outcome="built",
            evidence=(Evidence(gate="g", kind="claim", locator="trust-me"),),
        )
        verdict = EvidenceVerifier().verify(self.domain, result)
        self.assertFalse(verdict.accepted)

    def test_verifies_sha256_against_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "out.txt"
            artifact.write_text("hello", encoding="utf-8")
            digest = hashlib.sha256(b"hello").hexdigest()
            result = WorkerResult(
                domain_id="a",
                outcome="built",
                evidence=(Evidence(gate="g", kind="hash", locator="out.txt", sha256=digest),),
            )
            verdict = EvidenceVerifier(root).verify(self.domain, result)
            self.assertTrue(verdict.accepted)

    def test_rejects_unsubstantiated_permitted_blocker(self):
        result = WorkerResult(
            domain_id="a",
            outcome="blocked",
            blocker=Blocker(kind=BlockerKind.HARDWARE, detail="need independent host"),
        )
        verdict = EvidenceVerifier().verify(self.domain, result)
        self.assertFalse(verdict.accepted)
        self.assertIn("requires independent evidence", verdict.reasons[0])

    def test_rejects_unpermitted_blocker(self):
        result = WorkerResult(
            domain_id="a",
            outcome="blocked",
            blocker=Blocker(kind=BlockerKind.DATA, detail="need data"),
        )
        verdict = EvidenceVerifier().verify(self.domain, result)
        self.assertFalse(verdict.accepted)


if __name__ == "__main__":
    unittest.main()
