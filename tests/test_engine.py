import unittest

from build_colony.engine import ColonyEngine
from build_colony.models import (
    Blocker,
    BlockerKind,
    ColonyVerdict,
    Domain,
    Evidence,
    EvidenceGate,
    Profile,
    WorkerResult,
)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.profile = Profile(
            project="test",
            profile_version="1",
            goal="test",
            invariants=(),
            forbidden_actions=(),
            domains=(
                Domain(
                    id="a",
                    objective="a",
                    gates=(EvidenceGate(id="ga", description="ga", accepted_kinds=("test",)),),
                ),
                Domain(
                    id="b",
                    objective="b",
                    dependencies=("a",),
                    gates=(EvidenceGate(id="gb", description="gb", accepted_kinds=("test",)),),
                    permitted_blockers=(BlockerKind.HARDWARE,),
                ),
            ),
        )

    def test_integration_plan_contains_only_verified_work(self):
        engine = ColonyEngine(self.profile)
        results = {
            "a": WorkerResult(
                domain_id="a",
                outcome="built",
                revision="r1",
                evidence=(Evidence(gate="ga", kind="test", locator="suite-a"),),
            ),
            "b": WorkerResult(domain_id="b", outcome="failed"),
        }
        self.assertEqual([item.domain_id for item in engine.integration_plan(results)], ["a"])

    def test_stop_condition_is_not_project_completion(self):
        engine = ColonyEngine(self.profile)
        results = {
            "a": WorkerResult(
                domain_id="a",
                outcome="built",
                evidence=(Evidence(gate="ga", kind="test", locator="suite-a"),),
            ),
            "b": WorkerResult(
                domain_id="b",
                outcome="blocked",
                blocker=Blocker(
                    kind=BlockerKind.HARDWARE,
                    detail="requires independent host",
                    evidence=(Evidence(gate="", kind="constraint", locator="coordinator:independent-host-unavailable"),),
                ),
            ),
        }
        assessment = engine.assess(results)
        self.assertEqual(assessment.verdict, ColonyVerdict.REACHABLE_CEILINGS_REACHED)
        self.assertFalse(assessment.project_complete)
        self.assertEqual(assessment.externally_blocked, ("b",))
        self.assertEqual(assessment.dependency_blocked, ())

    def test_downstream_result_cannot_bypass_blocked_dependency(self):
        profile = Profile(
            project="test",
            profile_version="1",
            goal="test",
            invariants=(),
            forbidden_actions=(),
            domains=(
                Domain(
                    id="a",
                    objective="a",
                    gates=(EvidenceGate(id="ga", description="ga", accepted_kinds=("test",)),),
                    permitted_blockers=(BlockerKind.HARDWARE,),
                ),
                Domain(
                    id="b",
                    objective="b",
                    dependencies=("a",),
                    gates=(EvidenceGate(id="gb", description="gb", accepted_kinds=("test",)),),
                ),
            ),
        )
        engine = ColonyEngine(profile)
        results = {
            "a": WorkerResult(
                domain_id="a",
                outcome="blocked",
                blocker=Blocker(
                    kind=BlockerKind.HARDWARE,
                    detail="hardware gate",
                    evidence=(Evidence(gate="", kind="constraint", locator="coordinator:hardware-unavailable"),),
                ),
            ),
            "b": WorkerResult(
                domain_id="b",
                outcome="built",
                revision="must-not-integrate",
                evidence=(Evidence(gate="gb", kind="test", locator="suite-b"),),
            ),
        }
        verdicts = engine.verify(results)
        self.assertEqual(verdicts["b"].status, "dependency_blocked")
        self.assertEqual(engine.integration_plan(results, verdicts), ())
        assessment = engine.assess(results, verdicts)
        self.assertEqual(assessment.verdict, ColonyVerdict.REACHABLE_CEILINGS_REACHED)
        self.assertEqual(assessment.dependency_blocked, ("b",))

    def test_unknown_result_domain_is_rejected(self):
        from build_colony.errors import VerificationError

        with self.assertRaises(VerificationError):
            ColonyEngine(self.profile).verify({"unknown": WorkerResult(domain_id="unknown", outcome="failed")})

    def test_missing_result_means_continue(self):
        assessment = ColonyEngine(self.profile).assess({})
        self.assertEqual(assessment.verdict, ColonyVerdict.CONTINUE)


if __name__ == "__main__":
    unittest.main()
