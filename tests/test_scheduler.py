import unittest

from build_colony.models import Domain, Profile
from build_colony.scheduler import build_schedule


class SchedulerTests(unittest.TestCase):
    def test_parallelizes_independent_and_serializes_conflicts(self):
        profile = Profile(
            project="test",
            profile_version="1",
            goal="test",
            invariants=(),
            forbidden_actions=(),
            domains=(
                Domain(id="a", objective="a", write_scopes=("x",)),
                Domain(id="b", objective="b", write_scopes=("y",)),
                Domain(id="c", objective="c", dependencies=("a",), write_scopes=("z",)),
                Domain(id="d", objective="d", write_scopes=("x",)),
            ),
        )
        schedule = build_schedule(profile)
        self.assertEqual(schedule.waves[0], ("a", "b"))
        self.assertEqual(schedule.waves[1], ("c", "d"))

    def test_dependency_wave_order_is_deterministic(self):
        profile = Profile(
            project="test",
            profile_version="1",
            goal="test",
            invariants=(),
            forbidden_actions=(),
            domains=(
                Domain(id="b", objective="b"),
                Domain(id="a", objective="a"),
                Domain(id="c", objective="c", dependencies=("a", "b")),
            ),
        )
        self.assertEqual(build_schedule(profile).waves, (("a", "b"), ("c",)))


if __name__ == "__main__":
    unittest.main()
