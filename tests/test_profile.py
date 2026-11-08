import unittest

from build_colony.errors import ProfileError
from build_colony.profile import profile_from_dict


class ProfileTests(unittest.TestCase):
    def test_rejects_cycles(self):
        with self.assertRaises(ProfileError):
            profile_from_dict({
                "project": "x",
                "profile_version": "1",
                "goal": "x",
                "domains": [
                    {"id": "a", "objective": "a", "dependencies": ["b"]},
                    {"id": "b", "objective": "b", "dependencies": ["a"]}
                ]
            })

    def test_rejects_domain_without_evidence_gate(self):
        with self.assertRaises(ProfileError):
            profile_from_dict({
                "project": "x",
                "profile_version": "1",
                "goal": "x",
                "domains": [{"id": "a", "objective": "a"}]
            })

    def test_rejects_claim_as_gate_evidence(self):
        with self.assertRaises(ProfileError):
            profile_from_dict({
                "project": "x",
                "profile_version": "1",
                "goal": "x",
                "domains": [{
                    "id": "a",
                    "objective": "a",
                    "gates": [{
                        "id": "g",
                        "description": "g",
                        "accepted_kinds": ["claim"]
                    }]
                }]
            })


if __name__ == "__main__":
    unittest.main()
