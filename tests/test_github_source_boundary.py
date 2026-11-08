from dataclasses import replace
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from build_colony.errors import RemotePoolError
from build_colony.github_push_transport import make_github_push_intent
from build_colony.github_source_boundary import (
    REMOTE_INTENT_PATH,
    inspect_github_source_boundary,
    verify_source_boundary_evidence,
)


class GitHubSourceBoundaryTests(unittest.TestCase):
    def _git(self, root: Path, *args: str) -> str:
        completed = subprocess.run(
            ["git", *args],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return completed.stdout.strip()

    def _init_repo(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        self._git(root, "init")
        self._git(root, "config", "user.email", "ci@example.invalid")
        self._git(root, "config", "user.name", "Build Colony CI")
        (root / "README.md").write_text("base\n", encoding="utf-8")
        self._git(root, "add", "README.md")
        self._git(root, "commit", "-m", "base")
        source = self._git(root, "rev-parse", "HEAD")
        return temp, root, source

    def _commit_intent(self, root: Path, source: str, *, extra_change: bool = False):
        intent = make_github_push_intent(
            repository="Waterfound/Build-Colony-Engine",
            branch="colony-run/source-boundary-test",
            profile_path="profiles/build-colony.remote-probe.json",
            source_revision=source,
            domain_id="remote-conformance",
        )
        intent_path = root / REMOTE_INTENT_PATH
        intent_path.parent.mkdir(parents=True, exist_ok=True)
        intent_path.write_text(
            json.dumps(intent.__dict__, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self._git(root, "add", REMOTE_INTENT_PATH)
        if extra_change:
            (root / "README.md").write_text("tampered launch\n", encoding="utf-8")
            self._git(root, "add", "README.md")
        self._git(root, "commit", "-m", "launch")
        trigger = self._git(root, "rev-parse", "HEAD")
        return intent, trigger

    def test_exact_one_commit_metadata_only_launch_is_accepted(self):
        temp, root, source = self._init_repo()
        self.addCleanup(temp.cleanup)
        intent, trigger = self._commit_intent(root, source)
        evidence = inspect_github_source_boundary(
            intent,
            repo_root=root,
            trigger_sha=trigger,
        )
        self.assertEqual(evidence.commit_distance, 1)
        self.assertEqual(evidence.changed_paths, (REMOTE_INTENT_PATH,))
        accepted, reasons = verify_source_boundary_evidence(
            evidence,
            intent,
            expected_trigger_sha=trigger,
        )
        self.assertTrue(accepted, reasons)

    def test_launch_commit_with_code_change_is_rejected(self):
        temp, root, source = self._init_repo()
        self.addCleanup(temp.cleanup)
        intent, trigger = self._commit_intent(root, source, extra_change=True)
        with self.assertRaisesRegex(RemotePoolError, "launch delta"):
            inspect_github_source_boundary(intent, repo_root=root, trigger_sha=trigger)

    def test_two_commits_above_source_are_rejected(self):
        temp, root, source = self._init_repo()
        self.addCleanup(temp.cleanup)
        intent, _ = self._commit_intent(root, source)
        (root / "marker.txt").write_text("second\n", encoding="utf-8")
        self._git(root, "add", "marker.txt")
        self._git(root, "commit", "-m", "second launch commit")
        trigger = self._git(root, "rev-parse", "HEAD")
        with self.assertRaisesRegex(RemotePoolError, "exactly one commit"):
            inspect_github_source_boundary(intent, repo_root=root, trigger_sha=trigger)

    def test_trigger_sha_must_equal_checked_out_head(self):
        temp, root, source = self._init_repo()
        self.addCleanup(temp.cleanup)
        intent, _ = self._commit_intent(root, source)
        with self.assertRaisesRegex(RemotePoolError, "HEAD does not match"):
            inspect_github_source_boundary(
                intent,
                repo_root=root,
                trigger_sha="f" * 40,
            )

    def test_rehashed_tampered_boundary_evidence_is_rejected(self):
        temp, root, source = self._init_repo()
        self.addCleanup(temp.cleanup)
        intent, trigger = self._commit_intent(root, source)
        evidence = inspect_github_source_boundary(intent, repo_root=root, trigger_sha=trigger)
        tampered = replace(evidence, changed_paths=(REMOTE_INTENT_PATH, "src/evil.py"))
        accepted, reasons = verify_source_boundary_evidence(
            tampered,
            intent,
            expected_trigger_sha=trigger,
        )
        self.assertFalse(accepted)
        self.assertTrue(any("changed paths" in reason for reason in reasons))
        self.assertTrue(any("digest mismatch" in reason for reason in reasons))


if __name__ == "__main__":
    unittest.main()
