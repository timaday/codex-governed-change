import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from codex_governance.candidate import GitCliRepositoryAdapter


class GitCandidateAdapterTest(unittest.TestCase):
    POLICY = "sha256:" + "f" * 64
    REPOSITORY_ID = "repo:example/project"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name) / "repository"
        self.repository.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic Test")
        self.git("config", "user.email", "synthetic@example.invalid")
        (self.repository / "tracked.txt").write_bytes(b"base\n")
        self.git("add", "tracked.txt")
        self.git("commit", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").stdout.decode().strip()
        self.adapter = GitCliRepositoryAdapter(self.repository)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-C", str(self.repository), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def identify(self) -> dict:
        return self.adapter.identify(
            repository_id=self.REPOSITORY_ID,
            mode="working_tree",
            base_commit=self.base,
            effective_policy_sha256=self.POLICY,
            evidence_root="evidence",
        )

    def test_tracked_staged_deleted_and_untracked_mutations_change_identity(self) -> None:
        clean_document = self.identify()
        clean = clean_document["candidate_id"]
        self.assertEqual([], clean_document["changed_paths"])
        (self.repository / "tracked.txt").write_bytes(b"changed\n")
        unstaged_document = self.identify()
        unstaged = unstaged_document["candidate_id"]
        self.assertEqual(["tracked.txt"], unstaged_document["changed_paths"])
        self.assertNotEqual(clean, unstaged)
        self.git("add", "tracked.txt")
        self.assertEqual(unstaged, self.identify()["candidate_id"])
        (self.repository / "new.txt").write_bytes(b"new\n")
        untracked_document = self.identify()
        untracked = untracked_document["candidate_id"]
        self.assertEqual(["new.txt", "tracked.txt"], untracked_document["changed_paths"])
        self.assertNotEqual(unstaged, untracked)
        (self.repository / "tracked.txt").unlink()
        self.assertNotEqual(untracked, self.identify()["candidate_id"])

    def test_modes_symlink_targets_and_policy_change_identity(self) -> None:
        executable = self.repository / "tool"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        before_mode = self.identify()["candidate_id"]
        executable.chmod(0o755)
        self.assertNotEqual(before_mode, self.identify()["candidate_id"])
        if os.name == "posix":
            link = self.repository / "link"
            link.symlink_to("first-target")
            before_target = self.identify()["candidate_id"]
            link.unlink()
            link.symlink_to("second-target")
            self.assertNotEqual(before_target, self.identify()["candidate_id"])
        first = self.identify()["candidate_id"]
        second = self.adapter.identify(
            repository_id=self.REPOSITORY_ID,
            mode="working_tree",
            base_commit=self.base,
            effective_policy_sha256="sha256:" + "e" * 64,
            evidence_root="evidence",
        )["candidate_id"]
        self.assertNotEqual(first, second)

    def test_evidence_root_is_narrowly_excluded(self) -> None:
        before = self.identify()["candidate_id"]
        (self.repository / "evidence").mkdir()
        (self.repository / "evidence/result.json").write_bytes(b"generated")
        self.assertEqual(before, self.identify()["candidate_id"])
        (self.repository / "evidence-adjacent").write_bytes(b"candidate")
        self.assertNotEqual(before, self.identify()["candidate_id"])

    def test_commit_mode_requires_clean_checkout(self) -> None:
        result = self.adapter.identify(
            repository_id=self.REPOSITORY_ID,
            mode="commit",
            base_commit=self.base,
            head_commit=self.base,
            effective_policy_sha256=self.POLICY,
            evidence_root="evidence",
        )
        self.assertFalse(result["dirty"])
        (self.repository / "untracked.txt").write_bytes(b"candidate")
        with self.assertRaises(ValueError):
            self.adapter.identify(
                repository_id=self.REPOSITORY_ID,
                mode="commit",
                base_commit=self.base,
                head_commit=self.base,
                effective_policy_sha256=self.POLICY,
                evidence_root="evidence",
            )


if __name__ == "__main__":
    unittest.main()
