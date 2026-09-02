import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from codex_governance.artifacts import ArtifactSafetyError
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

    def test_untracked_leaf_replacement_fails_closed(self) -> None:
        parent = self.repository / "nested"
        parent.mkdir()
        target = parent / "value.txt"
        target.write_bytes(b"first")
        replacement = parent / "replacement"
        replacement.write_bytes(b"second")
        real_stat = os.stat
        leaf_observations = 0

        def replace_before_restat(path, *args, **kwargs):
            nonlocal leaf_observations
            if (
                path == "value.txt"
                and kwargs.get("dir_fd") is not None
                and kwargs.get("follow_symlinks") is False
            ):
                leaf_observations += 1
                if leaf_observations == 2:
                    replacement.replace(target)
            return real_stat(path, *args, **kwargs)

        with (
            patch(
                "codex_governance.artifacts.secure_repository_reads_available",
                return_value=True,
            ),
            patch(
                "codex_governance.artifacts.os.stat",
                side_effect=replace_before_restat,
            ),
        ):
            with self.assertRaisesRegex(ArtifactSafetyError, "leaf binding changed"):
                self.identify()
        self.assertEqual(2, leaf_observations)

    @unittest.skipUnless(os.name == "posix", "POSIX symbolic-link identity")
    def test_untracked_symlink_replacement_fails_closed(self) -> None:
        target = self.repository / "link"
        target.symlink_to("first-target")
        replacement = self.repository / "replacement-link"
        replacement.symlink_to("second-target")
        real_stat = os.stat
        leaf_observations = 0

        def replace_before_restat(path, *args, **kwargs):
            nonlocal leaf_observations
            if (
                path == "link"
                and kwargs.get("dir_fd") is not None
                and kwargs.get("follow_symlinks") is False
            ):
                leaf_observations += 1
                if leaf_observations == 2:
                    replacement.replace(target)
            return real_stat(path, *args, **kwargs)

        with (
            patch(
                "codex_governance.artifacts.secure_repository_reads_available",
                return_value=True,
            ),
            patch(
                "codex_governance.artifacts.os.stat",
                side_effect=replace_before_restat,
            ),
        ):
            with self.assertRaisesRegex(ArtifactSafetyError, "leaf binding changed"):
                self.identify()
        self.assertEqual(2, leaf_observations)

    def test_evidence_root_is_narrowly_excluded(self) -> None:
        before = self.identify()["candidate_id"]
        (self.repository / "evidence").mkdir()
        (self.repository / "evidence/result.json").write_bytes(b"generated")
        self.assertEqual(before, self.identify()["candidate_id"])
        (self.repository / "evidence-adjacent").write_bytes(b"candidate")
        self.assertNotEqual(before, self.identify()["candidate_id"])

    def test_untracked_content_read_receives_adapter_deadline(self) -> None:
        (self.repository / "untracked.txt").write_bytes(b"candidate")
        deadline = time.monotonic() + 10
        adapter = GitCliRepositoryAdapter(self.repository, deadline=deadline)
        from codex_governance import candidate as candidate_module

        real_read = candidate_module.read_bounded_repository_entry
        observed = []

        def bounded_read(repository, path, **kwargs):
            observed.append(kwargs.get("deadline"))
            return real_read(repository, path, **kwargs)

        with patch.object(
            candidate_module,
            "read_bounded_repository_entry",
            side_effect=bounded_read,
        ):
            adapter.identify(
                repository_id=self.REPOSITORY_ID,
                mode="working_tree",
                base_commit=self.base,
                effective_policy_sha256=self.POLICY,
                evidence_root="evidence",
            )
        self.assertEqual([deadline], observed)

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

    def test_commit_mode_rejects_clean_checkout_at_another_resolvable_head(self) -> None:
        (self.repository / "tracked.txt").write_bytes(b"successor\n")
        self.git("add", "tracked.txt")
        self.git("commit", "-qm", "successor")
        requested_head = self.git("rev-parse", "HEAD").stdout.decode().strip()
        self.git("checkout", "-q", "--detach", self.base)

        with self.assertRaisesRegex(ValueError, "checkout HEAD"):
            self.adapter.identify(
                repository_id=self.REPOSITORY_ID,
                mode="commit",
                base_commit=self.base,
                head_commit=requested_head,
                effective_policy_sha256=self.POLICY,
                evidence_root="evidence",
            )


if __name__ == "__main__":
    unittest.main()
