import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from codex_governance.artifacts import ArtifactSafetyError, FilesystemArtifactStore
from codex_governance.locking import PipelineLock, PipelineLockError


class PipelineLockAcceptanceTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[2]

    def test_second_process_fails_closed_while_first_holds_worktree_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(self.ROOT / "src")
            script = (
                "import sys\n"
                "from pathlib import Path\n"
                "from codex_governance.locking import PipelineLock\n"
                "with PipelineLock(repository=Path(sys.argv[1]), evidence_root='evidence'):\n"
                " print('LOCKED', flush=True)\n"
                " sys.stdin.read(1)\n"
            )
            holder = subprocess.Popen(
                [sys.executable, "-c", script, str(repository)],
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stderr = ""
            try:
                self.assertEqual("LOCKED\n", holder.stdout.readline())
                with self.assertRaisesRegex(PipelineLockError, "contended"):
                    with PipelineLock(
                        repository=repository, evidence_root="evidence"
                    ):
                        self.fail("contended lock unexpectedly succeeded")
            finally:
                try:
                    _, stderr = holder.communicate("x", timeout=10)
                except subprocess.TimeoutExpired:
                    holder.kill()
                    _, stderr = holder.communicate()
            self.assertEqual(0, holder.returncode, stderr)
            with PipelineLock(repository=repository, evidence_root="evidence"):
                self.assertTrue((repository / "evidence").is_dir())
                self.assertFalse((repository / "evidence/.pipeline.lock").exists())

    def test_replaceable_hardlinked_leaf_cannot_bypass_directory_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            evidence = repository / "evidence"
            evidence.mkdir()
            outside = repository / "outside-owned-file"
            outside.write_bytes(b"outside-owned\n")
            leaf = evidence / ".pipeline.lock"
            os.link(outside, leaf)
            with PipelineLock(repository=repository, evidence_root="evidence"):
                leaf.unlink()
                leaf.write_bytes(b"replacement\n")
                with self.assertRaisesRegex(PipelineLockError, "contended"):
                    with PipelineLock(
                        repository=repository, evidence_root="evidence"
                    ):
                        self.fail("replaceable leaf bypassed the directory lock")
            self.assertEqual(b"outside-owned\n", outside.read_bytes())
            self.assertEqual(b"replacement\n", leaf.read_bytes())

    def test_lock_rejects_symlinked_evidence_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            outside = repository / "outside"
            outside.mkdir()
            (repository / "evidence").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(PipelineLockError, "symlink"):
                with PipelineLock(
                    repository=repository, evidence_root="evidence"
                ):
                    self.fail("symlinked lock root unexpectedly succeeded")

    def test_replaced_root_cannot_share_lock_authority_with_publication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            first = PipelineLock(repository=repository, evidence_root="evidence")
            with first:
                original_identity = first.root_identity
                moved = repository / "original-evidence"
                (repository / "evidence").rename(moved)
                (repository / "evidence").mkdir()
                with self.assertRaisesRegex(PipelineLockError, "binding changed"):
                    first.assert_binding()
                store = FilesystemArtifactStore(
                    repository=repository,
                    root=Path("evidence"),
                    expected_root_identity=original_identity,
                )
                with self.assertRaisesRegex(
                    ArtifactSafetyError, "root binding changed"
                ):
                    store.write_bytes("result.json", b"{}")
                with PipelineLock(
                    repository=repository, evidence_root="evidence"
                ) as replacement_lock:
                    self.assertNotEqual(
                        original_identity, replacement_lock.root_identity
                    )
            self.assertFalse((repository / "evidence/result.json").exists())
            self.assertFalse((moved / "result.json").exists())


if __name__ == "__main__":
    unittest.main()
