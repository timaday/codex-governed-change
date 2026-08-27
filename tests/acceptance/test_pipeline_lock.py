import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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
            try:
                self.assertEqual("LOCKED\n", holder.stdout.readline())
                with self.assertRaisesRegex(PipelineLockError, "contended"):
                    with PipelineLock(
                        repository=repository, evidence_root="evidence"
                    ):
                        self.fail("contended lock unexpectedly succeeded")
            finally:
                if holder.stdin is not None:
                    holder.stdin.write("x")
                    holder.stdin.flush()
                holder.wait(timeout=10)
            self.assertEqual(0, holder.returncode, holder.stderr.read())
            with PipelineLock(repository=repository, evidence_root="evidence"):
                self.assertTrue((repository / "evidence/.pipeline.lock").is_file())

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


if __name__ == "__main__":
    unittest.main()
