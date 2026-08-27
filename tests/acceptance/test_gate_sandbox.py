import unittest
import tempfile
import subprocess
import os
from pathlib import Path

from codex_governance.domain.model import GateStatus
from codex_governance.evidence import content_address


class GateSandboxAcceptanceTest(unittest.TestCase):
    def capability(self) -> dict:
        return content_address({
            "schema_version": "1.0.0",
            "provider": "docker",
            "provider_version": "fixture",
            "implementation_sha256": "sha256:" + "9" * 64,
            "disposable": True,
            "secrets_present": False,
            "network_mode": "none",
            "candidate_copy_writable": True,
            "protected_paths_writable": False,
            "evidence_paths_writable": False,
            "supervisor_paths_writable": False,
            "process_limit": 64,
            "memory_bytes": 1000000,
            "cpu_seconds": 60,
            "timeout_seconds": 60,
            "output_bytes": 1000,
            "source_identity": "sha256:" + "a" * 64,
            "execution_identity": "sha256:" + "b" * 64,
            "verified_at": "2026-08-26T10:00:00Z",
            "limitations": ["unsigned local capability report"],
        }, "capability_id")

    def test_only_complete_safe_capability_report_is_usable(self) -> None:
        from codex_governance.sandbox import validate_sandbox_capability

        self.assertEqual([], validate_sandbox_capability(self.capability()))
        for field, unsafe in (
            ("disposable", False), ("secrets_present", True),
            ("network_mode", "declared"), ("protected_paths_writable", True),
            ("evidence_paths_writable", True), ("supervisor_paths_writable", True),
        ):
            report = self.capability()
            report[field] = unsafe
            with self.subTest(field=field):
                self.assertTrue(validate_sandbox_capability(report))

    def test_unavailable_isolation_is_unknown_without_host_fallback(self) -> None:
        from codex_governance.sandbox import classify_sandbox_execution

        self.assertEqual(
            GateStatus.UNKNOWN,
            classify_sandbox_execution(capability_report=None, termination="not_launched", exit_code=None, output_complete=False),
        )

    def test_container_command_disables_network_and_never_mounts_authority_writable(self) -> None:
        from codex_governance.sandbox import build_container_command

        with tempfile.TemporaryDirectory() as directory:
            command = build_container_command(
                executable="docker",
                image="python@sha256:" + "a" * 64,
                candidate_copy=str(Path(directory).resolve()),
                command=["python3", "-m", "unittest"],
                process_limit=64,
                memory_bytes=1000000,
                cpu_seconds=60,
            )
        joined = " ".join(command)
        self.assertIn("--network=none", command)
        self.assertIn("--pids-limit=64", command)
        self.assertIn("--read-only", command)
        self.assertEqual(
            "/tmp:rw,exec,nosuid,nodev,size=67108864",
            command[command.index("--tmpfs") + 1],
        )
        if hasattr(os, "getuid") and hasattr(os, "getgid"):
            self.assertEqual(
                f"{os.getuid()}:{os.getgid()}",
                command[command.index("--user") + 1],
            )
        self.assertNotIn("artifacts/governance", joined)
        self.assertNotIn("OPENAI_API_KEY", joined)
        self.assertNotIn("/var/run/docker.sock", joined)

    def test_production_invocation_binds_a_copy_to_a_pinned_image(self) -> None:
        from codex_governance.sandbox import build_container_invocation

        with tempfile.TemporaryDirectory() as directory:
            candidate_copy = Path(directory).resolve()
            invocation = build_container_invocation(
                executable="podman",
                provider_version="fixture",
                image="python@sha256:" + "c" * 64,
                candidate_copy=candidate_copy,
                candidate_id="sha256:" + "a" * 64,
                command=["python3", "-m", "unittest"],
                process_limit=64,
                memory_bytes=1000000,
                cpu_seconds=60,
                timeout_seconds=60,
                output_bytes=1000,
                implementation_sha256="sha256:" + "d" * 64,
                verified_at="2026-08-26T10:00:00Z",
            )
        self.assertEqual("podman", invocation.argv[0])
        self.assertEqual([], __import__(
            "codex_governance.sandbox", fromlist=["validate_sandbox_capability"]
        ).validate_sandbox_capability(invocation.capability_report))

    def test_candidate_copy_preserves_worktree_but_excludes_evidence_and_origin(self) -> None:
        from codex_governance.sandbox import prepare_candidate_copy

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            for arguments in (
                ["git", "init", "--quiet", str(repository)],
                ["git", "-C", str(repository), "config", "user.name", "Fixture"],
                ["git", "-C", str(repository), "config", "user.email", "fixture@example.invalid"],
            ):
                subprocess.run(arguments, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            (repository / "tracked.txt").write_text("original", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "tracked.txt"], check=True)
            subprocess.run(["git", "-C", str(repository), "commit", "--quiet", "-m", "fixture"], check=True)
            (repository / "tracked.txt").write_text("changed", encoding="utf-8")
            (repository / "untracked.txt").write_text("new", encoding="utf-8")
            evidence = repository / "artifacts" / "governance"
            evidence.mkdir(parents=True)
            (evidence / "machine-data.txt").write_text("must not copy", encoding="utf-8")
            copied = prepare_candidate_copy(
                repository=repository,
                destination=(root / "candidate-copy").resolve(),
                evidence_root="artifacts/governance",
            )
            self.assertEqual("changed", (copied / "tracked.txt").read_text(encoding="utf-8"))
            self.assertEqual("new", (copied / "untracked.txt").read_text(encoding="utf-8"))
            self.assertFalse((copied / "artifacts" / "governance").exists())
            remotes = subprocess.run(
                ["git", "-C", str(copied), "remote"], check=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ).stdout
            self.assertEqual(b"", remotes)

    def test_each_gate_gets_original_bytes_not_prior_gate_mutation(self) -> None:
        from codex_governance.sandbox import iter_fresh_gate_copies

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            for arguments in (
                ["git", "init", "--quiet", str(repository)],
                ["git", "-C", str(repository), "config", "user.name", "Fixture"],
                ["git", "-C", str(repository), "config", "user.email", "fixture@example.invalid"],
            ):
                subprocess.run(
                    arguments, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
            source = repository / "source.txt"
            source.write_text("original", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "source.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "--quiet", "-m", "fixture"],
                check=True,
            )
            supervisor = root / "supervisor"
            supervisor.mkdir()
            copies = iter_fresh_gate_copies(
                repository=repository,
                supervisor=supervisor,
                gate_ids=("first-gate", "second-gate"),
                evidence_root="artifacts/governance",
            )
            first_id, first = next(copies)
            (first / "source.txt").write_text("mutated-by-first", encoding="utf-8")
            second_id, second = next(copies)

            self.assertEqual("first-gate", first_id)
            self.assertEqual("second-gate", second_id)
            self.assertNotEqual(first, second)
            self.assertEqual("mutated-by-first", (first / "source.txt").read_text())
            self.assertEqual("original", (second / "source.txt").read_text())


if __name__ == "__main__":
    unittest.main()
