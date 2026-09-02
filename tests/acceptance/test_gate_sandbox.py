import unittest
import tempfile
import subprocess
import os
from pathlib import Path
from unittest.mock import patch

from codex_governance.domain.model import GateStatus
from codex_governance.evidence import content_address


class GateSandboxAcceptanceTest(unittest.TestCase):
    def capability(self) -> dict:
        from codex_governance.sandbox import sandbox_execution_identity

        execution_identity = sandbox_execution_identity(
            provider="docker",
            provider_version="fixture",
            image="python@sha256:" + "c" * 64,
            command=["python3", "-m", "unittest"],
            process_limit=64,
            memory_bytes=1000000,
            cpu_seconds=60,
            timeout_seconds=60,
            output_bytes=1000,
        )
        return content_address({
            "schema_version": "1.0.0",
            "provider": "docker",
            "provider_version": "fixture",
            "image": "python@sha256:" + "c" * 64,
            "command": ["python3", "-m", "unittest"],
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
            "execution_identity": execution_identity,
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

    def test_readdressing_any_execution_field_cannot_preserve_capability(self) -> None:
        from codex_governance.sandbox import validate_sandbox_capability

        for field, replacement in (
            ("provider_version", "different"),
            ("image", "python@sha256:" + "d" * 64),
            ("command", ["python3", "-m", "compileall"]),
            ("process_limit", 65),
            ("memory_bytes", 1000001),
            ("cpu_seconds", 61),
            ("timeout_seconds", 61),
            ("output_bytes", 1001),
        ):
            report = self.capability()
            report[field] = replacement
            report = content_address(report, "capability_id")
            with self.subTest(field=field):
                self.assertIn(
                    "sandbox execution identity does not reconstruct",
                    validate_sandbox_capability(report),
                )

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
                container_name="codex-governance-fixture",
                container_id_file=str(Path(directory).resolve().parent / "fixture.cid"),
            )
        joined = " ".join(command)
        self.assertEqual("create", command[1])
        self.assertIn("--network=none", command)
        self.assertIn("--pids-limit=64", command)
        self.assertIn("--read-only", command)
        self.assertEqual(
            "codex-governance-fixture", command[command.index("--name") + 1]
        )
        self.assertEqual(
            str(Path(directory).resolve().parent / "fixture.cid"),
            command[command.index("--cidfile") + 1],
        )
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
                supervisor_cwd=candidate_copy.parent,
            )
        self.assertEqual("podman", invocation.argv[0])
        self.assertEqual("create", invocation.argv[1])
        self.assertEqual("podman", invocation.container_provider)
        self.assertIn("--name", invocation.argv)
        self.assertIn("--cidfile", invocation.argv)
        self.assertEqual(candidate_copy.parent, invocation.container_id_file.parent)
        self.assertEqual([], __import__(
            "codex_governance.sandbox", fromlist=["validate_sandbox_capability"]
        ).validate_sandbox_capability(invocation.capability_report))

    def test_container_create_and_cleanup_bind_the_exact_immutable_id(self) -> None:
        from codex_governance.sandbox import (
            SandboxInvocation,
            cleanup_container,
            create_container,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cidfile = root / "fixture.cid"
            invocation = SandboxInvocation(
                ("docker", "create"),
                self.capability(),
                root,
                root,
                "docker",
                "codex-governance-fixture",
                cidfile,
            )
            container_id = "a" * 64

            def provider(arguments, **_kwargs):
                if arguments[1] == "create":
                    cidfile.write_text(container_id + "\n", encoding="ascii")
                    return subprocess.CompletedProcess(arguments, 0, stdout=(container_id + "\n").encode(), stderr=b"")
                if arguments[1:3] == ["container", "inspect"] and "--format" in arguments:
                    return subprocess.CompletedProcess(
                        arguments,
                        0,
                        stdout=f"{container_id} /codex-governance-fixture\n".encode(),
                        stderr=b"",
                    )
                if arguments[1] == "rm":
                    return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")
                if arguments[1:3] == ["container", "ls"]:
                    return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")
                raise AssertionError(arguments)

            with patch("codex_governance.sandbox.subprocess.run", side_effect=provider) as run:
                self.assertEqual(
                    container_id,
                    create_container(invocation, timeout_seconds=2),
                )
                self.assertTrue(cleanup_container(invocation, container_id))
            self.assertIn(
                ["docker", "rm", "--force", container_id],
                [call.args[0] for call in run.call_args_list],
            )
            self.assertFalse(cidfile.exists())

    def test_delayed_or_renamed_container_create_never_becomes_complete(self) -> None:
        from codex_governance.sandbox import (
            SandboxInvocation,
            cleanup_container,
            create_container,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cidfile = root / "fixture.cid"
            invocation = SandboxInvocation(
                ("docker", "create"),
                self.capability(),
                root,
                root,
                "docker",
                "codex-governance-fixture",
                cidfile,
            )
            with patch(
                "codex_governance.sandbox.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["docker", "create"], 0.01),
            ):
                self.assertIsNone(create_container(invocation, timeout_seconds=0.01))

            created = subprocess.CompletedProcess(
                [], 0, stdout=("a" * 64 + "\n").encode(), stderr=b""
            )
            renamed = subprocess.CompletedProcess(
                [], 0, stdout=("a" * 64 + " /attacker-name\n").encode(), stderr=b""
            )
            def renamed_provider(arguments, **_kwargs):
                if arguments[1] == "create":
                    cidfile.write_text("a" * 64 + "\n", encoding="ascii")
                    return created
                return renamed

            with patch(
                "codex_governance.sandbox.subprocess.run",
                side_effect=renamed_provider,
            ):
                self.assertIsNone(create_container(invocation, timeout_seconds=2))

            failed = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"")
            with patch("codex_governance.sandbox.subprocess.run", return_value=failed):
                self.assertFalse(cleanup_container(invocation, "a" * 64))

    def test_cleanup_resolves_late_identity_and_never_treats_provider_failure_as_absence(self) -> None:
        from codex_governance.sandbox import SandboxInvocation, cleanup_container

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cidfile = root / "fixture.cid"
            invocation = SandboxInvocation(
                ("docker", "create"),
                self.capability(),
                root,
                root,
                "docker",
                "codex-governance-fixture",
                cidfile,
            )
            late_id = "b" * 64
            name_queries = 0

            def delayed_provider(arguments, **_kwargs):
                nonlocal name_queries
                if arguments[1:3] == ["container", "ls"]:
                    filter_value = arguments[arguments.index("--filter") + 1]
                    if filter_value.startswith("name="):
                        name_queries += 1
                        if name_queries == 7:
                            cidfile.write_text(late_id + "\n", encoding="ascii")
                            return subprocess.CompletedProcess(
                                arguments,
                                0,
                                stdout=f"{late_id} codex-governance-fixture\n".encode(),
                                stderr=b"",
                            )
                    return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")
                if arguments[1] == "rm":
                    self.assertEqual(late_id, arguments[-1])
                    return subprocess.CompletedProcess(arguments, 0, stdout=b"", stderr=b"")
                raise AssertionError(arguments)

            with patch(
                "codex_governance.sandbox.subprocess.run",
                side_effect=delayed_provider,
            ) as run:
                self.assertFalse(
                    cleanup_container(invocation, None, timeout_seconds=2)
                )
            self.assertIn(
                ["docker", "rm", "--force", late_id],
                [call.args[0] for call in run.call_args_list],
            )

            unavailable = subprocess.CompletedProcess(
                [], 125, stdout=b"", stderr=b"provider unavailable"
            )
            with patch(
                "codex_governance.sandbox.subprocess.run",
                return_value=unavailable,
            ):
                self.assertFalse(
                    cleanup_container(invocation, late_id, timeout_seconds=1)
                )

    def test_cleanup_identity_taint_survives_later_absence(self) -> None:
        from codex_governance.sandbox import SandboxInvocation, cleanup_container

        original = "a" * 64
        replacement = "b" * 64
        for scenario in ("renamed-original", "same-name-substitution"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                cidfile = root / "fixture.cid"
                cidfile.write_text(original + "\n", encoding="ascii")
                invocation = SandboxInvocation(
                    ("docker", "create"), self.capability(), root, root,
                    "docker", "codex-governance-fixture", cidfile,
                )
                first_name_query = True
                first_original_query = True

                def provider(arguments, **_kwargs):
                    nonlocal first_name_query, first_original_query
                    if arguments[1] == "rm":
                        return subprocess.CompletedProcess(arguments, 0, b"", b"")
                    if arguments[1:3] != ["container", "ls"]:
                        raise AssertionError(arguments)
                    selected = arguments[arguments.index("--filter") + 1]
                    output = b""
                    if scenario == "same-name-substitution" and selected.startswith("name=") and first_name_query:
                        first_name_query = False
                        output = (
                            f"{replacement} codex-governance-fixture\n".encode()
                        )
                    elif scenario == "renamed-original" and selected == f"id={original}" and first_original_query:
                        first_original_query = False
                        output = f"{original} attacker-renamed\n".encode()
                    return subprocess.CompletedProcess(arguments, 0, output, b"")

                with patch(
                    "codex_governance.sandbox.subprocess.run", side_effect=provider
                ) as run:
                    self.assertFalse(
                        cleanup_container(invocation, original, timeout_seconds=2)
                    )
                removed = {
                    call.args[0][-1]
                    for call in run.call_args_list
                    if call.args[0][1] == "rm"
                }
                self.assertIn(original, removed)
                if scenario == "same-name-substitution":
                    self.assertIn(replacement, removed)
                self.assertTrue(cidfile.exists())

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
