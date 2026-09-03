import unittest
import tempfile
import subprocess
import os
import time
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
            "schema_version": "2.0.0",
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
        self.assertEqual([], invocation.capability_report["limitations"])
        self.assertEqual([], __import__(
            "codex_governance.sandbox", fromlist=["validate_sandbox_capability"]
        ).validate_sandbox_capability(invocation.capability_report))

    def test_rollback_invocation_mounts_protected_package_read_only(self) -> None:
        from codex_governance.sandbox import build_container_invocation
        from codex_governance.rollback import protected_rollback_command

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            candidate_copy = root / "candidate"
            protected_source = root / "protected-src"
            candidate_copy.mkdir()
            protected_source.mkdir()
            invocation = build_container_invocation(
                executable="docker",
                provider_version="fixture",
                image="python@sha256:" + "c" * 64,
                candidate_copy=candidate_copy,
                candidate_id="sha256:" + "a" * 64,
                command=protected_rollback_command("1" * 40),
                process_limit=64,
                memory_bytes=1000000,
                cpu_seconds=60,
                timeout_seconds=60,
                output_bytes=1000,
                implementation_sha256="sha256:" + "d" * 64,
                verified_at="2026-08-26T10:00:00Z",
                supervisor_cwd=root,
                protected_source_root=protected_source,
            )
        self.assertIn(
            f"type=bind,src={protected_source},dst=/opt/codex-governance,readonly",
            invocation.argv,
        )

    def test_protected_package_copy_contains_only_producer_digested_python(self) -> None:
        from codex_governance.attestation import producer_implementation_manifest
        from codex_governance.sandbox import prepare_protected_package_copy

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            (source / "sitecustomize.py").parent.mkdir(parents=True)
            (source / "sitecustomize.py").write_text(
                "raise SystemExit('sibling executed')\n", encoding="utf-8"
            )
            (source / "codex_governance/__pycache__").mkdir(parents=True)
            (source / "codex_governance/__init__.py").write_text(
                "VALUE = 1\n", encoding="utf-8"
            )
            (source / "codex_governance/rollback.py").write_text(
                "VALUE = 2\n", encoding="utf-8"
            )
            (source / "codex_governance/machine-local.txt").write_text(
                "ignored\n", encoding="utf-8"
            )
            (source / "codex_governance/__pycache__/rollback.pyc").write_bytes(
                b"machine-bytecode"
            )
            copied = prepare_protected_package_copy(
                package_root=source / "codex_governance",
                destination=root / "protected",
            )
            expected = {
                "codex_governance/" + item["path"]
                for item in producer_implementation_manifest(
                    "gate", source / "codex_governance"
                )["files"]
            }
            observed = {
                path.relative_to(copied).as_posix()
                for path in copied.rglob("*")
                if path.is_file()
            }
            self.assertEqual(expected, observed)
            self.assertFalse(
                (copied / "codex_governance/machine-local.txt").exists()
            )
            self.assertFalse(
                (copied / "codex_governance/__pycache__/rollback.pyc").exists()
            )
            self.assertFalse((copied / "sitecustomize.py").exists())

    def test_protected_rollback_command_disables_python_site_loading(self) -> None:
        from codex_governance.rollback import protected_rollback_command

        command = protected_rollback_command("1" * 40)
        self.assertEqual("python3", command[1])
        self.assertEqual("-I", command[2])
        self.assertEqual("-S", command[3])
        self.assertEqual("-c", command[4])
        self.assertIn("sys.path.insert(0,'/opt/codex-governance')", command[5])

    def test_container_create_and_cleanup_bind_the_exact_immutable_id(self) -> None:
        from codex_governance import sandbox as sandbox_module
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

            real_cidfile_read = sandbox_module.read_bounded_path_file
            observed_deadlines: list[float | None] = []

            def observe_cidfile_read(path, *, max_bytes, deadline=None):
                observed_deadlines.append(deadline)
                return real_cidfile_read(
                    path, max_bytes=max_bytes, deadline=deadline
                )

            with (
                patch(
                    "codex_governance.sandbox.subprocess.run",
                    side_effect=provider,
                ) as run,
                patch.object(
                    sandbox_module,
                    "read_bounded_path_file",
                    side_effect=observe_cidfile_read,
                ),
            ):
                create_deadline = time.monotonic() + 2
                self.assertEqual(
                    container_id,
                    create_container(invocation, deadline=create_deadline),
                )
                create_deadlines = list(observed_deadlines)
                cleanup_deadline = time.monotonic() + 10
                self.assertTrue(
                    cleanup_container(
                        invocation, container_id, deadline=cleanup_deadline
                    )
                )
                cleanup_deadlines = observed_deadlines[len(create_deadlines):]
            self.assertIn(
                ["docker", "rm", "--force", container_id],
                [call.args[0] for call in run.call_args_list],
            )
            self.assertEqual(1, len(create_deadlines))
            self.assertTrue(cleanup_deadlines)
            self.assertEqual(create_deadline, create_deadlines[0])
            self.assertEqual(cleanup_deadline, cleanup_deadlines[0])
            self.assertEqual(
                [cleanup_deadlines[0]] * len(cleanup_deadlines),
                cleanup_deadlines,
            )
            self.assertFalse(cidfile.exists())

    def test_container_id_file_replacement_or_special_leaf_fails_closed(self) -> None:
        from codex_governance import sandbox as sandbox_module
        from codex_governance.artifacts import ArtifactSafetyError
        from codex_governance.sandbox import (
            SandboxInvocation,
            cleanup_container,
            create_container,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cidfile = root / "fixture.cid"
            invocation = SandboxInvocation(
                ("docker", "create"), self.capability(), root, root,
                "docker", "codex-governance-fixture", cidfile,
            )
            container_id = "a" * 64

            def create_provider(arguments, **_kwargs):
                cidfile.write_text(container_id + "\n", encoding="ascii")
                return subprocess.CompletedProcess(
                    arguments, 0, stdout=(container_id + "\n").encode(), stderr=b""
                )

            with (
                patch(
                    "codex_governance.sandbox.subprocess.run",
                    side_effect=create_provider,
                ),
                patch.object(
                    sandbox_module,
                    "read_bounded_path_file",
                    side_effect=ArtifactSafetyError("binding changed"),
                ) as bounded_read,
            ):
                self.assertIsNone(
                    create_container(
                        invocation, deadline=time.monotonic() + 1
                    )
                )
            self.assertTrue(bounded_read.called)
            self.assertIsInstance(bounded_read.call_args.kwargs["deadline"], float)

            with (
                patch("codex_governance.sandbox.subprocess.run") as provider,
                patch.object(
                    sandbox_module,
                    "read_bounded_path_file",
                    side_effect=ArtifactSafetyError("special leaf"),
                ) as bounded_read,
            ):
                self.assertFalse(
                    cleanup_container(
                        invocation,
                        container_id,
                        deadline=time.monotonic() + 1,
                    )
                )
            provider.assert_not_called()
            self.assertTrue(bounded_read.called)
            self.assertIsInstance(bounded_read.call_args.kwargs["deadline"], float)

    def test_expired_absolute_container_deadlines_never_launch_provider(self) -> None:
        from codex_governance import sandbox as sandbox_module
        from codex_governance.sandbox import (
            SandboxInvocation,
            cleanup_container,
            create_container,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            invocation = SandboxInvocation(
                ("docker", "create"),
                self.capability(),
                root,
                root,
                "docker",
                "codex-governance-fixture",
                root / "fixture.cid",
            )
            caller_deadline = 100.0
            with (
                patch.object(
                    sandbox_module.time, "monotonic", return_value=100.01
                ),
                patch.object(sandbox_module.subprocess, "run") as provider,
            ):
                self.assertIsNone(
                    create_container(invocation, deadline=caller_deadline)
                )
                self.assertFalse(
                    cleanup_container(
                        invocation,
                        "a" * 64,
                        deadline=caller_deadline,
                    )
                )
            provider.assert_not_called()

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
                self.assertIsNone(
                    create_container(
                        invocation, deadline=time.monotonic() + 0.01
                    )
                )

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
                self.assertIsNone(
                    create_container(
                        invocation, deadline=time.monotonic() + 2
                    )
                )

            failed = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"")
            with patch("codex_governance.sandbox.subprocess.run", return_value=failed):
                self.assertFalse(
                    cleanup_container(
                        invocation,
                        "a" * 64,
                        deadline=time.monotonic() + 10,
                    )
                )

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
                    cleanup_container(
                        invocation, None, deadline=time.monotonic() + 2
                    )
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
                    cleanup_container(
                        invocation, late_id, deadline=time.monotonic() + 1
                    )
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
                        cleanup_container(
                            invocation,
                            original,
                            deadline=time.monotonic() + 2,
                        )
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

    def test_candidate_copy_git_helpers_receive_one_absolute_deadline(self) -> None:
        from codex_governance.sandbox import (
            CandidatePreparationError,
            prepare_candidate_copy,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            observed_timeouts = []

            def stalled_run(*args, **kwargs):
                observed_timeouts.append(kwargs.get("timeout"))
                raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout"))

            with patch(
                "codex_governance.sandbox.subprocess.run", side_effect=stalled_run
            ):
                with self.assertRaises(CandidatePreparationError):
                    prepare_candidate_copy(
                        repository=repository,
                        destination=root / "candidate",
                        evidence_root="artifacts/governance",
                        deadline=time.monotonic() + 0.25,
                    )
            self.assertEqual(1, len(observed_timeouts))
            observed_timeout = observed_timeouts[0]
            self.assertIsNotNone(observed_timeout)
            assert observed_timeout is not None
            self.assertGreater(observed_timeout, 0)
            self.assertLessEqual(observed_timeout, 0.25)

    def test_candidate_entries_use_descriptor_copy_with_the_shared_deadline(self) -> None:
        from codex_governance.sandbox import prepare_candidate_copy

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            (repository / "source.txt").write_text("bounded", encoding="utf-8")
            environment = dict(os.environ)
            environment.update(
                GIT_AUTHOR_NAME="fixture",
                GIT_AUTHOR_EMAIL="fixture@example.invalid",
                GIT_COMMITTER_NAME="fixture",
                GIT_COMMITTER_EMAIL="fixture@example.invalid",
            )
            for command in (
                ["git", "init", "-q", "-b", "main"],
                ["git", "add", "source.txt"],
                ["git", "commit", "-q", "-m", "fixture"],
            ):
                subprocess.run(
                    command, cwd=repository, env=environment, check=True
                )
            deadline = time.monotonic() + 10
            observed = []

            def descriptor_copy(
                source_root, relative_path, destination, *, deadline, max_bytes=None
            ):
                observed.append((source_root, relative_path, deadline))
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(
                    source_root.joinpath(*relative_path.split("/")).read_bytes()
                )
                return "regular", destination.stat()

            with patch(
                "codex_governance.sandbox.copy_bounded_repository_entry",
                side_effect=descriptor_copy,
            ):
                copied = prepare_candidate_copy(
                    repository=repository,
                    destination=root / "copy",
                    evidence_root="artifacts/governance",
                    deadline=deadline,
                )
            self.assertEqual("bounded", (copied / "source.txt").read_text())
            self.assertTrue(observed)
            self.assertTrue(
                all(item == (repository.resolve(), "source.txt", deadline) for item in observed)
            )

    def test_submodule_copy_is_reconstructed_without_ignored_worktree_files(self) -> None:
        from codex_governance.sandbox import prepare_candidate_copy

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child"
            parent = root / "parent"
            child.mkdir()
            parent.mkdir()
            for repository in (child, parent):
                subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
                subprocess.run(
                    ["git", "-C", str(repository), "config", "user.name", "Fixture"],
                    check=True,
                )
                subprocess.run(
                    [
                        "git", "-C", str(repository), "config", "user.email",
                        "fixture@example.invalid",
                    ],
                    check=True,
                )
            (child / ".gitignore").write_text("machine-local.txt\n", encoding="utf-8")
            (child / "safe.txt").write_text("tracked\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(child), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(child), "commit", "--quiet", "-m", "child"],
                check=True,
            )
            child_commit = subprocess.check_output(
                ["git", "-C", str(child), "rev-parse", "HEAD"], text=True
            ).strip()
            subprocess.run(
                [
                    "git", "-c", "protocol.file.allow=always", "-C", str(parent),
                    "submodule", "add", "--quiet", str(child), "vendor/child",
                ],
                check=True,
            )
            subprocess.run(["git", "-C", str(parent), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(parent), "commit", "--quiet", "-m", "parent"],
                check=True,
            )
            (parent / "vendor/child/machine-local.txt").write_text(
                "must-not-copy\n", encoding="utf-8"
            )

            copied = prepare_candidate_copy(
                repository=parent,
                destination=(root / "copy").resolve(),
                evidence_root="artifacts/governance",
            )

            self.assertEqual(
                "tracked\n", (copied / "vendor/child/safe.txt").read_text()
            )
            self.assertFalse((copied / "vendor/child/machine-local.txt").exists())
            self.assertEqual(
                child_commit,
                subprocess.check_output(
                    ["git", "-C", str(copied / "vendor/child"), "rev-parse", "HEAD"],
                    text=True,
                ).strip(),
            )


if __name__ == "__main__":
    unittest.main()
