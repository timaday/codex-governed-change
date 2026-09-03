import errno
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    import resource
except ImportError:  # pragma: no cover - unavailable on Windows
    resource = None

from codex_governance.candidate import GitCliRepositoryAdapter
from codex_governance.canonical import sha256_bytes, sha256_canonical
from codex_governance.domain.model import ReviewerVerdict
from codex_governance import reviewer_signal_guard
from codex_governance.reviewer import (
    _ReviewerOutputAuthority,
    _validate_portable_reviewer_command,
    build_reviewer_command,
    build_reviewer_environment,
    build_reviewer_permission_profile,
    build_reviewer_execution_statement,
    build_reviewer_stdin,
    launch_reviewer,
    observe_codex_cli_version,
    prepare_sanitized_harness,
    reviewer_argv_sha256,
    reviewer_stream_is_portable,
    resolve_reviewer_runtime_read_roots,
    sanitized_invocation_descriptor,
)


class ReviewerAdapterTest(unittest.TestCase):
    CANDIDATE = "sha256:" + "a" * 64
    TASK = "sha256:" + "b" * 64
    POLICY = "sha256:" + "c" * 64
    GATES = "sha256:" + "d" * 64
    PROMPT = "sha256:" + "e" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.repository = root / "repository"
        self.repository.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Synthetic Test")
        self.git("config", "user.email", "synthetic@example.invalid")
        (self.repository / ".gitignore").write_text(
            "ignored-secret\nevidence/\n", encoding="utf-8"
        )
        (self.repository / "tracked.txt").write_text("base\n", encoding="utf-8")
        (self.repository / "deleted.txt").write_text("delete\n", encoding="utf-8")
        (self.repository / ".codex").mkdir()
        (self.repository / ".codex/config.toml").write_text(
            "candidate_instruction = 'untrusted'\n", encoding="utf-8"
        )
        self.git("add", ".")
        self.git("commit", "-qm", "base")
        (self.repository / "tracked.txt").write_text("working\n", encoding="utf-8")
        (self.repository / "deleted.txt").unlink()
        (self.repository / "untracked.txt").write_text("candidate\n", encoding="utf-8")
        (self.repository / "ignored-secret").write_text("never-copy\n", encoding="utf-8")
        self.harness_root = root / "harness"
        evidence = self.repository / "evidence"
        evidence.mkdir()
        raw_log = b"bounded gate observation\n"
        raw_gate = json.dumps({
            "artifacts": [{
                "path": "evidence/raw-log.bin",
                "sha256": sha256_bytes(raw_log),
            }]
        }, sort_keys=True).encode("utf-8")
        mutation = b"curated mutation summary\n"
        gates = json.dumps({
            "gate_results": [{
                "reference": {
                    "path": "evidence/raw-gate.json",
                    "sha256": sha256_bytes(raw_gate),
                }
            }]
        }, sort_keys=True).encode("utf-8")
        projection = json.dumps({
            "evidence_index": [{
                "reference": "evidence/mutation.json",
                "sha256": sha256_bytes(mutation),
            }]
        }, sort_keys=True).encode("utf-8")
        documents = {
            "task-contract.json": b"task\n",
            "effective-policy.json": b"policy\n",
            "gates.json": gates,
            "context-receipt.json": b"receipt\n",
            "context-sources.json": b"sources\n",
            "context-projection.json": projection,
            "context-qualification.json": b"context qualification\n",
            "reviewer-qualification.json": b"qualification\n",
            "raw-gate.json": raw_gate,
            "raw-log.bin": raw_log,
            "mutation.json": mutation,
        }
        for name, data in documents.items():
            (evidence / name).write_bytes(data)
        self.candidate = self.current_candidate()
        self.CANDIDATE = self.candidate["candidate_id"]
        prompt_path = Path(".codex/review/reviewer.prompt.md")
        self.PROMPT = sha256_bytes(prompt_path.read_bytes())
        self.inputs = {
            "review_mode": "conformance",
            "repository_id": "repo:example/project",
            "candidate_id": self.CANDIDATE,
            "candidate_path": "candidate",
            "task_contract_path": "evidence/task-contract.json",
            "task_contract_sha256": sha256_bytes(documents["task-contract.json"]),
            "effective_policy_path": "evidence/effective-policy.json",
            "effective_policy_sha256": sha256_bytes(documents["effective-policy.json"]),
            "gate_manifest_path": "evidence/gates.json",
            "gate_manifest_sha256": sha256_bytes(documents["gates.json"]),
            "reviewer_prompt_sha256": self.PROMPT,
            "context_receipt_path": "evidence/context-receipt.json",
            "context_receipt_sha256": sha256_bytes(documents["context-receipt.json"]),
            "context_sources_path": "evidence/context-sources.json",
            "context_sources_sha256": sha256_bytes(documents["context-sources.json"]),
            "context_projection_path": "evidence/context-projection.json",
            "context_projection_sha256": sha256_bytes(documents["context-projection.json"]),
            "context_qualification_path": "evidence/context-qualification.json",
            "context_qualification_sha256": sha256_bytes(
                documents["context-qualification.json"]
            ),
            "context_qualification_id": "sha256:" + "4" * 64,
            "reviewer_qualification_path": "evidence/reviewer-qualification.json",
            "reviewer_qualification_sha256": sha256_bytes(
                documents["reviewer-qualification.json"]
            ),
            "reviewer_qualification_id": "sha256:" + "3" * 64,
        }
        self.harness = prepare_sanitized_harness(
            candidate_repository=self.repository,
            harness_root=self.harness_root,
            fixed_prompt_path=prompt_path,
            output_schema_path=Path("schemas/reviewer-result.schema.json"),
            permitted_inputs=self.inputs,
            expected_candidate=self.candidate,
            evidence_root="evidence",
        )

    def tearDown(self) -> None:
        # Restore permissions so TemporaryDirectory can clean the immutable fixture.
        for path in self.harness_root.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() else 0o644)
        self.temporary.cleanup()

    def git(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-C", str(self.repository), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def current_candidate(self, *, evidence_root: str = "evidence") -> dict:
        head = self.git("rev-parse", "HEAD").stdout.decode("ascii").strip()
        return GitCliRepositoryAdapter(self.repository).identify(
            repository_id="repo:example/project",
            mode="working_tree",
            base_commit=head,
            head_commit=head,
            effective_policy_sha256=self.POLICY,
            evidence_root=evidence_root,
        )

    def fake_codex(self, body: str) -> Path:
        executable = Path(self.temporary.name) / f"fake-codex-{len(list(Path(self.temporary.name).glob('fake-codex-*')))}"
        claims = [
            {
                "claim_id": claim_id,
                "claim": claim_id,
                "classification": "VERIFIED_WITHIN_SCOPE",
                "evidence_refs": [
                    {
                        "locator_id": "sha256:" + "1" * 64,
                        "sha256": "sha256:" + "2" * 64,
                    }
                ],
            }
            for claim_id in (
                "candidate_identity",
                "required_gates",
                "affected_closure",
                "governance_integrity",
                "evidence_reconstruction",
            )
        ]
        executable.write_text(
            "#!/usr/bin/env python3\nMANDATORY_CLAIMS = " + repr(claims) + "\n" + body,
            encoding="utf-8",
        )
        executable.chmod(0o755)
        return executable

    def command(self, executable: Path) -> list[str]:
        return build_reviewer_command(
            codex_executable=str(executable),
            model="fake-gpt",
            schema_path=self.harness["schema"],
            output_path=self.harness["output"],
            review_root=self.harness["root"],
        )

    def stdin(self) -> str:
        return build_reviewer_stdin(
            fixed_prompt=self.harness["prompt"].read_text(encoding="utf-8"),
            permitted_inputs=self.inputs,
        )

    def test_security_distinct_permission_profile_is_not_portably_normalized(self) -> None:
        command = self.command(Path(sys.executable))
        permission_index = next(
            index + 1
            for index, value in enumerate(command[:-1])
            if value == "--config"
            and command[index + 1].startswith(
                'permissions={governed_reviewer={extends=":read-only"'
            )
        )
        command[permission_index] = command[permission_index].replace(
            "network={enabled=false}", "network={enabled=true}"
        )
        with self.assertRaisesRegex(ValueError, "permission profile"):
            _validate_portable_reviewer_command(
                command, model="fake-gpt", reasoning_effort="xhigh"
            )

    @staticmethod
    def host_processes_with_command_token(token: str) -> list[int]:
        matches: list[int] = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            try:
                command = (entry / "cmdline").read_bytes()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            if token.encode("ascii") in command:
                matches.append(int(entry.name))
        return matches

    def assert_reviewer_descendant_is_cleaned(
        self, retained: str, *, escape_session: bool = False
    ) -> None:
        inherited = retained
        stdout = "None" if retained == "stdout" else "subprocess.DEVNULL"
        stderr = "None" if retained == "stderr" else "subprocess.DEVNULL"
        suffix = "-escaped" if escape_session else ""
        marker = self.harness["root"] / f"retained-{retained}{suffix}.json"
        process_token = f"reviewer-descendant-{retained}{suffix}"
        child_program = f"""import json, signal, time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path({str(marker)!r}).write_text(json.dumps({{'started': True, 'stream': {inherited!r}}}))
time.sleep(30)
"""
        fake = self.fake_codex(
            f"""import json, os, signal, subprocess, sys
import time
from pathlib import Path
args = sys.argv[1:]
inputs = json.loads(sys.stdin.read().split('PERMITTED_INPUTS ', 1)[1])
child = subprocess.Popen(
    [sys.executable, '-c', {child_program!r}, {process_token!r}],
    stdin=subprocess.DEVNULL, stdout={stdout}, stderr={stderr},
    start_new_session={escape_session!r},
)
deadline = time.monotonic() + 2
while not Path({str(marker)!r}).is_file() and time.monotonic() < deadline:
    time.sleep(0.01)
payload = {{
  'schema_version': '3.0.0', 'repository_id': inputs['repository_id'],
  'candidate_id': inputs['candidate_id'],
  'task_contract_sha256': inputs['task_contract_sha256'],
  'effective_policy_sha256': inputs['effective_policy_sha256'],
  'gate_manifest_sha256': inputs['gate_manifest_sha256'],
  'context_receipt_sha256': inputs['context_receipt_sha256'],
  'reviewer_prompt_sha256': inputs['reviewer_prompt_sha256'],
  'qualification_id': inputs['reviewer_qualification_id'],
  'model': 'fake-gpt', 'invocation_id': 'fake:retained-{retained}',
  'verdict': 'NO_BLOCKING_FINDING_OBSERVED',
  'reviewed_surfaces': ['candidate'], 'affected_closure': ['candidate'],
  'retrieval_expansions': [], 'findings': [], 'missing_evidence': [],
  'claims': MANDATORY_CLAIMS, 'limitations': []
}}
Path(args[args.index('--output-last-message') + 1]).write_text(json.dumps(payload))
print(json.dumps({{'type': 'thread.started', 'thread_id': 'retained-stream'}}))
print(json.dumps({{'type': 'turn.completed', 'usage': {{'input_tokens': 1, 'cached_input_tokens': 0, 'output_tokens': 1, 'reasoning_output_tokens': 0}}}}))
"""
        )
        try:
            result = launch_reviewer(
                command=self.command(fake),
                stdin_text=self.stdin(),
                schema_path=self.harness["schema"],
                output_path=self.harness["output"],
                expected_candidate_id=self.CANDIDATE,
                candidate_supplier=lambda _deadline: self.CANDIDATE,
                expected_bindings={
                    "repository_id": self.inputs["repository_id"],
                    "task_contract_sha256": self.inputs["task_contract_sha256"],
                },
                timeout_seconds=2,
            )
            marker_data = json.loads(marker.read_text(encoding="utf-8"))
            self.assertTrue(marker_data["started"])
            self.assertEqual(ReviewerVerdict.UNKNOWN, result["verdict"])
            self.assertFalse(result["execution_valid"])
            self.assertFalse(result["observation_complete"])
            self.assertTrue(result["capture_threads_completed"])
            self.assertTrue(result["process_cleanup_complete"])
            live = self.host_processes_with_command_token(process_token)
            if live:
                self.fail("retained reviewer descendant remained live")
        finally:
            for child_pid in self.host_processes_with_command_token(process_token):
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper contract")
    def test_zero_exit_parent_with_retained_stdout_is_unknown_and_cleaned(self) -> None:
        self.assert_reviewer_descendant_is_cleaned("stdout")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper contract")
    def test_zero_exit_parent_with_retained_stderr_is_unknown_and_cleaned(self) -> None:
        self.assert_reviewer_descendant_is_cleaned("stderr")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper contract")
    def test_zero_exit_parent_with_closed_stream_descendant_is_unknown_and_cleaned(self) -> None:
        self.assert_reviewer_descendant_is_cleaned("closed")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper contract")
    def test_session_escaped_closed_stream_descendant_is_unknown_and_cleaned(self) -> None:
        self.assert_reviewer_descendant_is_cleaned(
            "closed", escape_session=True
        )

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux subreaper contract")
    def test_timeout_lets_subreaper_clean_session_escaped_descendant(self) -> None:
        marker = self.harness["root"] / "timeout-escaped-pid"
        process_token = "reviewer-timeout-escaped-descendant"
        child_program = f"""import signal, time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path({str(marker)!r}).write_text('started')
time.sleep(30)
"""
        fake = self.fake_codex(
            f"""import subprocess, sys, time
from pathlib import Path
child = subprocess.Popen(
    [sys.executable, '-c', {child_program!r}, {process_token!r}],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    start_new_session=True,
)
deadline = time.monotonic() + 2
while not Path({str(marker)!r}).is_file() and time.monotonic() < deadline:
    time.sleep(0.01)
time.sleep(30)
"""
        )
        result = launch_reviewer(
            command=self.command(fake),
            stdin_text=self.stdin(),
            schema_path=self.harness["schema"],
            output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            timeout_seconds=1.0,
        )
        self.assertTrue(result["timed_out"])
        self.assertEqual(ReviewerVerdict.UNKNOWN, result["verdict"])
        self.assertTrue(result["process_cleanup_complete"])
        self.assertEqual("started", marker.read_text(encoding="utf-8"))
        live = self.host_processes_with_command_token(process_token)
        if live:
            for child_pid in live:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.fail("timed-out escaped reviewer descendant remained live")

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux namespace contract")
    def test_reviewer_cannot_kill_namespace_init_or_leak_setsid_child(self) -> None:
        marker = self.harness["root"] / "assassination-child-host-pid"
        attack = self.harness["root"] / "assassination-attempt"
        process_token = "reviewer-assassination-setsid-descendant"
        child_program = f"""import signal, time
from pathlib import Path
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path({str(marker)!r}).write_text('started')
time.sleep(30)
"""
        fake = self.fake_codex(
            f"""import os, signal, subprocess, sys, time
from pathlib import Path
sys.stdin.read()
subprocess.Popen(
    [sys.executable, '-c', {child_program!r}, {process_token!r}],
    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL, start_new_session=True,
)
deadline = time.monotonic() + 2
while not Path({str(marker)!r}).is_file() and time.monotonic() < deadline:
    time.sleep(0.01)
try:
    os.kill(os.getppid(), signal.SIGKILL)
except PermissionError:
    outcome = 'blocked'
else:
    outcome = 'caller-survived'
Path({str(attack)!r}).write_text(outcome)
"""
        )
        result = launch_reviewer(
            command=self.command(fake),
            stdin_text=self.stdin(),
            schema_path=self.harness["schema"],
            output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            timeout_seconds=2,
        )
        self.assertIn(
            attack.read_text(encoding="utf-8"), {"blocked", "caller-survived"}
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, result["verdict"])
        self.assertFalse(result["observation_complete"])
        self.assertTrue(result["process_cleanup_complete"])
        self.assertEqual("started", marker.read_text(encoding="utf-8"))
        live = self.host_processes_with_command_token(process_token)
        if live:
            for child_pid in live:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.fail("supervisor-assassination descendant remained live")

    @unittest.skipUnless(
        sys.platform.startswith("linux") and platform.machine().lower() == "x86_64",
        "x86_64 Linux seccomp contract",
    )
    def test_signal_guard_denies_x32_syscall_space_before_dispatch(self) -> None:
        marker = self.harness["root"] / "x32-kill-result"
        handshake_read, handshake_write = os.pipe()
        os.set_inheritable(handshake_write, True)
        x32_kill = reviewer_signal_guard.X32_SYSCALL_BIT | 62
        probe = f"""import ctypes, os
from pathlib import Path
libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
result = libc.syscall({x32_kill}, os.getppid(), 0)
Path({str(marker)!r}).write_text(f'{{result}}:{{ctypes.get_errno()}}')
"""
        process = subprocess.Popen(
            [
                sys.executable,
                os.fspath(Path(reviewer_signal_guard.__file__)),
                str(handshake_write),
                "--",
                sys.executable,
                "-c",
                probe,
            ],
            close_fds=True,
            pass_fds=(handshake_write,),
        )
        os.close(handshake_write)
        try:
            handshake = os.read(handshake_read, 4096)
        finally:
            os.close(handshake_read)
        self.assertEqual(0, process.wait(timeout=5))
        self.assertEqual(
            "seccomp_signal_guard", json.loads(handshake.decode("ascii"))["boundary"]
        )
        self.assertEqual(f"-1:{errno.EPERM}", marker.read_text(encoding="utf-8"))

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and resource is not None
        and platform.machine().lower() in {"aarch64", "x86_64"},
        "supported Linux seccomp contract",
    )
    def test_signal_guard_denies_parent_resource_limit_mutation(self) -> None:
        marker = self.harness["root"] / "prlimit-result"
        handshake_read, handshake_write = os.pipe()
        os.set_inheritable(handshake_write, True)
        machine = platform.machine().lower()
        syscall_number = reviewer_signal_guard.PRLIMIT64_SYSCALLS[machine]
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        unsigned_max = (1 << (8 * __import__("ctypes").sizeof(__import__("ctypes").c_ulong))) - 1
        soft_value = unsigned_max if soft == resource.RLIM_INFINITY else soft
        hard_value = unsigned_max if hard == resource.RLIM_INFINITY else hard
        probe = f"""import ctypes, errno, os, resource
from pathlib import Path
class Rlimit(ctypes.Structure):
    _fields_ = [('soft', ctypes.c_ulong), ('hard', ctypes.c_ulong)]
limit = Rlimit({soft_value}, {hard_value})
libc = ctypes.CDLL(None, use_errno=True)
ctypes.set_errno(0)
result = libc.syscall(
    {syscall_number}, os.getppid(), resource.RLIMIT_NOFILE,
    ctypes.byref(limit), ctypes.c_void_p(),
)
Path({str(marker)!r}).write_text(f'{{result}}:{{ctypes.get_errno()}}')
"""
        process = subprocess.Popen(
            [
                sys.executable,
                os.fspath(Path(reviewer_signal_guard.__file__)),
                str(handshake_write),
                "--",
                sys.executable,
                "-c",
                probe,
            ],
            close_fds=True,
            pass_fds=(handshake_write,),
        )
        os.close(handshake_write)
        try:
            handshake = json.loads(os.read(handshake_read, 4096).decode("ascii"))
        finally:
            os.close(handshake_read)
        self.assertEqual(0, process.wait(timeout=5))
        self.assertTrue(handshake["resource_limit_changes_blocked"])
        self.assertEqual(f"-1:{errno.EPERM}", marker.read_text(encoding="utf-8"))

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and platform.machine().lower() in {"aarch64", "x86_64"},
        "supported Linux seccomp contract",
    )
    def test_signal_guard_denies_asynchronous_fcntl_signal_operations(self) -> None:
        marker = self.harness["root"] / "fcntl-signal-results"
        handshake_read, handshake_write = os.pipe()
        os.set_inheritable(handshake_write, True)
        machine = platform.machine().lower()
        syscall_number = reviewer_signal_guard.FCNTL_SYSCALLS[machine]
        commands = (8, 10, 15, 1024, 1026)
        self.assertEqual(commands, reviewer_signal_guard.DENIED_FCNTL_COMMANDS)
        probe = f"""import ctypes, errno, os
from pathlib import Path
libc = ctypes.CDLL(None, use_errno=True)
results = []
ctypes.set_errno(0)
result = libc.syscall(
    {syscall_number}, 0, {reviewer_signal_guard.F_SETFL_COMMAND}, os.O_NONBLOCK
)
results.append(f'safe:{{result}}:{{ctypes.get_errno()}}')
ctypes.set_errno(0)
result = libc.syscall(
    {syscall_number}, 0, {reviewer_signal_guard.F_SETFL_COMMAND}, os.O_ASYNC
)
results.append(f'async:{{result}}:{{ctypes.get_errno()}}')
for command in {commands!r}:
    ctypes.set_errno(0)
    result = libc.syscall({syscall_number}, 0, command, 0)
    results.append(f'{{command}}:{{result}}:{{ctypes.get_errno()}}')
Path({str(marker)!r}).write_text('\\n'.join(results))
"""
        process = subprocess.Popen(
            [
                sys.executable,
                os.fspath(Path(reviewer_signal_guard.__file__)),
                str(handshake_write),
                "--",
                sys.executable,
                "-c",
                probe,
            ],
            close_fds=True,
            pass_fds=(handshake_write,),
        )
        os.close(handshake_write)
        try:
            handshake = json.loads(os.read(handshake_read, 4096).decode("ascii"))
        finally:
            os.close(handshake_read)
        self.assertEqual(0, process.wait(timeout=5))
        self.assertTrue(handshake["process_signals_blocked"])
        self.assertEqual(
            [
                "safe:0:0",
                f"async:-1:{errno.EPERM}",
                *[f"{command}:-1:{errno.EPERM}" for command in commands],
            ],
            marker.read_text(encoding="utf-8").splitlines(),
        )

    def test_snapshot_is_exact_bounded_data_under_an_outer_git_root(self) -> None:
        candidate = self.harness["candidate"]
        self.assertEqual("working\n", (candidate / "tracked.txt").read_text(encoding="utf-8"))
        self.assertEqual("candidate\n", (candidate / "untracked.txt").read_text(encoding="utf-8"))
        self.assertFalse((candidate / "deleted.txt").exists())
        self.assertFalse((candidate / "ignored-secret").exists())
        self.assertFalse((candidate / "evidence").exists())
        self.assertEqual(
            (self.repository / "evidence/gates.json").read_bytes(),
            (self.harness["root"] / "evidence/gates.json").read_bytes(),
        )
        self.assertEqual(
            b"bounded gate observation\n",
            (self.harness["root"] / "evidence/raw-log.bin").read_bytes(),
        )
        self.assertEqual(
            b"curated mutation summary\n",
            (self.harness["root"] / "evidence/mutation.json").read_bytes(),
        )
        self.assertTrue((candidate / ".codex/config.toml").is_file())
        outer = subprocess.run(
            ["git", "-C", str(self.harness["root"]), "rev-parse", "--show-toplevel"],
            check=True, stdout=subprocess.PIPE, text=True,
        ).stdout.strip()
        self.assertEqual(self.harness["root"], Path(outer))
        self.assertFalse((candidate / "tracked.txt").stat().st_mode & 0o222)
        self.assertNotIn(str(self.repository), (candidate / ".git/config").read_text(encoding="utf-8"))

    def test_source_change_during_copy_is_rejected_by_snapshot_identity(self) -> None:
        from codex_governance import reviewer

        original = reviewer._copy_entry
        changed = False

        def race(
            repository: Path,
            relative_path: str,
            destination: Path,
            *,
            deadline: float | None = None,
        ) -> None:
            nonlocal changed
            if relative_path == "tracked.txt" and not changed:
                (repository / relative_path).write_text("raced\n", encoding="utf-8")
                changed = True
            original(
                repository,
                relative_path,
                destination,
                deadline=deadline,
            )

        with patch("codex_governance.reviewer._copy_entry", side_effect=race):
            with self.assertRaisesRegex(ValueError, "snapshot does not match"):
                prepare_sanitized_harness(
                    candidate_repository=self.repository,
                    harness_root=Path(self.temporary.name) / "racing-harness",
                    fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                    output_schema_path=Path("schemas/reviewer-result.schema.json"),
                    permitted_inputs=self.inputs,
                    expected_candidate=self.candidate,
                    evidence_root="evidence",
                )

    def test_snapshot_git_clone_obeys_the_shared_absolute_deadline(self) -> None:
        real_run = subprocess.run

        def bounded(arguments, **kwargs):
            if arguments[:2] == ["git", "clone"]:
                self.assertIsNotNone(kwargs.get("timeout"))
                raise subprocess.TimeoutExpired(arguments, kwargs["timeout"])
            return real_run(arguments, **kwargs)

        with patch("codex_governance.reviewer.subprocess.run", side_effect=bounded):
            with self.assertRaisesRegex(TimeoutError, "snapshot clone"):
                prepare_sanitized_harness(
                    candidate_repository=self.repository,
                    harness_root=Path(self.temporary.name) / "deadline-harness",
                    fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                    output_schema_path=Path("schemas/reviewer-result.schema.json"),
                    permitted_inputs=self.inputs,
                    expected_candidate=self.candidate,
                    evidence_root="evidence",
                    deadline=time.monotonic() + 2,
                )

    def test_snapshot_copy_and_permissions_share_the_absolute_deadline(self) -> None:
        from codex_governance import reviewer

        copy_deadlines = []
        permission_deadlines = []
        real_copy = reviewer.copy_bounded_repository_entry
        real_permissions = reviewer.make_tree_read_only_bounded

        def copy_entry(
            repository, relative_path, destination, *, deadline, max_bytes=None
        ):
            copy_deadlines.append(deadline)
            return real_copy(
                repository,
                relative_path,
                destination,
                deadline=deadline,
                max_bytes=max_bytes,
            )

        def finalize_permissions(root, *, deadline):
            permission_deadlines.append(deadline)
            return real_permissions(root, deadline=deadline)

        deadline = time.monotonic() + 10
        with (
            patch(
                "codex_governance.reviewer.copy_bounded_repository_entry",
                side_effect=copy_entry,
            ),
            patch(
                "codex_governance.reviewer.make_tree_read_only_bounded",
                side_effect=finalize_permissions,
            ),
        ):
            prepare_sanitized_harness(
                candidate_repository=self.repository,
                harness_root=Path(self.temporary.name) / "bounded-copy-harness",
                fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                output_schema_path=Path("schemas/reviewer-result.schema.json"),
                permitted_inputs=self.inputs,
                expected_candidate=self.candidate,
                evidence_root="evidence",
                deadline=deadline,
            )
        self.assertTrue(copy_deadlines)
        self.assertTrue(permission_deadlines)
        self.assertEqual({deadline}, set(copy_deadlines + permission_deadlines))

    def test_protected_evidence_root_is_configurable_and_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "protected evidence root"):
            prepare_sanitized_harness(
                candidate_repository=self.repository,
                harness_root=Path(self.temporary.name) / "other-harness",
                fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                output_schema_path=Path("schemas/reviewer-result.schema.json"),
                permitted_inputs=self.inputs,
                expected_candidate=self.current_candidate(
                    evidence_root="artifacts/governance"
                ),
                evidence_root="artifacts/governance",
            )

    def test_fake_codex_proves_allowlist_environment_and_schema_binding(self) -> None:
        fake = self.fake_codex(
            """import json, os, sys
from pathlib import Path
args = sys.argv[1:]
raw = sys.stdin.read()
inputs = json.loads(raw.split('PERMITTED_INPUTS ', 1)[1])
output = Path(args[args.index('--output-last-message') + 1])
result = {
  'schema_version': '3.0.0', 'repository_id': inputs['repository_id'],
  'candidate_id': inputs['candidate_id'],
  'task_contract_sha256': inputs['task_contract_sha256'],
  'effective_policy_sha256': inputs['effective_policy_sha256'],
  'gate_manifest_sha256': inputs['gate_manifest_sha256'],
  'context_receipt_sha256': inputs['context_receipt_sha256'],
  'reviewer_prompt_sha256': inputs['reviewer_prompt_sha256'],
  'qualification_id': inputs['reviewer_qualification_id'],
  'model': 'fake-gpt', 'invocation_id': 'fake:1',
  'verdict': 'NO_BLOCKING_FINDING_OBSERVED',
  'reviewed_surfaces': ['candidate'], 'affected_closure': ['candidate'],
  'retrieval_expansions': [], 'findings': [], 'missing_evidence': [],
  'claims': MANDATORY_CLAIMS, 'limitations': []
}
output.write_bytes((json.dumps(result, indent=2) + '\\n').encode('utf-8'))
observed = Path(args[args.index('--cd') + 1]) / 'observed.json'
observed.write_text(json.dumps({'argv': args, 'stdin': raw, 'env_keys': sorted(os.environ)}), encoding='utf-8')
print(json.dumps({'type': 'thread.started', 'thread_id': 'fake-thread-1'}))
print(json.dumps({'type': 'turn.completed', 'usage': {
  'input_tokens': 120, 'cached_input_tokens': 40,
  'output_tokens': 30, 'reasoning_output_tokens': 10
}}))
"""
        )
        environment = dict(os.environ)
        environment["AUTHOR_TRANSCRIPT_SECRET"] = "context-canary"
        environment["OPENAI_API_KEY"] = "api-key-canary"
        environment["CODEX_API_KEY"] = "codex-api-key-canary"
        result = launch_reviewer(
            command=self.command(fake), stdin_text=self.stdin(),
            schema_path=self.harness["schema"], output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            expected_bindings={
                "repository_id": self.inputs["repository_id"],
                "task_contract_sha256": self.inputs["task_contract_sha256"],
            },
            timeout_seconds=2, environment=environment,
        )
        self.assertEqual(ReviewerVerdict.NO_BLOCKING_FINDING_OBSERVED, result["verdict"])
        observed = json.loads((self.harness["root"] / "observed.json").read_text(encoding="utf-8"))
        self.assertNotIn("AUTHOR_TRANSCRIPT_SECRET", observed["env_keys"])
        self.assertNotIn("OPENAI_API_KEY", observed["env_keys"])
        self.assertNotIn("CODEX_API_KEY", observed["env_keys"])
        self.assertNotIn("context-canary", observed["stdin"])
        self.assertIn("--ephemeral", observed["argv"])
        self.assertIn("--json", observed["argv"])
        observed_argv = " ".join(observed["argv"])
        self.assertIn('extends=":read-only"', observed_argv)
        self.assertIn('":root"="deny"', observed_argv)
        self.assertTrue(result["usage_observed"])
        self.assertEqual(120, result["input_tokens"])
        self.assertEqual(40, result["cached_input_tokens"])
        self.assertEqual(30, result["output_tokens"])
        self.assertEqual(10, result["reasoning_output_tokens"])
        self.assertEqual("fake-thread-1", result["thread_id"])
        self.assertNotEqual(
            sha256_canonical(self.command(fake)),
            result["executed_argv_sha256"],
        )
        self.assertEqual(
            result["observation"]["supervisor"]["executed_argv_sha256"],
            result["executed_argv_sha256"],
        )
        exact_output = (
            json.dumps(result["result"], indent=2) + "\n"
        ).encode("utf-8")
        self.assertEqual(exact_output, result["output_bytes"])
        self.assertEqual(sha256_bytes(exact_output), result["output_sha256"])
        descriptor = sanitized_invocation_descriptor(
            model="fake-gpt", reasoning_effort="xhigh", prompt_sha256=self.PROMPT
        )
        self.assertNotIn(str(fake), json.dumps(descriptor))
        self.assertFalse(descriptor["environment_values_recorded"])
        self.assertFalse(descriptor["author_context_available"])
        self.assertFalse(descriptor["connectors_available"])
        self.assertEqual("custom-read-only", descriptor["sandbox"])
        self.assertFalse(descriptor["host_root_readable"])
        self.assertFalse(descriptor["tool_network_enabled"])
        self.assertEqual("never", descriptor["approval_policy"])

        self.harness["output"].unlink()
        wrong_binding = launch_reviewer(
            command=self.command(fake), stdin_text=self.stdin(),
            schema_path=self.harness["schema"], output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            expected_bindings={"task_contract_sha256": "sha256:" + "0" * 64},
            timeout_seconds=2, environment=environment,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, wrong_binding["verdict"])
        self.assertFalse(wrong_binding["bindings_match"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO contract is unavailable")
    def test_reviewer_output_authority_rejects_special_leaf_without_blocking(self) -> None:
        output = Path(self.temporary.name) / "special-output.json"
        authority = _ReviewerOutputAuthority(output)
        try:
            os.mkfifo(output)
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                authority.read_once(1_000)
            self.assertLess(time.monotonic() - started, 1.0)
        finally:
            authority.close()
            output.unlink(missing_ok=True)

    def test_reviewer_output_authority_rejects_leaf_swap_after_exact_read(self) -> None:
        output = Path(self.temporary.name) / "swapped-output.json"
        authority = _ReviewerOutputAuthority(output)
        output.write_bytes(b'{"observed":true}\n')
        moved = Path(self.temporary.name) / "original-output.json"
        real_fstat = os.fstat
        observations = 0
        swapped = False

        def swap_after_final_descriptor_observation(descriptor: int):
            nonlocal observations, swapped
            observed = real_fstat(descriptor)
            observations += 1
            if observations == 2 and not swapped:
                output.rename(moved)
                output.write_bytes(b'{"replacement":true}\n')
                swapped = True
            return observed

        try:
            with patch(
                "codex_governance.reviewer.os.fstat",
                side_effect=swap_after_final_descriptor_observation,
            ):
                with self.assertRaisesRegex(ValueError, "binding changed"):
                    authority.read_once(1_000)
        finally:
            authority.close()

    def test_reviewer_output_authority_rejects_parent_swap(self) -> None:
        parent = Path(self.temporary.name) / "output-parent"
        parent.mkdir()
        output = parent / "reviewer-result.json"
        authority = _ReviewerOutputAuthority(output)
        output.write_bytes(b'{"observed":true}\n')
        original_parent = Path(self.temporary.name) / "original-output-parent"
        replacement_parent = Path(self.temporary.name) / "output-parent"
        parent.rename(original_parent)
        replacement_parent.mkdir()
        (replacement_parent / output.name).write_bytes(b'{"replacement":true}\n')
        try:
            with self.assertRaisesRegex(ValueError, "parent binding changed"):
                authority.read_once(1_000)
        finally:
            authority.close()

    def test_parent_environment_excludes_api_keys_and_undeclared_values(self) -> None:
        source = {
            "PATH": "/portable/bin",
            "HOME": "/parent-auth-home",
            "CODEX_HOME": "/parent-codex-home",
            "HTTPS_PROXY": "https://proxy.invalid",
            "OPENAI_API_KEY": "must-not-cross",
            "UNDECLARED_SECRET": "must-not-cross",
        }
        sanitized = build_reviewer_environment(source)
        self.assertEqual(
            {"PATH", "HOME", "CODEX_HOME", "HTTPS_PROXY"}, set(sanitized)
        )
        self.assertNotIn("OPENAI_API_KEY", sanitized)
        self.assertNotIn("UNDECLARED_SECRET", sanitized)

    def test_reviewer_streams_are_retained_without_machine_runtime_values(self) -> None:
        fake = self.fake_codex(
            """import json, os, sys
from pathlib import Path
args = sys.argv[1:]
inputs = json.loads(sys.stdin.read().split('PERMITTED_INPUTS ', 1)[1])
output = Path(args[args.index('--output-last-message') + 1])
payload = {
  'schema_version': '3.0.0', 'repository_id': inputs['repository_id'],
  'candidate_id': inputs['candidate_id'],
  'task_contract_sha256': inputs['task_contract_sha256'],
  'effective_policy_sha256': inputs['effective_policy_sha256'],
  'gate_manifest_sha256': inputs['gate_manifest_sha256'],
  'context_receipt_sha256': inputs['context_receipt_sha256'],
  'reviewer_prompt_sha256': inputs['reviewer_prompt_sha256'],
  'qualification_id': inputs['reviewer_qualification_id'],
  'model': 'fake-gpt', 'invocation_id': 'fake:portable-stream',
  'verdict': 'NO_BLOCKING_FINDING_OBSERVED',
  'reviewed_surfaces': ['candidate'], 'affected_closure': ['candidate'],
  'retrieval_expansions': [], 'findings': [], 'missing_evidence': [],
  'claims': MANDATORY_CLAIMS, 'limitations': []
}
output.write_text(json.dumps(payload), encoding='utf-8')
print(json.dumps({'type': 'thread.started', 'thread_id': 'portable-stream'}))
print(json.dumps({'type': 'item.completed', 'text': os.environ['HOME'] + ' ' + str(output)}))
print(json.dumps({'type': 'turn.completed', 'usage': {
  'input_tokens': 1, 'cached_input_tokens': 0,
  'output_tokens': 1, 'reasoning_output_tokens': 0
}}))
print(os.environ['CODEX_HOME'] + ' ' + str(output), file=sys.stderr)
"""
        )
        environment = dict(os.environ)
        environment["HOME"] = "/machine/private/home"
        environment["CODEX_HOME"] = "/machine/private/codex"
        result = launch_reviewer(
            command=self.command(fake),
            stdin_text=self.stdin(),
            schema_path=self.harness["schema"],
            output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            expected_bindings={"repository_id": self.inputs["repository_id"]},
            timeout_seconds=2,
            environment=environment,
        )
        self.assertTrue(result["execution_valid"])
        for stream in (result["stdout_bytes"], result["stderr_bytes"]):
            self.assertNotIn(b"/machine/private", stream)
            self.assertNotIn(os.fsencode(self.harness["root"]), stream)
            self.assertIn(b"<REVIEWER_RUNTIME>", stream)
        self.assertEqual(sha256_bytes(result["stdout_bytes"]), result["stdout_sha256"])
        self.assertEqual(sha256_bytes(result["stderr_bytes"]), result["stderr_sha256"])

    def test_ambiguous_reviewer_stream_values_are_redacted_and_unknown(self) -> None:
        token = "gh" + "p_" + "Z" * 32
        host_path = "/" + "var" + "/lib/private-runner/state"
        endpoint = "192" + ".168.50.7:8443"
        named_endpoint = "https://runner.internal.invalid/review/status"
        fake = self.fake_codex(
            """
import json, pathlib, sys
args = sys.argv[1:]
output = pathlib.Path(args[args.index('--output-last-message') + 1])
candidate = %r
payload = {
  'schema_version': '3.0.0', 'repository_id': 'repo:example/project',
  'candidate_id': candidate, 'task_contract_sha256': %r,
  'effective_policy_sha256': %r, 'gate_manifest_sha256': %r,
  'context_receipt_sha256': %r, 'reviewer_prompt_sha256': %r,
  'qualification_id': %r, 'model': 'fake-gpt',
  'invocation_id': 'fake:redaction', 'verdict': 'NO_BLOCKING_FINDING_OBSERVED',
  'reviewed_surfaces': ['candidate'], 'affected_closure': ['candidate'],
  'retrieval_expansions': [], 'findings': [], 'missing_evidence': [],
  'claims': MANDATORY_CLAIMS, 'limitations': []
}
output.write_text(json.dumps(payload), encoding='utf-8')
print(json.dumps({'type': 'thread.started', 'thread_id': 'redaction'}))
print(json.dumps({'type': 'item.completed', 'item': {'type': 'agent_message', 'text': json.dumps(payload)}}))
print(json.dumps({'type': 'turn.completed', 'usage': {'input_tokens': 1, 'cached_input_tokens': 0, 'output_tokens': 1, 'reasoning_output_tokens': 0}}))
print(%r + ' ' + %r + ' ' + %r + ' ' + %r, file=sys.stderr)
"""
            % (
                self.CANDIDATE, self.TASK, self.POLICY, self.GATES,
                self.inputs["context_receipt_sha256"], self.PROMPT,
                self.inputs["reviewer_qualification_id"], token, host_path,
                endpoint, named_endpoint,
            )
        )
        result = launch_reviewer(
            command=self.command(fake), stdin_text=self.stdin(),
            schema_path=self.harness["schema"], output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            expected_bindings={"repository_id": self.inputs["repository_id"]},
            timeout_seconds=2,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, result["verdict"])
        self.assertFalse(result["execution_valid"])
        self.assertTrue(result["capture_threads_completed"])
        self.assertFalse(result["observation_complete"])
        self.assertNotIn(
            "reviewer capture threads did not complete", result["limitations"]
        )
        self.assertTrue(result["observation"]["stderr"]["ambiguous_redaction"])
        for original in (token, host_path, endpoint, named_endpoint):
            self.assertNotIn(original.encode(), result["stderr_bytes"])
            self.assertFalse(reviewer_stream_is_portable(original.encode()))
        self.assertIn(b"<REVIEWER_REDACTED>", result["stderr_bytes"])

    @unittest.skipUnless(
        sys.platform.startswith("linux")
        and platform.machine().lower() in {"aarch64", "x86_64"},
        "supported Linux seccomp contract",
    )
    def test_signal_guard_denies_asynchronous_ioctl_operations(self) -> None:
        marker = self.harness["root"] / "ioctl-signal-results"
        handshake_read, handshake_write = os.pipe()
        os.set_inheritable(handshake_write, True)
        machine = platform.machine().lower()
        syscall_number = reviewer_signal_guard.IOCTL_SYSCALLS[machine]
        requests = reviewer_signal_guard.DENIED_IOCTL_REQUESTS
        self.assertEqual((0x5452, 0x8901, 0x8902), requests)
        probe = f"""import ctypes, os
from pathlib import Path
libc = ctypes.CDLL(None, use_errno=True)
read_fd, write_fd = os.pipe()
available = ctypes.c_int()
results = []
ctypes.set_errno(0)
safe = libc.syscall({syscall_number}, read_fd, 0x541B, ctypes.byref(available))
results.append(f'safe:{{safe}}:{{ctypes.get_errno()}}')
for request in {requests!r}:
    ctypes.set_errno(0)
    result = libc.syscall({syscall_number}, read_fd, request, 0)
    results.append(f'{{request}}:{{result}}:{{ctypes.get_errno()}}')
os.close(read_fd)
os.close(write_fd)
Path({str(marker)!r}).write_text('\\n'.join(results))
"""
        process = subprocess.Popen(
            [
                sys.executable,
                os.fspath(Path(reviewer_signal_guard.__file__)),
                str(handshake_write),
                "--",
                sys.executable,
                "-c",
                probe,
            ],
            close_fds=True,
            pass_fds=(handshake_write,),
        )
        os.close(handshake_write)
        try:
            handshake = json.loads(os.read(handshake_read, 4096).decode("ascii"))
        finally:
            os.close(handshake_read)
        self.assertEqual(0, process.wait(timeout=5))
        self.assertTrue(handshake["process_signals_blocked"])
        self.assertEqual(
            [
                "safe:0:0",
                *[f"{request}:-1:{errno.EPERM}" for request in requests],
            ],
            marker.read_text(encoding="utf-8").splitlines(),
        )

    def test_command_event_payload_is_omitted_and_preserves_jsonl(self) -> None:
        source_literal = "/" + "var" + "/lib/public-example"
        credential_literal = "gh" + "p_" + "Q" * 32
        fake = self.fake_codex(
            """
import json, pathlib, sys
args = sys.argv[1:]
output = pathlib.Path(args[args.index('--output-last-message') + 1])
candidate = %r
payload = {
  'schema_version': '3.0.0', 'repository_id': 'repo:example/project',
  'candidate_id': candidate, 'task_contract_sha256': %r,
  'effective_policy_sha256': %r, 'gate_manifest_sha256': %r,
  'context_receipt_sha256': %r, 'reviewer_prompt_sha256': %r,
  'qualification_id': %r, 'model': 'fake-gpt',
  'invocation_id': 'fake:source-literal',
  'verdict': 'NO_BLOCKING_FINDING_OBSERVED',
  'reviewed_surfaces': ['candidate'], 'affected_closure': ['candidate'],
  'retrieval_expansions': [], 'findings': [], 'missing_evidence': [],
  'claims': MANDATORY_CLAIMS, 'limitations': []
}
output.write_text(json.dumps(payload), encoding='utf-8')
print(json.dumps({'type': 'thread.started', 'thread_id': 'source-literal'}))
print(json.dumps({'type': 'item.completed', 'item': {
  'type': 'command_execution',
  'command': %r,
  'aggregated_output': %r + chr(34)
}}))
print(json.dumps({'type': 'item.completed', 'item': {
  'type': 'agent_message', 'text': json.dumps(payload)
}}))
print(json.dumps({'type': 'turn.completed', 'usage': {
  'input_tokens': 1, 'cached_input_tokens': 0,
  'output_tokens': 1, 'reasoning_output_tokens': 0
}}))
"""
            % (
                self.CANDIDATE, self.TASK, self.POLICY, self.GATES,
                self.inputs["context_receipt_sha256"], self.PROMPT,
                self.inputs["reviewer_qualification_id"], credential_literal,
                source_literal,
            )
        )
        result = launch_reviewer(
            command=self.command(fake), stdin_text=self.stdin(),
            schema_path=self.harness["schema"], output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            expected_bindings={"repository_id": self.inputs["repository_id"]},
            timeout_seconds=2,
        )
        self.assertTrue(result["execution_valid"])
        self.assertEqual(
            ReviewerVerdict.NO_BLOCKING_FINDING_OBSERVED, result["verdict"]
        )
        self.assertTrue(result["usage_observed"])
        self.assertFalse(result["observation"]["stdout"]["ambiguous_redaction"])
        self.assertFalse(result["observation"]["stderr"]["ambiguous_redaction"])
        self.assertNotIn(source_literal.encode("utf-8"), result["stdout_bytes"])
        self.assertNotIn(credential_literal.encode("utf-8"), result["stdout_bytes"])
        self.assertIn(b"<REVIEWER_COMMAND_OMITTED>", result["stdout_bytes"])
        self.assertIn(
            b"<REVIEWER_COMMAND_OUTPUT_OMITTED>", result["stdout_bytes"]
        )
        for line in result["stdout_bytes"].splitlines():
            json.loads(line)

        self.harness["output"].unlink()
        fake.write_text(
            fake.read_text(encoding="utf-8").replace(
                "'claims': MANDATORY_CLAIMS, 'limitations': []",
                "'claims': MANDATORY_CLAIMS, 'limitations': [%r]" % source_literal,
            ),
            encoding="utf-8",
        )
        final_output = launch_reviewer(
            command=self.command(fake), stdin_text=self.stdin(),
            schema_path=self.harness["schema"], output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            expected_bindings={"repository_id": self.inputs["repository_id"]},
            timeout_seconds=2,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, final_output["verdict"])
        self.assertTrue(final_output["observation"]["stdout"]["ambiguous_redaction"])
        self.assertNotIn(source_literal.encode("utf-8"), final_output["stdout_bytes"])

    def test_runtime_profile_is_bounded_and_rejects_filesystem_root(self) -> None:
        install = Path(self.temporary.name) / "runtime" / "bin"
        install.mkdir(parents=True)
        executable = install / "codex"
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o755)
        roots = resolve_reviewer_runtime_read_roots(
            "codex", environment={"PATH": str(install), "HOME": self.temporary.name}
        )
        self.assertEqual((install.parent,), roots)
        profile = build_reviewer_permission_profile(roots)
        self.assertIn(json.dumps(str(install.parent)) + '="read"', profile)
        self.assertIn('":root"="deny"', profile)
        with self.assertRaisesRegex(ValueError, "unsafe"):
            build_reviewer_permission_profile([Path(Path.cwd().anchor)])

    def test_unavailable_malformed_timeout_and_drift_are_unknown(self) -> None:
        unavailable = launch_reviewer(
            command=self.command(Path(self.temporary.name) / "missing-codex"),
            stdin_text=self.stdin(), schema_path=self.harness["schema"],
            output_path=self.harness["output"], expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE, timeout_seconds=0.1,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, unavailable["verdict"])

        malformed_fake = self.fake_codex(
            "import sys\nfrom pathlib import Path\na=sys.argv[1:]\nPath(a[a.index('--output-last-message')+1]).write_text('{}')\n"
        )
        malformed = launch_reviewer(
            command=self.command(malformed_fake), stdin_text=self.stdin(),
            schema_path=self.harness["schema"], output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE, timeout_seconds=2,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, malformed["verdict"])
        self.harness["output"].unlink()

        slow_fake = self.fake_codex("import time\ntime.sleep(5)\n")
        timeout = launch_reviewer(
            command=self.command(slow_fake), stdin_text=self.stdin(),
            schema_path=self.harness["schema"], output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE, timeout_seconds=0.05,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, timeout["verdict"])
        self.assertTrue(timeout["timed_out"])

    def test_pre_and_post_candidate_observation_share_the_absolute_deadline(self) -> None:
        idle = self.fake_codex("raise SystemExit(0)\n")
        started = time.monotonic()
        pre = launch_reviewer(
            command=self.command(idle),
            stdin_text=self.stdin(),
            schema_path=self.harness["schema"],
            output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: time.sleep(5),
            timeout_seconds=0.2,
        )
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertEqual(ReviewerVerdict.UNKNOWN, pre["verdict"])
        self.assertIn("pre-review", pre["reason"])

        fake = self.fake_codex(
            "import json, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "inputs = json.loads(sys.stdin.read().split('PERMITTED_INPUTS ', 1)[1])\n"
            "payload = {'schema_version': '3.0.0', 'repository_id': inputs['repository_id'], "
            "'candidate_id': inputs['candidate_id'], 'task_contract_sha256': inputs['task_contract_sha256'], "
            "'effective_policy_sha256': inputs['effective_policy_sha256'], "
            "'gate_manifest_sha256': inputs['gate_manifest_sha256'], "
            "'context_receipt_sha256': inputs['context_receipt_sha256'], "
            "'reviewer_prompt_sha256': inputs['reviewer_prompt_sha256'], "
            "'qualification_id': inputs['reviewer_qualification_id'], 'model': 'fake-gpt', "
            "'invocation_id': 'fake:post-deadline', 'verdict': 'NO_BLOCKING_FINDING_OBSERVED', "
            "'reviewed_surfaces': ['candidate'], 'affected_closure': ['candidate'], "
            "'retrieval_expansions': [], 'findings': [], 'missing_evidence': [], "
            "'claims': MANDATORY_CLAIMS, 'limitations': []}\n"
            "Path(args[args.index('--output-last-message') + 1]).write_text(json.dumps(payload))\n"
            "print(json.dumps({'type': 'turn.completed', 'usage': {'input_tokens': 1, "
            "'cached_input_tokens': 0, 'output_tokens': 1, 'reasoning_output_tokens': 0}}))\n"
        )
        observations = 0

        def supplier(_deadline: float) -> str:
            nonlocal observations
            observations += 1
            if observations == 2:
                time.sleep(5)
            return self.CANDIDATE

        started = time.monotonic()
        post = launch_reviewer(
            command=self.command(fake),
            stdin_text=self.stdin(),
            schema_path=self.harness["schema"],
            output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=supplier,
            expected_bindings={"repository_id": self.inputs["repository_id"]},
            timeout_seconds=1.0,
        )
        self.assertLess(time.monotonic() - started, 1.5)
        self.assertEqual(ReviewerVerdict.UNKNOWN, post["verdict"])
        self.assertFalse(post["observation_complete"])
        self.assertFalse(post["execution_valid"])

    def test_final_output_read_receives_the_absolute_deadline(self) -> None:
        output = self.harness["output"]
        deadline = time.monotonic() + 10
        observed = []
        from codex_governance import reviewer as reviewer_module

        real_read = reviewer_module.read_bounded_descriptor

        def bounded_read(descriptor, *, deadline, max_bytes):
            observed.append(deadline)
            return real_read(descriptor, deadline=deadline, max_bytes=max_bytes)

        authority = _ReviewerOutputAuthority(output)
        output.write_bytes(b"{}")
        try:
            with patch.object(
                reviewer_module, "read_bounded_descriptor", side_effect=bounded_read
            ):
                self.assertEqual(
                    b"{}", authority.read_once(100, deadline=deadline)
                )
        finally:
            authority.close()
        self.assertEqual([deadline], observed)
        output.unlink()

        launcher_deadline = time.monotonic() + 5
        launcher_observed: list[float | None] = []
        real_read_once = _ReviewerOutputAuthority.read_once

        def observed_read_once(
            authority: _ReviewerOutputAuthority,
            max_bytes: int,
            *,
            deadline: float | None = None,
        ) -> bytes:
            launcher_observed.append(deadline)
            return real_read_once(authority, max_bytes, deadline=deadline)

        fake = self.fake_codex(
            "import sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "Path(args[args.index('--output-last-message') + 1]).write_text('{}')\n"
        )
        with patch.object(
            _ReviewerOutputAuthority, "read_once", new=observed_read_once
        ):
            launch_reviewer(
                command=self.command(fake),
                stdin_text=self.stdin(),
                schema_path=self.harness["schema"],
                output_path=output,
                expected_candidate_id=self.CANDIDATE,
                candidate_supplier=lambda _deadline: self.CANDIDATE,
                timeout_seconds=5,
                absolute_deadline=launcher_deadline,
            )
        self.assertEqual([launcher_deadline], launcher_observed)

    def test_codex_version_observation_honors_expired_deadline(self) -> None:
        with patch("codex_governance.reviewer.subprocess.run") as run:
            with self.assertRaises(RuntimeError):
                observe_codex_cli_version(
                    "codex", deadline=time.monotonic() - 1
                )
        run.assert_not_called()

    def test_broken_reviewer_stdin_retains_process_handle_for_cleanup(self) -> None:
        closes_stdin = self.fake_codex(
            "import os, time\nos.close(0)\ntime.sleep(30)\n"
        )
        result = launch_reviewer(
            command=self.command(closes_stdin),
            stdin_text="x" * 2_000_000,
            schema_path=self.harness["schema"],
            output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            timeout_seconds=0.5,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, result["verdict"])
        self.assertFalse(result["execution_valid"])
        self.assertFalse(result["observation_complete"])
        self.assertTrue(result["capture_threads_completed"])
        self.assertTrue(result["process_cleanup_complete"])

    def test_unread_full_stdin_is_bounded_by_the_reviewer_deadline(self) -> None:
        retains_stdin = self.fake_codex("import time\ntime.sleep(30)\n")
        started = time.monotonic()
        result = launch_reviewer(
            command=self.command(retains_stdin),
            stdin_text="x" * 2_000_000,
            schema_path=self.harness["schema"],
            output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            timeout_seconds=0.5,
        )
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(ReviewerVerdict.UNKNOWN, result["verdict"])
        self.assertTrue(result["timed_out"])
        self.assertFalse(result["stdin_delivery_complete"])
        self.assertFalse(result["observation_complete"])
        self.assertTrue(result["capture_threads_completed"])
        self.assertTrue(result["process_cleanup_complete"])

    def test_codex_cli_version_observation_is_bounded_and_portable(self) -> None:
        valid = self.fake_codex("print('codex-cli 1.2.3')\n")
        self.assertEqual("codex-cli 1.2.3", observe_codex_cli_version(str(valid)))
        invalid = self.fake_codex("print('/machine/private/codex')\n")
        with self.assertRaisesRegex(RuntimeError, "version is unavailable"):
            observe_codex_cli_version(str(invalid))

    def test_missing_jsonl_usage_is_explicitly_unobserved(self) -> None:
        fake = self.fake_codex(
            "import json, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "inputs = json.loads(sys.stdin.read().split('PERMITTED_INPUTS ', 1)[1])\n"
            "payload = {'schema_version': '3.0.0', 'repository_id': inputs['repository_id'], "
            "'candidate_id': inputs['candidate_id'], 'task_contract_sha256': inputs['task_contract_sha256'], "
            "'effective_policy_sha256': inputs['effective_policy_sha256'], "
            "'gate_manifest_sha256': inputs['gate_manifest_sha256'], "
            "'context_receipt_sha256': inputs['context_receipt_sha256'], "
            "'reviewer_prompt_sha256': inputs['reviewer_prompt_sha256'], "
            "'qualification_id': inputs['reviewer_qualification_id'], 'model': 'fake-gpt', "
            "'invocation_id': 'fake:no-usage', 'verdict': 'NO_BLOCKING_FINDING_OBSERVED', "
            "'reviewed_surfaces': ['candidate'], 'affected_closure': ['candidate'], "
            "'retrieval_expansions': [], 'findings': [], 'missing_evidence': [], "
            "'claims': MANDATORY_CLAIMS, 'limitations': []}\n"
            "Path(args[args.index('--output-last-message') + 1]).write_text(json.dumps(payload))\n"
        )
        result = launch_reviewer(
            command=self.command(fake),
            stdin_text=self.stdin(),
            schema_path=self.harness["schema"],
            output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            expected_bindings={"repository_id": self.inputs["repository_id"]},
            timeout_seconds=2,
        )
        self.assertTrue(result["execution_valid"])
        self.assertFalse(result["usage_observed"])
        self.assertIn("usage was unavailable", result["limitations"][0])

    def test_execution_statement_identity_covers_output_context_termination_and_usage(self) -> None:
        facts = {
            "reviewer_prompt_sha256": self.PROMPT,
            "output_sha256": "sha256:" + "1" * 64,
            "candidate_before": self.CANDIDATE,
            "candidate_after": self.CANDIDATE,
            "environment_keys": ["PATH"],
            "argv_sha256": reviewer_argv_sha256(
                model="fake-gpt", reasoning_effort="xhigh"
            ),
            "executed_argv_sha256": "sha256:" + "4" * 64,
            "stdin_sha256": "sha256:" + "c" * 64,
            "thread_id": "fixture-thread",
            "started_at": "2026-08-26T10:00:00Z",
            "ended_at": "2026-08-26T10:01:00Z",
            "latency_ms": 60000,
            "return_code": 0,
            "timed_out": False,
            "observation_complete": True,
            "capture_threads_completed": True,
            "process_cleanup_complete": True,
            "execution_valid": True,
            "output_valid": True,
            "bindings_match": True,
            "output_truncated": False,
            "stdout_sha256": "sha256:" + "2" * 64,
            "stderr_sha256": "sha256:" + "3" * 64,
            "usage_observed": True,
            "input_tokens": 10,
            "cached_input_tokens": 2,
            "output_tokens": 3,
            "reasoning_output_tokens": 1,
            "limitations": [],
            "observation": {
                "parent_exit_observed": True,
                "return_code": 0,
                "timed_out": False,
                "candidate_unchanged": True,
                "stdin": {"complete": True, "bytes_expected": 10, "bytes_written": 10},
                "stdout": {"bytes_observed": 20, "bytes_captured": 20, "bytes_normalized": 20, "thread_completed": True, "eof": True, "read_failed": False, "truncated": False, "ambiguous_redaction": False},
                "stderr": {"bytes_observed": 0, "bytes_captured": 0, "bytes_normalized": 0, "thread_completed": True, "eof": True, "read_failed": False, "truncated": False, "ambiguous_redaction": False},
                "supervisor": {"boundary_available": True, "boundary_kind": "pid_namespace", "descendants_observed": False, "cleanup_complete": True, "executed_argv_sha256": "sha256:" + "4" * 64},
                "process_cleanup_complete": True,
                "output": {"present": True, "regular": True, "bytes": 30, "schema_valid": True, "candidate_matches": True, "bindings_match": True, "truncated": False},
            },
        }

        def statement(execution=facts, context="sha256:" + "4" * 64):
            return build_reviewer_execution_statement(
                repository_id="repo:example/project",
                task_contract_sha256=self.TASK,
                effective_policy_sha256=self.POLICY,
                candidate_id=self.CANDIDATE,
                review_mode="conformance",
                output_schema_sha256="sha256:" + "5" * 64,
                launcher_sha256="sha256:" + "6" * 64,
                qualification_id="sha256:" + "7" * 64,
                model="fake-gpt",
                reasoning_effort="xhigh",
                context_source_bundle_sha256="sha256:" + "9" * 64,
                context_projection_sha256="sha256:" + "1" * 64,
                context_qualification_id="sha256:" + "2" * 64,
                input_context_receipt_sha256="sha256:" + "8" * 64,
                context_execution_receipt_sha256=context,
                workflow_system="unit",
                run_id="fixture",
                attempt=1,
                timeout_seconds=60,
                max_output_bytes=1000,
                codex_cli_version="codex-cli 0.149.1",
                stdout_reference={"path": "evidence/stdout.bin", "sha256": execution["stdout_sha256"]},
                stderr_reference={"path": "evidence/stderr.bin", "sha256": execution["stderr_sha256"]},
                execution=execution,
                permitted_inputs_sha256="sha256:" + "d" * 64,
            )

        baseline = statement()["execution_id"]
        missing_exact = json.loads(json.dumps(facts))
        missing_exact.pop("executed_argv_sha256")
        with self.assertRaisesRegex(ValueError, "executed_argv_sha256"):
            statement(missing_exact)
        mismatched_exact = json.loads(json.dumps(facts))
        mismatched_exact["observation"]["supervisor"][
            "executed_argv_sha256"
        ] = "sha256:" + "5" * 64
        with self.assertRaisesRegex(ValueError, "does not reconstruct"):
            statement(mismatched_exact)
        for field, value in (
            ("output_sha256", "sha256:" + "9" * 64),
            ("usage_observed", False),
            ("input_tokens", 11),
        ):
            changed = dict(facts, **{field: value})
            with self.subTest(field=field):
                self.assertNotEqual(baseline, statement(changed)["execution_id"])
        changed_observation = json.loads(json.dumps(facts))
        changed_observation["observation"]["return_code"] = 7
        self.assertNotEqual(
            baseline, statement(changed_observation)["execution_id"]
        )
        self.assertNotEqual(baseline, statement(context="sha256:" + "a" * 64)["execution_id"])

    def test_escaping_candidate_symlink_is_rejected_before_review(self) -> None:
        outside = Path(self.temporary.name) / "outside.txt"
        outside.write_text("host data\n", encoding="utf-8")
        escape = self.repository / "escape-link"
        escape.symlink_to(outside)
        expected_candidate = self.current_candidate()
        inputs = dict(
            self.inputs, candidate_id=expected_candidate["candidate_id"]
        )
        with self.assertRaisesRegex(ValueError, "escaping symlink"):
            prepare_sanitized_harness(
                candidate_repository=self.repository,
                harness_root=Path(self.temporary.name) / "escaping-harness",
                fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                output_schema_path=Path("schemas/reviewer-result.schema.json"),
                permitted_inputs=inputs,
                expected_candidate=expected_candidate,
                evidence_root="evidence",
            )

    def test_conflicting_transitive_evidence_reference_is_rejected(self) -> None:
        raw = (self.repository / "evidence/raw-log.bin").read_bytes()
        gates = json.dumps(
            {
                "artifacts": [
                    {"path": "evidence/raw-log.bin", "sha256": sha256_bytes(raw)},
                    {"path": "evidence/raw-log.bin", "sha256": "sha256:" + "0" * 64},
                ]
            },
            sort_keys=True,
        ).encode("utf-8")
        (self.repository / "evidence/gates.json").write_bytes(gates)
        inputs = dict(self.inputs, gate_manifest_sha256=sha256_bytes(gates))
        with self.assertRaisesRegex(ValueError, "conflicting reviewer evidence"):
            prepare_sanitized_harness(
                candidate_repository=self.repository,
                harness_root=Path(self.temporary.name) / "conflicting-harness",
                fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                output_schema_path=Path("schemas/reviewer-result.schema.json"),
                permitted_inputs=inputs,
                expected_candidate=self.candidate,
                evidence_root="evidence",
            )

    def test_transitive_evidence_symlink_is_rejected(self) -> None:
        outside = Path(self.temporary.name) / "outside-evidence.json"
        outside.write_bytes(b"host-local evidence\n")
        link = self.repository / "evidence/linked-evidence.json"
        link.symlink_to(outside)
        projection = json.dumps(
            {
                "evidence_index": [
                    {
                        "path": "evidence/linked-evidence.json",
                        "sha256": sha256_bytes(outside.read_bytes()),
                    }
                ]
            },
            sort_keys=True,
        ).encode("utf-8")
        (self.repository / "evidence/context-projection.json").write_bytes(projection)
        inputs = dict(
            self.inputs,
            context_projection_sha256=sha256_bytes(projection),
        )
        with self.assertRaisesRegex(ValueError, "symlink"):
            prepare_sanitized_harness(
                candidate_repository=self.repository,
                harness_root=Path(self.temporary.name) / "evidence-symlink-harness",
                fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                output_schema_path=Path("schemas/reviewer-result.schema.json"),
                permitted_inputs=inputs,
                expected_candidate=self.candidate,
                evidence_root="evidence",
            )

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO contract is unavailable")
    def test_reviewer_materialization_rejects_fifo_without_blocking(self) -> None:
        mutation = self.repository / "evidence/mutation.json"
        mutation.unlink()
        os.mkfifo(mutation)
        projection = json.dumps(
            {
                "evidence_index": [
                    {
                        "reference": "evidence/mutation.json",
                        "sha256": "sha256:" + "1" * 64,
                    }
                ]
            },
            sort_keys=True,
        ).encode("utf-8")
        (self.repository / "evidence/context-projection.json").write_bytes(projection)
        inputs = dict(
            self.inputs,
            context_projection_sha256=sha256_bytes(projection),
        )
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, "regular file"):
            prepare_sanitized_harness(
                candidate_repository=self.repository,
                harness_root=Path(self.temporary.name) / "fifo-harness",
                fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                output_schema_path=Path("schemas/reviewer-result.schema.json"),
                permitted_inputs=inputs,
                expected_candidate=self.candidate,
                evidence_root="evidence",
            )
        self.assertLess(time.monotonic() - started, 1.0)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO contract is unavailable")
    def test_validated_direct_bytes_are_materialized_without_path_reopen(self) -> None:
        prepared = {
            value: (self.repository / value).read_bytes()
            for key, value in self.inputs.items()
            if key.endswith("_path") and key != "candidate_path"
        }
        task_path = self.repository / self.inputs["task_contract_path"]
        original = prepared[self.inputs["task_contract_path"]]
        task_path.unlink()
        os.mkfifo(task_path)
        harness = prepare_sanitized_harness(
            candidate_repository=self.repository,
            harness_root=Path(self.temporary.name) / "prepared-bytes-harness",
            fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
            output_schema_path=Path("schemas/reviewer-result.schema.json"),
            permitted_inputs=self.inputs,
            expected_candidate=self.candidate,
            evidence_root="evidence",
            prepared_evidence=prepared,
            fixed_prompt_bytes=Path(
                ".codex/review/reviewer.prompt.md"
            ).read_bytes(),
            output_schema_bytes=Path(
                "schemas/reviewer-result.schema.json"
            ).read_bytes(),
        )
        self.assertEqual(
            original,
            harness["root"].joinpath(*self.inputs["task_contract_path"].split("/")).read_bytes(),
        )

    def test_reviewer_materialization_rejects_oversized_replacement(self) -> None:
        mutation = self.repository / "evidence/mutation.json"
        with mutation.open("wb") as stream:
            stream.truncate(64_000_001)
        projection = json.dumps(
            {
                "evidence_index": [
                    {
                        "reference": "evidence/mutation.json",
                        "sha256": "sha256:" + "1" * 64,
                    }
                ]
            },
            sort_keys=True,
        ).encode("utf-8")
        (self.repository / "evidence/context-projection.json").write_bytes(projection)
        inputs = dict(
            self.inputs,
            context_projection_sha256=sha256_bytes(projection),
        )
        with self.assertRaisesRegex(ValueError, "size bound"):
            prepare_sanitized_harness(
                candidate_repository=self.repository,
                harness_root=Path(self.temporary.name) / "oversize-harness",
                fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                output_schema_path=Path("schemas/reviewer-result.schema.json"),
                permitted_inputs=inputs,
                expected_candidate=self.candidate,
                evidence_root="evidence",
            )

    def test_reviewer_materialization_rejects_parent_swap(self) -> None:
        from unittest.mock import patch

        parent = self.repository / "evidence"
        moved = self.repository / "original-evidence"
        outside = Path(self.temporary.name) / "outside-evidence"
        outside.mkdir()
        (outside / "mutation.json").write_bytes(b"untrusted")
        real_open = os.open
        swapped = False

        def replace_parent(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if not swapped and path == "mutation.json" and dir_fd is not None:
                parent.rename(moved)
                parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with (
            patch(
                "codex_governance.artifacts.secure_repository_reads_available",
                return_value=True,
            ),
            patch(
                "codex_governance.artifacts.os.open", side_effect=replace_parent
            ),
        ):
            with self.assertRaisesRegex(ValueError, "binding changed"):
                prepare_sanitized_harness(
                    candidate_repository=self.repository,
                    harness_root=Path(self.temporary.name) / "swap-harness",
                    fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                    output_schema_path=Path(
                        "schemas/reviewer-result.schema.json"
                    ),
                    permitted_inputs=self.inputs,
                    expected_candidate=self.candidate,
                    evidence_root="evidence",
                )
        self.assertTrue(swapped)

    def test_completed_rapid_session_requires_exact_charter_binding(self) -> None:
        payload = json.loads(
            Path("examples/rapid-review-session.json").read_text(encoding="utf-8")
        )
        payload.update(
            repository_id="repo:example/project",
            candidate_id=self.CANDIDATE,
            task_contract_sha256=self.TASK,
            charter_id="CHARTER-EXACT",
            charter_sha256="sha256:" + "8" * 64,
        )
        fake = self.fake_codex(
            "import json, sys\n"
            "from pathlib import Path\n"
            f"payload = {payload!r}\n"
            "args = sys.argv[1:]\n"
            "Path(args[args.index('--output-last-message') + 1]).write_text(json.dumps(payload))\n"
            "print(json.dumps({'type': 'turn.completed', 'usage': {"
            "'input_tokens': 10, 'cached_input_tokens': 2, 'output_tokens': 3, "
            "'reasoning_output_tokens': 1}}))\n"
        )
        output = Path(self.temporary.name) / "rapid-session.json"
        command = build_reviewer_command(
            codex_executable=str(fake), model="fake-gpt",
            schema_path=Path("schemas/rapid-review-session.schema.json"),
            output_path=output, review_root=Path(self.temporary.name),
        )
        expected = {
            "repository_id": "repo:example/project",
            "candidate_id": self.CANDIDATE,
            "task_contract_sha256": self.TASK,
            "charter_id": "CHARTER-EXACT",
            "charter_sha256": "sha256:" + "8" * 64,
        }
        result = launch_reviewer(
            command=command, stdin_text="rapid review", schema_path=Path(
                "schemas/rapid-review-session.schema.json"
            ), output_path=output, expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            expected_bindings=expected, review_mode="rapid_review", timeout_seconds=2,
        )
        self.assertTrue(result["execution_valid"])
        self.assertEqual("completed", result["review_status"])

        output.unlink()
        expected["charter_sha256"] = "sha256:" + "9" * 64
        mismatched = launch_reviewer(
            command=command, stdin_text="rapid review", schema_path=Path(
                "schemas/rapid-review-session.schema.json"
            ), output_path=output, expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda _deadline: self.CANDIDATE,
            expected_bindings=expected, review_mode="rapid_review", timeout_seconds=2,
        )
        self.assertFalse(mismatched["execution_valid"])
        self.assertFalse(mismatched["bindings_match"])


if __name__ == "__main__":
    unittest.main()
