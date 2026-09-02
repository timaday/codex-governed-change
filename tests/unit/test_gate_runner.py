import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from codex_governance.artifacts import FilesystemArtifactStore
from codex_governance.evidence import content_address
from codex_governance.gate import (
    _BoundedCapture,
    _close_process_streams,
    _posix_process_group_exited,
    run_gate,
)
from codex_governance.sandbox import SandboxInvocation, sandbox_execution_identity


class GateRunnerTest(unittest.TestCase):
    CANDIDATE = "sha256:" + "a" * 64

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name) / "repository"
        self.repository.mkdir()
        self.sandbox_area = Path(self.temporary.name) / "sandbox-supervisor"
        self.sandbox_area.mkdir()
        self.store = FilesystemArtifactStore(
            repository=self.repository,
            root=Path("evidence"),
            max_bytes=100_000,
        )
        self.number = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def observe(self, code: str, **overrides) -> dict:
        self.number += 1
        capability_verified_at = overrides.pop(
            "capability_verified_at", "2026-08-26T10:00:00Z"
        )
        values = {
            "gate_id": f"gate-{self.number}",
            "profile": "code",
            "command": [sys.executable, "-c", code],
            "cwd": self.repository,
            "repository_id": "repo:example/project",
            "task_contract_sha256": "sha256:" + "b" * 64,
            "effective_policy_sha256": "sha256:" + "c" * 64,
            "provenance_context": {
                "repository_digest": "sha256:" + "d" * 64,
                "gate_definition_sha256": "sha256:" + "e" * 64,
                "reviewer_prompt_sha256": "sha256:" + "f" * 64,
                "producer": {
                    "builder_id": "unit-fixture",
                    "implementation_sha256": "sha256:" + "1" * 64,
                    "version": "test",
                },
                "workflow": {"system": "unit", "run_id": "fixture", "attempt": 1},
                "tools": [{"name": "python", "version": "test"}],
                "materials": [{"name": "candidate", "sha256": self.CANDIDATE}],
            },
            "candidate_supplier": lambda: self.CANDIDATE,
            "artifact_store": self.store,
            "artifact_prefix": f"gates/gate-{self.number}",
            "timeout_seconds": 2,
            "max_output_bytes": 64,
        }
        values.update(overrides)
        if "sandbox_invocation" not in overrides:
            execution_identity = sandbox_execution_identity(
                provider="docker",
                provider_version="test",
                image="python@sha256:" + "a" * 64,
                command=list(values["command"]),
                process_limit=8,
                memory_bytes=1000000,
                cpu_seconds=2,
                timeout_seconds=2,
                output_bytes=64,
            )
            report = content_address(
                {
                    "schema_version": "2.0.0",
                    "provider": "docker",
                    "provider_version": "test",
                    "image": "python@sha256:" + "a" * 64,
                    "command": list(values["command"]),
                    "implementation_sha256": "sha256:" + "1" * 64,
                    "source_identity": self.CANDIDATE,
                    "execution_identity": execution_identity,
                    "disposable": True,
                    "secrets_present": False,
                    "network_mode": "none",
                    "candidate_copy_writable": True,
                    "protected_paths_writable": False,
                    "evidence_paths_writable": False,
                    "supervisor_paths_writable": False,
                    "process_limit": 8,
                    "memory_bytes": 1000000,
                    "cpu_seconds": 2,
                    "timeout_seconds": 2,
                    "output_bytes": 64,
                    "verified_at": capability_verified_at,
                    "limitations": ["unit fixture; not production isolation"],
                },
                "capability_id",
            )
            invocation_command = list(values["command"])
            if values.get("shell"):
                invocation_command = [sys.executable, "-c", code]
            values["sandbox_invocation"] = SandboxInvocation(
                tuple(invocation_command), report, self.sandbox_area, self.sandbox_area
            )
        return run_gate(**values)

    def test_exit_and_binary_stream_observations(self) -> None:
        passed = self.observe("import os; os.write(1, b'out\\xff'); os.write(2, b'err')")
        self.assertEqual("PASS", passed["status"])
        self.assertEqual(0, passed["termination"]["exit_code"])
        failed = self.observe("raise SystemExit(7)")
        self.assertEqual("FAIL", failed["status"])
        self.assertEqual(7, failed["termination"]["exit_code"])

    def test_timeout_truncation_launch_error_and_drift_are_unknown(self) -> None:
        timeout = self.observe("import time; time.sleep(5)", timeout_seconds=0.05)
        self.assertEqual("UNKNOWN", timeout["status"])
        self.assertEqual("timeout", timeout["termination"]["kind"])
        truncated = self.observe("print('x' * 1000)", max_output_bytes=16)
        self.assertEqual("UNKNOWN", truncated["status"])
        self.assertTrue(truncated["artifacts"][0]["truncated"])
        missing = self.observe("pass", command=["definitely-not-a-real-governance-tool"])
        self.assertEqual("UNKNOWN", missing["status"])
        self.assertEqual("launch_error", missing["termination"]["kind"])
        identities = iter([self.CANDIDATE, "sha256:" + "b" * 64])
        drift = self.observe("pass", candidate_supplier=lambda: next(identities))
        self.assertEqual("UNKNOWN", drift["status"])

    def test_container_cleanup_runs_after_timeout_and_unproven_cleanup_blocks(self) -> None:
        command = [sys.executable, "-c", "import time; time.sleep(10)"]
        report = content_address(
            {
                "schema_version": "2.0.0",
                "provider": "docker",
                "provider_version": "fixture",
                "image": "python@sha256:" + "a" * 64,
                "command": command,
                "implementation_sha256": "sha256:" + "1" * 64,
                "source_identity": self.CANDIDATE,
                "execution_identity": sandbox_execution_identity(
                    provider="docker",
                    provider_version="fixture",
                    image="python@sha256:" + "a" * 64,
                    command=command,
                    process_limit=8,
                    memory_bytes=1000000,
                    cpu_seconds=2,
                    timeout_seconds=2,
                    output_bytes=64,
                ),
                "disposable": True,
                "secrets_present": False,
                "network_mode": "none",
                "candidate_copy_writable": True,
                "protected_paths_writable": False,
                "evidence_paths_writable": False,
                "supervisor_paths_writable": False,
                "process_limit": 8,
                "memory_bytes": 1000000,
                "cpu_seconds": 2,
                "timeout_seconds": 2,
                "output_bytes": 64,
                "verified_at": "2026-08-26T10:00:00Z",
                "limitations": ["unit fixture"],
            },
            "capability_id",
        )
        invocation = SandboxInvocation(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            report,
            self.sandbox_area,
            self.sandbox_area,
            "docker",
            "codex-governance-fixture",
            self.sandbox_area / "fixture.cid",
        )
        container_id = "a" * 64
        with (
            patch("codex_governance.gate.create_container", return_value=container_id),
            patch(
                "codex_governance.gate.build_container_start_command",
                return_value=[sys.executable, "-c", "import time; time.sleep(5)"],
            ),
            patch("codex_governance.gate.cleanup_container", return_value=True) as cleanup,
        ):
            timed_out = self.observe(
                "pass",
                sandbox_invocation=invocation,
                timeout_seconds=0.05,
            )
        cleanup.assert_called_once()
        self.assertEqual((invocation, container_id), cleanup.call_args.args)
        self.assertGreaterEqual(cleanup.call_args.kwargs["timeout_seconds"], 0.0)
        self.assertLessEqual(cleanup.call_args.kwargs["timeout_seconds"], 0.05)
        self.assertEqual("timeout", timed_out["termination"]["kind"])
        with (
            patch("codex_governance.gate.create_container", return_value=container_id),
            patch(
                "codex_governance.gate.build_container_start_command",
                return_value=[sys.executable, "-c", "pass"],
            ),
            patch("codex_governance.gate.cleanup_container", return_value=False),
        ):
            incomplete = self.observe("pass", sandbox_invocation=invocation)
        self.assertEqual("UNKNOWN", incomplete["status"])
        self.assertIn(
            "sandbox container cleanup could not be proven",
            incomplete["limitations"],
        )

    def test_missing_sandbox_never_falls_back_to_host_execution(self) -> None:
        marker = self.repository / "must-not-exist"
        result = self.observe(
            f"from pathlib import Path; Path({marker.name!r}).write_text('bad')",
            sandbox_invocation=None,
        )
        self.assertEqual("UNKNOWN", result["status"])
        self.assertFalse(marker.exists())

    def test_future_capability_never_launches_the_gate(self) -> None:
        marker = self.repository / "future-capability-must-not-run"
        result = self.observe(
            f"from pathlib import Path; Path({marker.name!r}).write_text('bad')",
            capability_verified_at="2099-01-01T00:00:00Z",
        )
        self.assertEqual("UNKNOWN", result["status"])
        self.assertEqual("launch_error", result["termination"]["kind"])
        self.assertFalse(marker.exists())

    def test_supervisor_machine_paths_are_redacted_before_storage(self) -> None:
        result = self.observe("import os; print(os.getcwd())")
        output = self.store.read_bytes(result["artifacts"][0]["path"].removeprefix("evidence/"))
        self.assertNotIn(str(self.sandbox_area).encode(), output)
        self.assertIn(b"<SANDBOX_CANDIDATE>", output)
        self.assertTrue(result["redactions"])

    def test_secret_shaped_and_unbound_host_values_never_enter_evidence(self) -> None:
        token = "gh" + "p_" + "A" * 32
        private_home = "/" + "home" + "/private-person/work"
        result = self.observe(
            f"print({token!r}); print({private_home!r})",
            max_output_bytes=1024,
        )
        output = self.store.read_bytes(
            result["artifacts"][0]["path"].removeprefix("evidence/")
        )
        self.assertEqual("UNKNOWN", result["status"])
        self.assertNotIn(token.encode(), output)
        self.assertNotIn(private_home.encode(), output)
        self.assertIn(b"<REDACTED_CREDENTIAL>", output)
        self.assertIn(b"<REDACTED_HOST_PATH>", output)
        self.assertEqual(
            {"credential", "generic_host_path"},
            {
                item["category"]
                for item in result["redactions"]
                if item["category"] in {"credential", "generic_host_path"}
            },
        )
        self.assertTrue(any("ambiguous" in item for item in result["limitations"]))

    def test_complete_host_paths_and_named_endpoints_are_ambiguous(self) -> None:
        values = (
            "/var/lib/runner/cache/result.json",
            "C:" + "\\" + "Users\\runner\\workspace\\result.json",
            "\\" * 2 + "build-host\\workspace\\cache\\result.json",
            "https://runner.internal.invalid/api/status",
        )
        result = self.observe(
            "print(" + repr(" ".join(values)) + ")", max_output_bytes=1024
        )
        output = self.store.read_bytes(
            result["artifacts"][0]["path"].removeprefix("evidence/")
        )
        self.assertEqual("UNKNOWN", result["status"])
        for value in values:
            self.assertNotIn(value.encode(), output)
        self.assertIn(b"<REDACTED_HOST_PATH>", output)
        self.assertIn(b"<REDACTED_ENDPOINT>", output)

    def test_incomplete_preparation_is_retained_unknown_without_launch(self) -> None:
        marker = self.repository / "preparation-must-not-launch"
        result = self.observe(
            f"from pathlib import Path; Path({marker.name!r}).write_text('bad')",
            sandbox_invocation=None,
            preparation_error="CandidatePreparationError",
            absolute_deadline=time.monotonic() - 1,
        )
        self.assertEqual("UNKNOWN", result["status"])
        self.assertEqual(
            "candidate_preparation_incomplete", result["termination"]["detail"]
        )
        self.assertIn("candidate preparation was incomplete", result["limitations"])
        self.assertFalse(marker.exists())

    def test_exact_host_value_redaction_is_reported_without_hiding_exit(self) -> None:
        hostname = "fixture-host-value"
        with patch("codex_governance.gate.socket.gethostname", return_value=hostname):
            result = self.observe(f"print({hostname!r})")
        output = self.store.read_bytes(
            result["artifacts"][0]["path"].removeprefix("evidence/")
        )
        self.assertEqual("UNKNOWN", result["status"])
        self.assertNotIn(hostname.encode(), output)
        self.assertIn(b"<REDACTED_HOST_VALUE>", output)
        self.assertTrue(
            any(item["category"] == "host_value" for item in result["redactions"])
        )
        self.assertTrue(any("ambiguous" in item for item in result["limitations"]))

    def test_short_hostname_is_removed_from_gate_evidence(self) -> None:
        hostname = "xy"
        with patch("codex_governance.gate.socket.gethostname", return_value=hostname):
            result = self.observe(f"print({hostname!r})")
        output = self.store.read_bytes(
            result["artifacts"][0]["path"].removeprefix("evidence/")
        )
        self.assertEqual("UNKNOWN", result["status"])
        self.assertNotIn(hostname.encode(), output)
        self.assertIn(b"<REDACTED_HOST_VALUE>", output)
        self.assertTrue(any("ambiguous" in item for item in result["limitations"]))

    def test_address_shaped_endpoint_is_ambiguous_and_not_retained(self) -> None:
        endpoint = ".".join(("198", "51", "100", "7")) + ":" + str(8443)
        result = self.observe(f"print({endpoint!r})")
        output = self.store.read_bytes(
            result["artifacts"][0]["path"].removeprefix("evidence/")
        )
        self.assertEqual("UNKNOWN", result["status"])
        self.assertNotIn(endpoint.encode(), output)
        self.assertIn(b"<REDACTED_ENDPOINT>", output)
        self.assertTrue(
            any(item["category"] == "endpoint" for item in result["redactions"])
        )

    def test_proxy_environment_value_is_secret_ambiguous(self) -> None:
        proxy = "http://private-user:private-password@proxy.invalid:8080"
        with patch.dict(os.environ, {"HTTPS_PROXY": proxy}):
            result = self.observe(f"print({proxy!r})")
        output = self.store.read_bytes(
            result["artifacts"][0]["path"].removeprefix("evidence/")
        )
        self.assertEqual("UNKNOWN", result["status"])
        self.assertNotIn(proxy.encode(), output)
        self.assertIn(b"<REDACTED_CREDENTIAL>", output)
        self.assertTrue(
            any(item["category"] == "credential" for item in result["redactions"])
        )

    def test_hostname_lookup_failure_does_not_bypass_normalization(self) -> None:
        token = "sk-" + "B" * 32
        with patch("codex_governance.gate.socket.gethostname", side_effect=OSError):
            result = self.observe(f"print({token!r})")
        output = self.store.read_bytes(
            result["artifacts"][0]["path"].removeprefix("evidence/")
        )
        self.assertEqual("UNKNOWN", result["status"])
        self.assertNotIn(token.encode(), output)
        self.assertIn(b"<REDACTED_CREDENTIAL>", output)

    def test_argument_arrays_do_not_expand_shell_fragments(self) -> None:
        marker = self.repository / "should-not-exist"
        fragment = f"; touch {marker.name}"
        result = self.observe(
            "import sys; print(sys.argv[1])",
            command=[sys.executable, "-c", "import sys; print(sys.argv[1])", fragment],
        )
        self.assertEqual("PASS", result["status"])
        self.assertFalse(marker.exists())

    def test_shell_mode_is_explicit_and_risk_labelled(self) -> None:
        with self.assertRaises(ValueError):
            self.observe("pass", shell=True)
        result = self.observe(
            "pass",
            command=[f'"{sys.executable}" -c "pass"'],
            shell=True,
            risk_label="legacy-command-language",
        )
        self.assertEqual("PASS", result["status"])

    @unittest.skipUnless(os.name == "posix", "POSIX process-group contract")
    def test_zombie_only_scan_cannot_establish_initial_group_exit(self) -> None:
        with (
            patch("codex_governance.gate.os.killpg"),
            patch(
                "codex_governance.gate._linux_process_group_is_zombie_only",
                return_value=True,
            ),
        ):
            self.assertFalse(_posix_process_group_exited(12345, 0))
            self.assertTrue(
                _posix_process_group_exited(
                    12345, 0, allow_zombie_only=True
                )
            )

    def test_stream_close_is_time_bounded_while_capture_is_blocked(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdout is not None and process.stderr is not None
        stdout_capture = _BoundedCapture(1024)
        stderr_capture = _BoundedCapture(1024)
        readers = [
            threading.Thread(
                target=stdout_capture.read, args=(process.stdout,), daemon=True
            ),
            threading.Thread(
                target=stderr_capture.read, args=(process.stderr,), daemon=True
            ),
        ]
        for reader in readers:
            reader.start()
        time.sleep(0.02)
        started = time.monotonic()
        try:
            self.assertFalse(_close_process_streams(process, timeout=0.05))
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            process.kill()
            process.wait(timeout=2)
            for reader in readers:
                reader.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
