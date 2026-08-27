import sys
import tempfile
import unittest
from pathlib import Path

from codex_governance.artifacts import FilesystemArtifactStore
from codex_governance.evidence import content_address
from codex_governance.gate import run_gate
from codex_governance.sandbox import SandboxInvocation


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
            report = content_address(
                {
                    "schema_version": "1.0.0",
                    "provider": "unit-fixture",
                    "provider_version": "test",
                    "implementation_sha256": "sha256:" + "1" * 64,
                    "source_identity": self.CANDIDATE,
                    "execution_identity": "sha256:" + "2" * 64,
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

    def test_missing_sandbox_never_falls_back_to_host_execution(self) -> None:
        marker = self.repository / "must-not-exist"
        result = self.observe(
            f"from pathlib import Path; Path({marker.name!r}).write_text('bad')",
            sandbox_invocation=None,
        )
        self.assertEqual("UNKNOWN", result["status"])
        self.assertFalse(marker.exists())

    def test_supervisor_machine_paths_are_redacted_before_storage(self) -> None:
        result = self.observe("import os; print(os.getcwd())")
        output = self.store.read_bytes(result["artifacts"][0]["path"].removeprefix("evidence/"))
        self.assertNotIn(str(self.sandbox_area).encode(), output)
        self.assertIn(b"<SANDBOX_CANDIDATE>", output)
        self.assertTrue(result["redactions"])

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


if __name__ == "__main__":
    unittest.main()
