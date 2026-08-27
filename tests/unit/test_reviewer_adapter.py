import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from codex_governance.candidate import GitCliRepositoryAdapter
from codex_governance.canonical import sha256_bytes
from codex_governance.domain.model import ReviewerVerdict
from codex_governance.reviewer import (
    build_reviewer_command,
    build_reviewer_environment,
    build_reviewer_permission_profile,
    build_reviewer_execution_statement,
    build_reviewer_stdin,
    launch_reviewer,
    observe_codex_cli_version,
    prepare_sanitized_harness,
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
            "context-projection.json": projection,
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
            "context_projection_path": "evidence/context-projection.json",
            "context_projection_sha256": sha256_bytes(documents["context-projection.json"]),
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
        executable.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
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
        from unittest.mock import patch

        from codex_governance import reviewer

        original = reviewer._copy_entry
        changed = False

        def race(source: Path, destination: Path) -> None:
            nonlocal changed
            if source == self.repository / "tracked.txt" and not changed:
                source.write_text("raced\n", encoding="utf-8")
                changed = True
            original(source, destination)

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
  'schema_version': '2.0.0', 'repository_id': inputs['repository_id'],
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
  'claims': [], 'limitations': []
}
output.write_text(json.dumps(result), encoding='utf-8')
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
            candidate_supplier=lambda: self.CANDIDATE,
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
            candidate_supplier=lambda: self.CANDIDATE,
            expected_bindings={"task_contract_sha256": "sha256:" + "0" * 64},
            timeout_seconds=2, environment=environment,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, wrong_binding["verdict"])
        self.assertFalse(wrong_binding["bindings_match"])

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
            candidate_supplier=lambda: self.CANDIDATE, timeout_seconds=0.1,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, unavailable["verdict"])

        malformed_fake = self.fake_codex(
            "import sys\nfrom pathlib import Path\na=sys.argv[1:]\nPath(a[a.index('--output-last-message')+1]).write_text('{}')\n"
        )
        malformed = launch_reviewer(
            command=self.command(malformed_fake), stdin_text=self.stdin(),
            schema_path=self.harness["schema"], output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda: self.CANDIDATE, timeout_seconds=2,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, malformed["verdict"])
        self.harness["output"].unlink()

        slow_fake = self.fake_codex("import time\ntime.sleep(5)\n")
        timeout = launch_reviewer(
            command=self.command(slow_fake), stdin_text=self.stdin(),
            schema_path=self.harness["schema"], output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda: self.CANDIDATE, timeout_seconds=0.05,
        )
        self.assertEqual(ReviewerVerdict.UNKNOWN, timeout["verdict"])
        self.assertTrue(timeout["timed_out"])

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
            "payload = {'schema_version': '2.0.0', 'repository_id': inputs['repository_id'], "
            "'candidate_id': inputs['candidate_id'], 'task_contract_sha256': inputs['task_contract_sha256'], "
            "'effective_policy_sha256': inputs['effective_policy_sha256'], "
            "'gate_manifest_sha256': inputs['gate_manifest_sha256'], "
            "'context_receipt_sha256': inputs['context_receipt_sha256'], "
            "'reviewer_prompt_sha256': inputs['reviewer_prompt_sha256'], "
            "'qualification_id': inputs['reviewer_qualification_id'], 'model': 'fake-gpt', "
            "'invocation_id': 'fake:no-usage', 'verdict': 'NO_BLOCKING_FINDING_OBSERVED', "
            "'reviewed_surfaces': ['candidate'], 'affected_closure': ['candidate'], "
            "'retrieval_expansions': [], 'findings': [], 'missing_evidence': [], "
            "'claims': [], 'limitations': []}\n"
            "Path(args[args.index('--output-last-message') + 1]).write_text(json.dumps(payload))\n"
        )
        result = launch_reviewer(
            command=self.command(fake),
            stdin_text=self.stdin(),
            schema_path=self.harness["schema"],
            output_path=self.harness["output"],
            expected_candidate_id=self.CANDIDATE,
            candidate_supplier=lambda: self.CANDIDATE,
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
            "argv_sha256": "sha256:" + "b" * 64,
            "stdin_sha256": "sha256:" + "c" * 64,
            "thread_id": "fixture-thread",
            "started_at": "2026-08-26T10:00:00Z",
            "ended_at": "2026-08-26T10:01:00Z",
            "latency_ms": 60000,
            "return_code": 0,
            "timed_out": False,
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
                input_context_receipt_sha256="sha256:" + "8" * 64,
                context_execution_receipt_sha256=context,
                workflow_system="unit",
                run_id="fixture",
                attempt=1,
                timeout_seconds=60,
                max_output_bytes=1000,
                codex_cli_version="codex-cli 0.149.1",
                execution=execution,
            )

        baseline = statement()["execution_id"]
        for field, value in (
            ("output_sha256", "sha256:" + "9" * 64),
            ("return_code", 7),
            ("usage_observed", False),
            ("input_tokens", 11),
        ):
            changed = dict(facts, **{field: value})
            with self.subTest(field=field):
                self.assertNotEqual(baseline, statement(changed)["execution_id"])
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
        with self.assertRaisesRegex(ValueError, "evidence source contains a symlink"):
            prepare_sanitized_harness(
                candidate_repository=self.repository,
                harness_root=Path(self.temporary.name) / "evidence-symlink-harness",
                fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                output_schema_path=Path("schemas/reviewer-result.schema.json"),
                permitted_inputs=inputs,
                expected_candidate=self.candidate,
                evidence_root="evidence",
            )

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
            candidate_supplier=lambda: self.CANDIDATE,
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
            candidate_supplier=lambda: self.CANDIDATE,
            expected_bindings=expected, review_mode="rapid_review", timeout_seconds=2,
        )
        self.assertFalse(mismatched["execution_valid"])
        self.assertFalse(mismatched["bindings_match"])


if __name__ == "__main__":
    unittest.main()
