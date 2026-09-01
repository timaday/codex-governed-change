import json
import os
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import Mock, patch

from codex_governance.candidate import GitCliRepositoryAdapter
from codex_governance.canonical import canonical_json_bytes, sha256_canonical
from codex_governance.domain.model import DispositionState


class CliOrchestrationAcceptanceTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[2]

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(self.ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "codex_governance", *arguments],
            cwd=self.ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def sources(self, candidate: dict | None = None, affected_closure=None) -> dict:
        digest = lambda character: "sha256:" + character * 64
        candidate = candidate or json.loads(
            (self.ROOT / "examples/candidate.json").read_text()
        )
        return {
            "repository_id": candidate["repository_id"],
            "candidate_id": candidate["candidate_id"],
            "created_at": "2026-08-26T10:00:00Z",
            "task_authority": {"summary": "authenticated", "sha256": digest("b")},
            "policy": {"summary": "protected", "sha256": digest("c")},
            "repository_inventory": {"summary": "inventory", "sha256": digest("d")},
            "changed_files": candidate["changed_paths"],
            "affected_closure": affected_closure or ["src/service.py", "tests/test_service.py"],
            "gate_results": [{"id": "unit", "status": "PASS", "sha256": digest("e")}],
            "risks": [], "failures": [], "conflicts": [], "survivors": [],
            "limitations": [], "unknowns": [],
            "rubric": {"summary": "fixed", "sha256": digest("f")},
            "disposition_contract": "all fixed claims are mandatory",
            "artifacts": [],
        }

    def test_scope_and_verify_have_stable_fail_closed_exits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            scoped = self.run_cli(
                "scope", "--repository", str(repository),
                "--task", "examples/task-contract.json",
                "--policy", "examples/effective-policy.json",
            )
            self.assertEqual(0, scoped.returncode, scoped.stderr.decode())
            self.assertEqual("VALID", json.loads(scoped.stdout)["state"])
        with tempfile.TemporaryDirectory() as directory:
            tampered = json.loads((self.ROOT / "examples/context-receipt.json").read_text(encoding="utf-8"))
            tampered["profile"] = "COMPACT"
            path = Path(directory) / "tampered.json"
            path.write_bytes(canonical_json_bytes(tampered))
            invalid_id = self.run_cli(
                "verify", "--artifact", str(path),
                "--schema", "context-receipt", "--identity-field", "receipt_id",
            )
            self.assertEqual(2, invalid_id.returncode)
            self.assertEqual("UNKNOWN", json.loads(invalid_id.stdout)["state"])

    def test_cli_outputs_are_write_once_and_identical_replays_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            output = repository / "artifacts/governance/scope.json"
            arguments = (
                "scope", "--repository", str(repository),
                "--task", "examples/task-contract.json",
                "--policy", "examples/effective-policy.json",
                "--output", "artifacts/governance/scope.json",
            )
            first = self.run_cli(*arguments)
            self.assertEqual(0, first.returncode, first.stderr.decode())
            original = output.read_bytes()
            replay = self.run_cli(*arguments)
            self.assertEqual(0, replay.returncode, replay.stderr.decode())
            self.assertEqual(original, output.read_bytes())

            conflicting_task = json.loads(
                (self.ROOT / "examples/task-contract.json").read_text(
                    encoding="utf-8"
                )
            )
            conflicting_task["required_gate_ids"].reverse()
            conflicting_task_path = root / "conflicting-task.json"
            conflicting_task_path.write_bytes(canonical_json_bytes(conflicting_task))
            conflicting = self.run_cli(
                "scope", "--repository", str(repository),
                "--task", str(conflicting_task_path),
                "--policy", "examples/effective-policy.json",
                "--output", "artifacts/governance/scope.json",
            )
            self.assertEqual(2, conflicting.returncode)
            self.assertEqual("UNKNOWN", json.loads(conflicting.stdout)["state"])
            self.assertEqual(original, output.read_bytes())

            victim = output.parent / "victim.json"
            victim.write_bytes(b"unchanged")
            linked_output = output.parent / "linked.json"
            try:
                linked_output.symlink_to(victim)
            except OSError:
                self.assertFalse(linked_output.exists())
            else:
                linked = self.run_cli(
                    "scope", "--repository", str(repository),
                    "--task", "examples/task-contract.json",
                    "--policy", "examples/effective-policy.json",
                    "--output", linked_output.relative_to(repository).as_posix(),
                )
                self.assertEqual(2, linked.returncode)
                self.assertEqual(b"unchanged", victim.read_bytes())

    def test_cli_outputs_reject_absolute_and_symlink_parent_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            evidence_directory = repository / "artifacts/governance"
            evidence_directory.mkdir(parents=True)
            absolute = root / "absolute.json"
            rejected_absolute = self.run_cli(
                "scope", "--repository", str(repository),
                "--task", "examples/task-contract.json",
                "--policy", "examples/effective-policy.json",
                "--output", str(absolute),
            )
            self.assertEqual(2, rejected_absolute.returncode)
            self.assertFalse(absolute.exists())

            outside_parent = root / "outside-parent"
            outside_parent.mkdir()
            linked_parent = evidence_directory / "linked-parent"
            try:
                linked_parent.symlink_to(outside_parent, target_is_directory=True)
            except OSError:
                self.assertFalse(linked_parent.exists())
            else:
                escaped = linked_parent / "escaped.json"
                rejected_symlink = self.run_cli(
                    "scope", "--repository", str(repository),
                    "--task", "examples/task-contract.json",
                    "--policy", "examples/effective-policy.json",
                    "--output", escaped.relative_to(repository).as_posix(),
                )
                self.assertEqual(2, rejected_symlink.returncode)
                self.assertFalse((outside_parent / "escaped.json").exists())

    def test_every_output_producing_command_is_in_the_containment_inventory(self) -> None:
        from codex_governance import cli

        expected = {
            "scope": ("output",),
            "identify": ("output",),
            "run-gates": ("output",),
            "prepare-review": ("projection_output", "receipt_output"),
            "assemble-manifest": ("output",),
            "mutate": ("output",),
            "review": ("output", "execution_output", "context_execution_output"),
            "import-reviewer-result": ("destination",),
            "evaluate": ("output",),
        }
        self.assertEqual(expected, cli.CLI_OUTPUT_ARGUMENTS)
        commands = next(
            action for action in cli._parser()._actions
            if action.dest == "command"
        ).choices
        discovered = {
            command: tuple(
                action.dest for action in subparser._actions
                if (
                    action.dest == "destination"
                    or action.dest == "output"
                    or action.dest.endswith("_output")
                )
                and action.dest != "output_schema"
            )
            for command, subparser in commands.items()
        }
        self.assertEqual(
            expected,
            {command: paths for command, paths in discovered.items() if paths},
        )

    def test_output_authority_is_rechecked_after_lock_selection(self) -> None:
        from codex_governance import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            policy = json.loads(
                (self.ROOT / "examples/effective-policy.json").read_text(
                    encoding="utf-8"
                )
            )
            policy_path = root / "policy.json"
            policy_path.write_bytes(canonical_json_bytes(policy))

            class AuthorityChangingLock:
                def __init__(self) -> None:
                    self.repository = repository.resolve()
                    self.root = repository / policy["evidence_root"]

                def __enter__(self):
                    changed = dict(policy)
                    changed["evidence_root"] = "different-evidence-root"
                    policy_path.write_bytes(canonical_json_bytes(changed))
                    return self

                def __exit__(self, exc_type, exc_value, traceback) -> None:
                    return None

            emitted = []
            with (
                patch.object(
                    cli, "_pipeline_lock_for", return_value=AuthorityChangingLock()
                ),
                patch.object(cli, "_scope") as handler,
                patch.object(cli, "_emit", side_effect=emitted.append),
            ):
                exit_code = cli.main(
                    [
                        "scope", "--repository", str(repository),
                        "--task", "examples/task-contract.json",
                        "--policy", str(policy_path),
                        "--output", "artifacts/governance/scope.json",
                    ]
                )
            self.assertEqual(2, exit_code)
            handler.assert_not_called()
            self.assertEqual("UNKNOWN", emitted[-1]["state"])
            self.assertFalse((repository / "artifacts/governance/scope.json").exists())

    def test_replaced_evidence_root_blocks_before_cli_handler(self) -> None:
        from codex_governance import cli
        from codex_governance.locking import PipelineLock

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            policy = json.loads(
                (self.ROOT / "examples/effective-policy.json").read_text(
                    encoding="utf-8"
                )
            )
            policy_path = root / "policy.json"
            policy_path.write_bytes(canonical_json_bytes(policy))

            class RootReplacingLock(PipelineLock):
                def __enter__(self):
                    super().__enter__()
                    self.root.rename(self.root.with_name(self.root.name + "-original"))
                    self.root.mkdir()
                    return self

            lock = RootReplacingLock(
                repository=repository,
                evidence_root=policy["evidence_root"],
            )
            emitted = []
            with (
                patch.object(cli, "_pipeline_lock_for", return_value=lock),
                patch.object(cli, "_scope") as handler,
                patch.object(cli, "_emit", side_effect=emitted.append),
            ):
                exit_code = cli.main(
                    [
                        "scope", "--repository", str(repository),
                        "--task", "examples/task-contract.json",
                        "--policy", str(policy_path),
                        "--output", "artifacts/governance/scope.json",
                    ]
                )
            self.assertEqual(2, exit_code)
            handler.assert_not_called()
            self.assertEqual("UNKNOWN", emitted[-1]["state"])
            self.assertFalse((repository / "artifacts/governance/scope.json").exists())

    def test_prepare_review_emits_schema_valid_receipt_and_budget_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "candidate"
            repository.mkdir()
            (repository / "src").mkdir()
            (repository / "tests").mkdir()
            (repository / "src/service.py").write_text("VALUE = 1\n", encoding="utf-8")
            (repository / "src/caller.py").write_text(
                "from src.service import VALUE\n", encoding="utf-8"
            )
            (repository / "tests/test_service.py").write_text(
                "from src.service import VALUE\n", encoding="utf-8"
            )
            environment = dict(os.environ)
            environment.update(
                GIT_AUTHOR_NAME="fixture",
                GIT_AUTHOR_EMAIL="fixture@example.invalid",
                GIT_COMMITTER_NAME="fixture",
                GIT_COMMITTER_EMAIL="fixture@example.invalid",
            )
            for command in (
                ["git", "init", "-q", "-b", "main"],
                ["git", "add", "."],
                ["git", "commit", "-q", "-m", "fixture"],
            ):
                subprocess.run(command, cwd=repository, env=environment, check=True)
            base = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repository, env=environment,
                check=True, stdout=subprocess.PIPE,
            ).stdout.decode("ascii").strip()
            (repository / "src/service.py").write_text("VALUE = 2\n", encoding="utf-8")

            policy = json.loads(
                (self.ROOT / "examples/effective-policy.json").read_text(encoding="utf-8")
            )
            policy["repository_id"] = "repo:example/context-fixture"
            policy["lkg_governance_commit"] = base
            policy_path = root / "policy.json"
            policy_path.write_bytes(canonical_json_bytes(policy))
            candidate = GitCliRepositoryAdapter(repository).identify(
                repository_id=policy["repository_id"],
                mode="working_tree",
                base_commit=base,
                head_commit=base,
                effective_policy_sha256=sha256_canonical(policy),
                evidence_root=policy["evidence_root"],
            )
            candidate_path = root / "candidate.json"
            candidate_path.write_bytes(canonical_json_bytes(candidate))
            closure = GitCliRepositoryAdapter(repository).conservative_affected_closure(
                candidate=candidate, evidence_root=policy["evidence_root"]
            )
            sources = root / "sources.json"
            sources.write_bytes(
                canonical_json_bytes(self.sources(candidate, closure))
            )
            projection = repository / "artifacts/governance/projection.json"
            receipt = repository / "artifacts/governance/receipt.json"
            prepared = self.run_cli(
                "prepare-review", "--repository", str(repository),
                "--policy", str(policy_path),
                "--sources", str(sources),
                "--candidate", str(candidate_path), "--profile", "STANDARD",
                "--token-budget", "24000",
                "--model", "gpt-5.6-sol", "--reasoning-effort", "xhigh",
                "--projection-output", "artifacts/governance/projection.json",
                "--receipt-output", "artifacts/governance/receipt.json",
            )
            self.assertEqual(0, prepared.returncode, prepared.stderr.decode())
            verified = self.run_cli(
                "verify", "--artifact", str(receipt), "--schema", "context-receipt",
                "--identity-field", "receipt_id",
            )
            self.assertEqual(0, verified.returncode, verified.stderr.decode())
            blocked = self.run_cli(
                "prepare-review", "--repository", str(repository),
                "--policy", str(policy_path), "--sources", str(sources),
                "--candidate", str(candidate_path), "--profile", "COMPACT",
                "--token-budget", "1",
                "--model", "gpt-5.6-sol", "--reasoning-effort", "xhigh",
                "--projection-output", "artifacts/governance/small-projection.json",
                "--receipt-output", "artifacts/governance/small-receipt.json",
            )
            self.assertEqual(2, blocked.returncode)
            self.assertEqual("UNKNOWN", json.loads(blocked.stdout)["state"])

            tampered_sources = self.sources(candidate, ["src/service.py"])
            tampered_path = root / "tampered-sources.json"
            tampered_path.write_bytes(canonical_json_bytes(tampered_sources))
            mismatch = self.run_cli(
                "prepare-review", "--repository", str(repository),
                "--policy", str(policy_path), "--sources", str(tampered_path),
                "--candidate", str(candidate_path), "--profile", "STANDARD",
                "--token-budget", "24000", "--model", "gpt-5.6-sol",
                "--reasoning-effort", "xhigh",
                "--projection-output", "artifacts/governance/tampered-projection.json",
                "--receipt-output", "artifacts/governance/tampered-receipt.json",
            )
            self.assertEqual(2, mismatch.returncode)
            self.assertEqual("UNKNOWN", json.loads(mismatch.stdout)["state"])

    def test_illustrative_disposition_never_reports_ready(self) -> None:
        status = self.run_cli("status", "--disposition", "examples/disposition.json")
        self.assertEqual(2, status.returncode)
        self.assertEqual("UNKNOWN", json.loads(status.stdout)["state"])

    def test_evaluate_accepts_nonempty_verified_decision_ids(self) -> None:
        from codex_governance import cli

        manifest = json.loads(
            (self.ROOT / "examples/evidence-manifest.json").read_text(
                encoding="utf-8"
            )
        )
        candidate = json.loads(
            (self.ROOT / "examples/candidate.json").read_text(encoding="utf-8")
        )
        policy = json.loads(
            (self.ROOT / "examples/effective-policy.json").read_text(
                encoding="utf-8"
            )
        )
        decision_id = "sha256:" + "9" * 64
        adapter = Mock()
        adapter.identify.return_value = candidate
        args = Namespace(
            manifest=Path("manifest.json"),
            candidate=Path("candidate.json"),
            schema_root=self.ROOT / "schemas",
            repository=self.ROOT,
            evaluated_at="2026-08-26T12:00:00Z",
            verified_decision_id=[decision_id],
            output="artifacts/governance/disposition.json",
        )
        with (
            patch.object(cli, "_validated", side_effect=[manifest, candidate]),
            patch.object(cli, "load_referenced_json", return_value=policy),
            patch.object(cli, "GitCliRepositoryAdapter", return_value=adapter),
            patch.object(
                cli,
                "evaluate_manifest",
                return_value=(DispositionState.UNKNOWN, ["fixture unknown"]),
            ) as evaluate,
            patch.object(cli, "_write_cli_output"),
            patch.object(cli, "_emit"),
        ):
            self.assertEqual(2, cli._evaluate(args))
        self.assertEqual(
            frozenset({decision_id}),
            evaluate.call_args.kwargs["verified_decision_ids"],
        )

    def test_gate_manifest_time_follows_all_referenced_results(self) -> None:
        from codex_governance.cli import _gate_manifest_created_at

        self.assertEqual(
            "2026-08-26T10:00:03Z",
            _gate_manifest_created_at(
                [
                    {"ended_at": "2026-08-26T10:00:03Z"},
                    {"ended_at": "2026-08-26T10:00:01Z"},
                    {"ended_at": "2026-08-26T10:00:02Z"},
                ]
            ),
        )

    def test_manifest_assembly_is_content_addressed_and_schema_valid(self) -> None:
        example = json.loads(
            (self.ROOT / "examples/evidence-manifest.json").read_text(encoding="utf-8")
        )
        required = {
            key: example[key]
            for key in (
                "repository_id", "candidate_id", "task_contract",
                "effective_policy", "authenticated_decisions", "evidence_locators",
                "sandbox_capabilities", "provenance_statements", "gate_manifest",
                "required_gate_ids", "mutation_corpus", "mutation_baseline",
                "mutant_records", "reviewer_qualification",
                "rapid_review_qualification", "context_receipt",
                "context_execution_receipt", "reviewer_result",
                "reviewer_execution", "rapid_review_executions",
                "rapid_review_context_execution_receipts",
                "risk_register", "oracle_references",
                "coverage_notes", "follow_ups", "assurance_case", "risk_assessment",
                "rapid_review_charters", "rapid_review_sessions",
                "rapid_review_debrief", "risk_disposition", "created_at",
            )
        }
        required["gate_references"] = {
            item["gate_id"]: item["reference"] for item in example["gate_results"]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
            inputs = root / "assembly.json"
            output = repository / "artifacts/governance/manifest.json"
            inputs.write_bytes(canonical_json_bytes(required))
            assembled = self.run_cli(
                "assemble-manifest", "--repository", str(repository),
                "--policy", "examples/effective-policy.json",
                "--input", str(inputs),
                "--output", "artifacts/governance/manifest.json",
            )
            self.assertEqual(0, assembled.returncode, assembled.stderr.decode())
            verified = self.run_cli(
                "verify", "--artifact", str(output), "--schema", "evidence-manifest",
                "--identity-field", "manifest_id",
            )
            self.assertEqual(0, verified.returncode, verified.stderr.decode())


if __name__ == "__main__":
    unittest.main()
