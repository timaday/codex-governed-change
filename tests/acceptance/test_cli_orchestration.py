import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from codex_governance.candidate import GitCliRepositoryAdapter
from codex_governance.canonical import (
    canonical_json_bytes,
    content_address,
    sha256_bytes,
    sha256_canonical,
)
from codex_governance.evidence import assemble_gate_manifest
from codex_governance.mutation import REQUIRED_CURATED_MUTANTS
from codex_governance.domain.model import DispositionState
from codex_governance.rollback import protected_rollback_command


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

    def test_review_cli_retains_exact_noncanonical_reviewer_bytes(self) -> None:
        from codex_governance.artifacts import FilesystemArtifactStore
        from codex_governance.cli import _retain_reviewer_output

        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            raw = b'{\n  "z": 1,\n  "a": 2\n}\n'
            arguments = Namespace(
                _cli_output_store=FilesystemArtifactStore(
                    repository=repository, root=Path("evidence")
                ),
                _cli_output_paths={"output": "reviewer-result.json"},
            )
            result = {
                "execution_valid": True,
                "result": {"z": 1, "a": 2},
                "output_sha256": sha256_bytes(raw),
            }
            _retain_reviewer_output(arguments, result, raw)
            self.assertEqual(
                raw, (repository / "evidence/reviewer-result.json").read_bytes()
            )

            mismatch = dict(result, output_sha256=sha256_bytes(b"different"))
            mismatch_arguments = Namespace(
                _cli_output_store=arguments._cli_output_store,
                _cli_output_paths={"output": "mismatch.json"},
            )
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                _retain_reviewer_output(mismatch_arguments, mismatch, raw)
            self.assertFalse((repository / "evidence/mismatch.json").exists())

    def test_review_cli_rejects_special_authoritative_input_without_blocking(self) -> None:
        self.assertTrue(hasattr(os, "mkfifo"), "protected reviewer CLI requires POSIX FIFO detection")
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            evidence = repository / "evidence"
            evidence.mkdir(parents=True)
            policy = json.loads(
                (self.ROOT / "examples/effective-policy.json").read_text()
            )
            policy["evidence_root"] = "evidence"
            policy_path = repository / "policy.json"
            policy_path.write_bytes(canonical_json_bytes(policy))
            candidate_path = repository / "candidate.json"
            os.mkfifo(candidate_path)
            started = time.monotonic()
            completed = self.run_cli(
                "review",
                "--repository", str(repository),
                "--authority-root", str(self.ROOT),
                "--policy", str(policy_path),
                "--candidate", str(candidate_path),
                "--permitted-inputs", str(repository / "permitted.json"),
                "--prompt", str(repository / "prompt.md"),
                "--output-schema", str(repository / "review.schema.json"),
                "--output", "evidence/result.json",
                "--execution-output", "evidence/execution.json",
                "--context-execution-output", "evidence/context-execution.json",
                "--stdout-output", "evidence/stdout.bin",
                "--stderr-output", "evidence/stderr.bin",
                "--run-id", "fifo-fixture",
                "--model", "gpt-5.6-sol",
                "--reasoning-effort", "xhigh",
            )
            self.assertEqual(2, completed.returncode, completed.stderr.decode())
            self.assertLess(time.monotonic() - started, 1.0)

    def test_reviewer_candidate_and_protected_authority_roots_are_distinct(self) -> None:
        from codex_governance.cli import (
            _read_authority_argument,
            _read_repository_argument,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "candidate"
            authority = root / "authority"
            candidate.mkdir()
            authority.mkdir()
            (candidate / "evidence.json").write_bytes(b"candidate")
            (authority / "prompt.md").write_bytes(b"authority")
            self.assertEqual(
                b"candidate",
                _read_repository_argument(candidate, Path("evidence.json")),
            )
            self.assertEqual(
                b"authority",
                _read_authority_argument(authority, Path("prompt.md")),
            )
            with self.assertRaisesRegex(ValueError, "authority-relative"):
                _read_authority_argument(authority, candidate / "evidence.json")
            with self.assertRaisesRegex(ValueError, "repository-relative"):
                _read_repository_argument(candidate, authority / "prompt.md")

    def test_admission_schema_root_is_unprefixed_and_authority_relative(self) -> None:
        from codex_governance.cli import _admission_schema_root

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            authority = root / "authority"
            candidate = root / "candidate"
            (authority / "schemas").mkdir(parents=True)
            (candidate / "schemas").mkdir(parents=True)
            args = Namespace(
                authority_root=authority,
                repository=candidate,
                schema_root=Path("schemas"),
            )
            self.assertEqual(authority / "schemas", _admission_schema_root(args))
            args.schema_root = candidate / "schemas"
            with self.assertRaisesRegex(ValueError, "authority-relative"):
                _admission_schema_root(args)
            args.schema_root = Path("authority/schemas")
            with self.assertRaisesRegex(ValueError, "checkout-prefixed"):
                _admission_schema_root(args)

    def test_evaluate_uses_only_distinct_protected_schema_authority(self) -> None:
        from codex_governance import cli

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate_root = root / "candidate"
            authority_root = root / "authority"
            candidate_root.mkdir()
            authority_root.mkdir()
            shutil.copytree(self.ROOT / "schemas", authority_root / "schemas")
            (authority_root / ".codex/review").mkdir(parents=True)
            shutil.copyfile(
                self.ROOT / ".codex/review/reviewer.prompt.md",
                authority_root / ".codex/review/reviewer.prompt.md",
            )

            manifest = json.loads(
                (self.ROOT / "examples/evidence-manifest.json").read_text()
            )
            candidate = json.loads(
                (self.ROOT / "examples/candidate.json").read_text()
            )
            policy = json.loads(
                (self.ROOT / "examples/effective-policy.json").read_text()
            )
            manifest["effective_policy"]["sha256"] = sha256_bytes(
                canonical_json_bytes(policy)
            )
            manifest = content_address(manifest, "manifest_id")
            manifest_path = candidate_root / "manifest.json"
            candidate_path = candidate_root / "candidate.json"
            policy_path = candidate_root / manifest["effective_policy"]["path"]
            policy_path.parent.mkdir(parents=True)
            manifest_path.write_bytes(canonical_json_bytes(manifest))
            candidate_path.write_bytes(canonical_json_bytes(candidate))
            policy_path.write_bytes(canonical_json_bytes(policy))

            malicious = candidate_root / "schemas"
            malicious.mkdir()
            (malicious / "evidence-manifest.schema.json").write_text(
                '{"not":{}}\n', encoding="utf-8"
            )
            adapter = Mock()
            adapter.identify.return_value = candidate
            emitted: list[dict] = []
            original_cwd = Path.cwd()
            try:
                os.chdir(candidate_root)
                with (
                    patch.object(
                        cli, "GitCliRepositoryAdapter", return_value=adapter
                    ),
                    patch.object(
                        cli,
                        "evaluate_manifest",
                        return_value=(
                            DispositionState.UNKNOWN,
                            ["fixture unknown"],
                        ),
                    ) as evaluate,
                    patch.object(cli, "_emit", side_effect=emitted.append),
                ):
                    result = cli.main(
                        [
                            "--schema-root", "schemas", "evaluate",
                            "--repository", str(candidate_root),
                            "--authority-root", str(authority_root),
                            "--manifest", str(manifest_path),
                            "--candidate", str(candidate_path),
                            "--prompt", ".codex/review/reviewer.prompt.md",
                            "--evaluated-at", "2026-08-26T12:00:00Z",
                            "--output", "artifacts/governance/disposition.json",
                        ]
                    )
            finally:
                os.chdir(original_cwd)
            self.assertEqual(2, result)
            self.assertEqual("UNKNOWN", emitted[-1]["state"])
            self.assertIsNotNone(evaluate.call_args, emitted)
            self.assertEqual(
                authority_root / "schemas",
                evaluate.call_args.kwargs["schema_root"],
            )
            self.assertTrue(
                (candidate_root / "artifacts/governance/disposition.json").is_file()
            )

    def test_every_output_producing_command_is_in_the_containment_inventory(self) -> None:
        from codex_governance import cli

        expected = {
            "scope": ("output",),
            "identify": ("output",),
            "run-gates": ("output",),
            "prepare-review": (
                "sources_output", "projection_output", "receipt_output"
            ),
            "assemble-manifest": ("output",),
            "mutate": ("output",),
            "review": (
                "output",
                "execution_output",
                "context_execution_output",
                "stdout_output",
                "stderr_output",
            ),
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
            qualification = json.loads(
                (self.ROOT / "examples/context-qualification.json").read_text(
                    encoding="utf-8"
                )
            )
            qualification["profile"] = "DEEP"
            qualification = content_address(qualification, "qualification_id")
            policy["context"]["qualification_ids"]["DEEP"] = qualification[
                "qualification_id"
            ]
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
            task = json.loads(
                (self.ROOT / "examples/task-contract.json").read_text(
                    encoding="utf-8"
                )
            )
            task.update(
                repository_id=policy["repository_id"],
                base_commit=base,
                profile="mixed",
                required_gate_ids=["blueprint-quality"],
                unknowns=[],
            )
            task_path = root / "task.json"
            task_path.write_bytes(canonical_json_bytes(task))
            task_sha = sha256_bytes(canonical_json_bytes(task))
            qualification_path = root / "context-qualification.json"
            qualification_path.write_bytes(canonical_json_bytes(qualification))

            evidence = repository / "artifacts/governance"
            evidence.mkdir(parents=True)
            gate_result = json.loads(
                (self.ROOT / "examples/gate-result.json").read_text(
                    encoding="utf-8"
                )
            )
            gate_result.update(
                repository_id=policy["repository_id"],
                task_contract_sha256=task_sha,
                profile=task["profile"],
                candidate_before=candidate["candidate_id"],
                candidate_after=candidate["candidate_id"],
                source_identity=candidate["candidate_id"],
            )
            gate_stdout = b"BLUEPRINT_QUALITY=PASS\n"
            gate_stderr = b""
            gate_provenance = canonical_json_bytes({"fixture": "provenance"})
            (evidence / "gate-stdout.bin").write_bytes(gate_stdout)
            (evidence / "gate-stderr.bin").write_bytes(gate_stderr)
            (evidence / "gate-provenance.json").write_bytes(gate_provenance)
            gate_result["artifacts"] = [
                {
                    "stream": "stdout",
                    "path": "artifacts/governance/gate-stdout.bin",
                    "bytes": len(gate_stdout),
                    "sha256": sha256_bytes(gate_stdout),
                    "truncated": False,
                },
                {
                    "stream": "stderr",
                    "path": "artifacts/governance/gate-stderr.bin",
                    "bytes": len(gate_stderr),
                    "sha256": sha256_bytes(gate_stderr),
                    "truncated": False,
                },
            ]
            gate_result["provenance_statement"] = {
                "path": "artifacts/governance/gate-provenance.json",
                "sha256": sha256_bytes(gate_provenance),
            }
            gate_result_path = evidence / "gate-result.json"
            gate_result_bytes = canonical_json_bytes(gate_result)
            gate_result_path.write_bytes(gate_result_bytes)
            gate_result_ref = {
                "path": "artifacts/governance/gate-result.json",
                "sha256": sha256_bytes(gate_result_bytes),
            }
            gate_manifest = assemble_gate_manifest(
                repository_id=policy["repository_id"],
                task_contract_sha256=task_sha,
                candidate_id=candidate["candidate_id"],
                required_gate_ids=["blueprint-quality"],
                gate_references={"blueprint-quality": gate_result_ref},
                created_at=gate_result["ended_at"],
            )
            gate_manifest_path = evidence / "gate-manifest.json"
            gate_manifest_bytes = canonical_json_bytes(gate_manifest)
            gate_manifest_path.write_bytes(gate_manifest_bytes)
            gate_summary = root / "gate-summary.json"
            gate_summary.write_bytes(
                canonical_json_bytes(
                    {
                        "repository_id": policy["repository_id"],
                        "candidate_id": candidate["candidate_id"],
                        "gate_manifest": {
                            "path": "artifacts/governance/gate-manifest.json",
                            "sha256": sha256_bytes(gate_manifest_bytes),
                        },
                        "results": [
                            {"gate_id": "blueprint-quality", "status": "PASS"}
                        ],
                    }
                )
            )
            mutant_template = json.loads(
                (self.ROOT / "examples/mutant-record.json").read_text(
                    encoding="utf-8"
                )
            )
            nested_mutation_materials = {
                "sandbox_capability": b'{"fixture":"sandbox"}\n',
                "provenance_statement": b'{"fixture":"provenance"}\n',
                "execution_result": b'{"fixture":"execution"}\n',
            }
            nested_mutation_references = {}
            for name, data in nested_mutation_materials.items():
                path = f"artifacts/governance/mutation-{name}.json"
                (repository / path).write_bytes(data)
                nested_mutation_references[name] = {
                    "path": path,
                    "sha256": sha256_bytes(data),
                }
            mutant_references = []
            for index, mutant_id in enumerate(sorted(REQUIRED_CURATED_MUTANTS)):
                mutant = dict(mutant_template)
                mutant.update(
                    repository_id=policy["repository_id"],
                    task_contract_sha256=task_sha,
                    effective_policy_sha256=sha256_canonical(policy),
                    candidate_id=candidate["candidate_id"],
                    mutant_id="MUTANT-" + mutant_id.upper(),
                    outcome="KILLED",
                )
                mutant.update(nested_mutation_references)
                mutant = content_address(mutant, "mutant_record_id")
                mutant_bytes = canonical_json_bytes(mutant)
                mutant_path = evidence / f"mutant-{index}.json"
                mutant_path.write_bytes(mutant_bytes)
                mutant_references.append(
                    {
                        "path": f"artifacts/governance/mutant-{index}.json",
                        "sha256": sha256_bytes(mutant_bytes),
                    }
                )
            mutation_summary = root / "mutation-summary.json"
            mutation_summary.write_bytes(
                canonical_json_bytes(
                    {"state": "PASS", "mutant_records": mutant_references}
                )
            )
            closure = GitCliRepositoryAdapter(repository).conservative_affected_closure(
                candidate=candidate, evidence_root=policy["evidence_root"]
            )
            sources = root / "sources.json"
            sources.write_bytes(canonical_json_bytes(self.sources(candidate, closure)))
            source_bundle = repository / "artifacts/governance/sources.json"
            projection = repository / "artifacts/governance/projection.json"
            receipt = repository / "artifacts/governance/receipt.json"
            prepared = self.run_cli(
                "prepare-review", "--repository", str(repository),
                "--policy", str(policy_path),
                "--task", str(task_path),
                "--gate-summary", str(gate_summary),
                "--mutation-summary", str(mutation_summary),
                "--context-qualification", str(qualification_path),
                "--candidate", str(candidate_path), "--profile", "DEEP",
                "--token-budget", "64000",
                "--model", "gpt-5.6-sol", "--reasoning-effort", "xhigh",
                "--observed-at", "2026-08-26T10:00:00Z",
                "--sources-output", "artifacts/governance/sources.json",
                "--projection-output", "artifacts/governance/projection.json",
                "--receipt-output", "artifacts/governance/receipt.json",
            )
            self.assertEqual(
                0,
                prepared.returncode,
                prepared.stderr.decode() + prepared.stdout.decode(),
            )
            self.assertTrue(source_bundle.is_file())
            protected_artifacts = json.loads(source_bundle.read_text())["sources"][
                "artifacts"
            ]
            self.assertEqual(
                {
                    gate_result_ref["path"],
                    *[reference["path"] for reference in mutant_references],
                    *[
                        reference["path"]
                        for reference in nested_mutation_references.values()
                    ],
                    "artifacts/governance/gate-stdout.bin",
                    "artifacts/governance/gate-stderr.bin",
                    "artifacts/governance/gate-provenance.json",
                },
                {item["reference"] for item in protected_artifacts},
            )
            verified = self.run_cli(
                "verify", "--artifact", str(receipt), "--schema", "context-receipt",
                "--identity-field", "receipt_id",
            )
            self.assertEqual(0, verified.returncode, verified.stderr.decode())
            blocked = self.run_cli(
                "prepare-review", "--repository", str(repository),
                "--policy", str(policy_path), "--task", str(task_path),
                "--gate-summary", str(gate_summary),
                "--mutation-summary", str(mutation_summary),
                "--context-qualification", str(qualification_path),
                "--candidate", str(candidate_path), "--profile", "COMPACT",
                "--token-budget", "1",
                "--model", "gpt-5.6-sol", "--reasoning-effort", "xhigh",
                "--observed-at", "2026-08-26T10:00:00Z",
                "--sources-output", "artifacts/governance/small-sources.json",
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
                "--task", str(task_path), "--gate-summary", str(gate_summary),
                "--mutation-summary", str(mutation_summary),
                "--context-qualification", str(qualification_path),
                "--candidate", str(candidate_path), "--profile", "DEEP",
                "--token-budget", "64000", "--model", "gpt-5.6-sol",
                "--reasoning-effort", "xhigh",
                "--observed-at", "2026-08-26T10:00:00Z",
                "--sources-output", "artifacts/governance/tampered-sources.json",
                "--projection-output", "artifacts/governance/tampered-projection.json",
                "--receipt-output", "artifacts/governance/tampered-receipt.json",
            )
            self.assertEqual(2, mismatch.returncode)
            self.assertEqual("UNKNOWN", json.loads(mismatch.stdout)["state"])

    def test_illustrative_disposition_never_reports_ready(self) -> None:
        status = self.run_cli("status", "--disposition", "examples/disposition.json")
        self.assertEqual(2, status.returncode)
        payload = json.loads(status.stdout)
        self.assertEqual("UNKNOWN", payload["state"])
        self.assertEqual("UNKNOWN", payload["reported_state"])
        self.assertFalse(payload["authoritative"])

        with tempfile.TemporaryDirectory() as directory:
            forged = json.loads(
                (self.ROOT / "examples/disposition.json").read_text(
                    encoding="utf-8"
                )
            )
            forged["state"] = "READY_FOR_HUMAN"
            path = Path(directory) / "forged-ready.json"
            path.write_bytes(canonical_json_bytes(forged))
            ready = self.run_cli("status", "--disposition", str(path))
        self.assertEqual(2, ready.returncode)
        ready_payload = json.loads(ready.stdout)
        self.assertEqual("UNKNOWN", ready_payload["state"])
        self.assertEqual("READY_FOR_HUMAN", ready_payload["reported_state"])
        self.assertFalse(ready_payload["authoritative"])

    def test_review_candidate_supplier_rejects_source_or_snapshot_drift(self) -> None:
        from codex_governance.cli import _composite_review_candidate_supplier

        source = Path("source")
        snapshot = Path("snapshot")
        identities = {source: "sha256:" + "a" * 64, snapshot: "sha256:" + "a" * 64}
        supplier = _composite_review_candidate_supplier(
            source_repository=source,
            snapshot_repository=snapshot,
            identify=lambda repository, _deadline: identities[repository],
        )
        self.assertEqual("sha256:" + "a" * 64, supplier(1.0))
        identities[snapshot] = "sha256:" + "b" * 64
        with self.assertRaisesRegex(ValueError, "source and copied snapshot"):
            supplier(1.0)

    def test_gate_candidate_supplier_rejects_source_or_copy_drift(self) -> None:
        from codex_governance.cli import _composite_gate_candidate_supplier

        source = Path("source")
        copied = Path("copy")
        expected = "sha256:" + "a" * 64
        identities = {source: expected, copied: expected}
        supplier = _composite_gate_candidate_supplier(
            source_repository=source,
            copied_repository=copied,
            expected_candidate_id=expected,
            identify=lambda repository, _deadline: identities[repository],
            deadline=1.0,
        )
        self.assertEqual(expected, supplier())
        for drifted in (source, copied):
            identities[drifted] = "sha256:" + "b" * 64
            with self.subTest(drifted=drifted), self.assertRaisesRegex(
                ValueError, "source and copied gate candidate"
            ):
                supplier()
            identities[drifted] = expected

    def test_review_deadline_exists_before_pipeline_lock_selection(self) -> None:
        from codex_governance import cli

        args = Namespace(
            command="review",
            timeout_seconds=10.0,
            handler=lambda _args: 0,
        )
        parser = Mock()
        parser.parse_args.return_value = args
        observed: list[float] = []

        def lock_for(received: Namespace):
            observed.append(received._review_deadline)
            return cli.nullcontext()

        with (
            patch.object(cli, "_parser", return_value=parser),
            patch.object(cli, "_pipeline_lock_for", side_effect=lock_for),
            patch.object(cli, "_preflight_cli_outputs"),
        ):
            self.assertEqual(0, cli.main([]))
        self.assertEqual(1, len(observed))
        self.assertGreater(observed[0], time.monotonic())

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
            authority_root=self.ROOT,
            prompt=Path(".codex/review/reviewer.prompt.md"),
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
        self.assertEqual(
            (self.ROOT / ".codex/review/reviewer.prompt.md").read_bytes(),
            evaluate.call_args.kwargs["protected_prompt_bytes"],
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

    def test_governance_gate_producer_emits_separate_typed_rollback_evidence(self) -> None:
        from codex_governance import cli
        from codex_governance.artifacts import FilesystemArtifactStore
        from codex_governance.attestation import (
            build_provenance_statement,
            gate_implementation_sha256,
        )
        from codex_governance.sandbox import sandbox_execution_identity
        from codex_governance.schema import load_json, validate_instance

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            (repository / "schemas").mkdir(parents=True)
            (repository / "scripts").mkdir()
            (repository / "schemas/change.json").write_text(
                '{"version":1}\n', encoding="utf-8"
            )
            (repository / "scripts/rehearse_rollback.py").write_text(
                "print('fixture')\n", encoding="utf-8"
            )
            environment = dict(os.environ)
            environment.update(
                GIT_AUTHOR_NAME="fixture",
                GIT_AUTHOR_EMAIL="fixture@example.invalid",
                GIT_COMMITTER_NAME="fixture",
                GIT_COMMITTER_EMAIL="fixture@example.invalid",
            )
            subprocess.run(
                ["git", "init", "-q", str(repository)],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            subprocess.run(
                ["git", "-C", str(repository), "add", "."],
                check=True,
                env=environment,
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-qm", "base"],
                check=True,
                env=environment,
            )
            base = subprocess.check_output(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                text=True,
            ).strip()
            (repository / "schemas/change.json").write_text(
                '{"version":2}\n', encoding="utf-8"
            )
            subprocess.run(
                ["git", "-C", str(repository), "add", "."],
                check=True,
                env=environment,
            )
            subprocess.run(
                ["git", "-C", str(repository), "commit", "-qm", "candidate"],
                check=True,
                env=environment,
            )
            head = subprocess.check_output(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                text=True,
            ).strip()

            policy = json.loads(
                (self.ROOT / "examples/effective-policy.json").read_text()
            )
            policy.update(
                repository_id="repo:example/rollback-producer",
                lkg_governance_commit=base,
            )
            rollback_definition = next(
                item
                for item in policy["gates"]
                if item["gate_id"] == "rollback-rehearsal"
            )
            rollback_definition["command"] = protected_rollback_command(base)
            proposed_policy = json.loads(json.dumps(policy))
            proposed_policy["policy_id"] = "POLICY-PROPOSED-FIXTURE"
            proposed_policy["lkg_governance_commit"] = head
            next(
                item
                for item in proposed_policy["gates"]
                if item["gate_id"] == "rollback-rehearsal"
            )["command"][-1] = head
            policy_path = root / "policy.json"
            proposed_path = root / "proposed-policy.json"
            policy_path.write_bytes(canonical_json_bytes(policy))
            proposed_path.write_bytes(canonical_json_bytes(proposed_policy))

            candidate = GitCliRepositoryAdapter(repository).identify(
                repository_id=policy["repository_id"],
                mode="commit",
                base_commit=base,
                head_commit=head,
                effective_policy_sha256=sha256_canonical(policy),
                evidence_root=policy["evidence_root"],
            )
            candidate_path = root / "candidate.json"
            candidate_path.write_bytes(canonical_json_bytes(candidate))
            task = json.loads((self.ROOT / "examples/task-contract.json").read_text())
            task.update(
                repository_id=policy["repository_id"],
                base_commit=base,
                profile="governance",
                affected_surfaces=[
                    {"path": "schemas/", "reason": "governance fixture"}
                ],
                required_gate_ids=["blueprint-quality"],
                unknowns=[],
                governance_change_requested=True,
            )
            task_path = root / "task.json"
            task_path.write_bytes(canonical_json_bytes(task))
            task_sha = sha256_canonical(task)
            store = FilesystemArtifactStore(
                repository=repository,
                root=Path(policy["evidence_root"]),
            )
            emitted = []

            def fake_run_gate(**arguments):
                gate_id = arguments["gate_id"]
                command = list(arguments["command"])
                artifact_store = arguments["artifact_store"]
                prefix = arguments["artifact_prefix"]
                candidate_id = arguments["candidate_supplier"]()
                executed_copy = arguments["sandbox_invocation"].candidate_copy
                drift_probe = executed_copy / "schemas/change.json"
                original_probe = drift_probe.read_bytes()
                drift_probe.write_text('{"version":999}\n', encoding="utf-8")
                with self.assertRaises(ValueError):
                    arguments["candidate_supplier"]()
                drift_probe.write_bytes(original_probe)
                self.assertEqual(candidate_id, arguments["candidate_supplier"]())
                timeout_seconds = int(arguments["timeout_seconds"])
                max_output_bytes = arguments["max_output_bytes"]
                execution_identity = sandbox_execution_identity(
                    provider="docker",
                    provider_version="fixture",
                    image=policy["sandbox"]["image"],
                    command=command,
                    process_limit=policy["sandbox"]["process_limit"],
                    memory_bytes=policy["sandbox"]["memory_bytes"],
                    cpu_seconds=timeout_seconds,
                    timeout_seconds=timeout_seconds,
                    output_bytes=max_output_bytes,
                )
                capability = content_address(
                    {
                        "schema_version": "2.0.0",
                        "provider": "docker",
                        "provider_version": "fixture",
                        "image": policy["sandbox"]["image"],
                        "command": command,
                        "implementation_sha256": gate_implementation_sha256(),
                        "source_identity": candidate_id,
                        "execution_identity": execution_identity,
                        "disposable": True,
                        "secrets_present": False,
                        "network_mode": "none",
                        "candidate_copy_writable": True,
                        "protected_paths_writable": False,
                        "evidence_paths_writable": False,
                        "supervisor_paths_writable": False,
                        "process_limit": policy["sandbox"]["process_limit"],
                        "memory_bytes": policy["sandbox"]["memory_bytes"],
                        "cpu_seconds": timeout_seconds,
                        "timeout_seconds": timeout_seconds,
                        "output_bytes": max_output_bytes,
                        "verified_at": "2026-08-26T09:59:59Z",
                        "limitations": [],
                    },
                    "capability_id",
                )
                capability_sha = artifact_store.write_bytes(
                    f"{prefix}/sandbox-capability.json",
                    canonical_json_bytes(capability),
                )
                stdout = (
                    f"ROLLBACK_REHEARSAL=PASS target={base}\n".encode("ascii")
                    if gate_id == "rollback-rehearsal"
                    else b"PASS\n"
                )
                stdout_sha = artifact_store.write_bytes(
                    f"{prefix}/stdout.bin", stdout
                )
                stderr_sha = artifact_store.write_bytes(
                    f"{prefix}/stderr.bin", b""
                )
                provenance_context = arguments["provenance_context"]
                provenance = build_provenance_statement(
                    repository_id=policy["repository_id"],
                    candidate_id=candidate_id,
                    repository_digest=candidate_id,
                    task_contract_sha256=task_sha,
                    effective_policy_sha256=sha256_canonical(policy),
                    gate_definition_sha256=provenance_context[
                        "gate_definition_sha256"
                    ],
                    reviewer_prompt_sha256=provenance_context[
                        "reviewer_prompt_sha256"
                    ],
                    producer=provenance_context["producer"],
                    workflow=provenance_context["workflow"],
                    tools=provenance_context["tools"],
                    environment={
                        "source_identity": candidate_id,
                        "execution_identity": execution_identity,
                        "sandbox_capability_sha256": capability_sha,
                    },
                    materials=provenance_context["materials"],
                    started_at="2026-08-26T10:00:00Z",
                    ended_at="2026-08-26T10:00:01Z",
                    result="PASS",
                    limits={
                        "timeout_seconds": timeout_seconds,
                        "max_output_bytes": max_output_bytes,
                        "process_limit": policy["sandbox"]["process_limit"],
                        "memory_bytes": policy["sandbox"]["memory_bytes"],
                        "cpu_seconds": timeout_seconds,
                    },
                    artifacts=[
                        {"name": "stdout", "sha256": stdout_sha},
                        {"name": "stderr", "sha256": stderr_sha},
                        {"name": "sandbox-capability", "sha256": capability_sha},
                    ],
                    limitations=[],
                )
                provenance_sha = artifact_store.write_bytes(
                    f"{prefix}/provenance.json",
                    canonical_json_bytes(provenance),
                )
                result = {
                    "schema_version": "1.0.0",
                    "repository_id": policy["repository_id"],
                    "task_contract_sha256": task_sha,
                    "gate_id": gate_id,
                    "profile": "governance",
                    "candidate_before": candidate_id,
                    "candidate_after": candidate_id,
                    "source_identity": candidate_id,
                    "execution_identity": execution_identity,
                    "sandbox_capability_sha256": capability_sha,
                    "command": command,
                    "started_at": "2026-08-26T10:00:00Z",
                    "ended_at": "2026-08-26T10:00:01Z",
                    "duration_ms": 1000,
                    "termination": {"kind": "exited", "exit_code": 0},
                    "artifacts": [
                        {
                            "stream": "stdout",
                            "path": f"artifacts/governance/{prefix}/stdout.bin",
                            "bytes": len(stdout),
                            "sha256": stdout_sha,
                            "truncated": False,
                        },
                        {
                            "stream": "stderr",
                            "path": f"artifacts/governance/{prefix}/stderr.bin",
                            "bytes": 0,
                            "sha256": stderr_sha,
                            "truncated": False,
                        },
                    ],
                    "redactions": [],
                    "observation_complete": True,
                    "status": "PASS",
                    "limitations": [],
                    "provenance_statement": {
                        "path": f"artifacts/governance/{prefix}/provenance.json",
                        "sha256": provenance_sha,
                    },
                    "producer_version": "0.1.0",
                }
                artifact_store.write_bytes(
                    f"{prefix}/result.json", canonical_json_bytes(result)
                )
                return result

            arguments = Namespace(
                repository=repository,
                policy=policy_path,
                proposed_policy=proposed_path,
                task=task_path,
                candidate=candidate_path,
                reviewer_prompt=self.ROOT / ".codex/review/reviewer.prompt.md",
                schema_root=self.ROOT / "schemas",
                run_id="rollback-producer-fixture",
                attempt=1,
                workflow_system="protected-fixture",
                observed_at="2026-08-26T09:59:59Z",
                output=None,
                _cli_output_store=store,
            )

            def fake_container_invocation(**values):
                protected = values["protected_source_root"]
                if values["command"] == rollback_definition["command"]:
                    self.assertIsNotNone(protected)
                    self.assertNotEqual(
                        Path(cli.__file__).resolve().parents[1], protected
                    )
                    protected_files = [
                        path for path in protected.rglob("*") if path.is_file()
                    ]
                    self.assertTrue(protected_files)
                    self.assertTrue(
                        all(path.suffix == ".py" for path in protected_files)
                    )
                    self.assertTrue(
                        (protected / "codex_governance/rollback.py").is_file()
                    )
                else:
                    self.assertIsNone(protected)
                return SimpleNamespace(candidate_copy=values["candidate_copy"])

            with (
                patch.object(cli, "observe_container_provider", return_value="fixture"),
                patch.object(
                    cli,
                    "build_container_invocation",
                    side_effect=fake_container_invocation,
                ),
                patch.object(cli, "run_gate", side_effect=fake_run_gate),
                patch.object(cli, "_emit", side_effect=emitted.append),
            ):
                try:
                    exit_code = cli._run_gates(arguments)
                except Exception as exc:  # pragma: no cover - mutation oracle
                    self.fail(
                        "protected rollback orchestration raised unexpectedly: "
                        f"{type(exc).__name__}"
                    )
                self.assertEqual(0, exit_code)

            summary = emitted[-1]
            self.assertEqual(
                [{"gate_id": "blueprint-quality", "status": "PASS"}],
                summary["results"],
            )
            rollback_reference = summary["rollback_evidence"]
            self.assertIsNotNone(rollback_reference)
            rollback = json.loads(
                (repository / rollback_reference["path"]).read_text()
            )
            self.assertEqual(
                [],
                validate_instance(
                    rollback,
                    load_json(self.ROOT / "schemas/rollback-evidence.schema.json"),
                ),
            )
            self.assertEqual(base, rollback["rollback_target_commit"])
            gate = json.loads(
                (repository / rollback["gate_result"]["path"]).read_text()
            )
            self.assertEqual(protected_rollback_command(base), gate["command"])
            stdout = next(
                item for item in gate["artifacts"] if item["stream"] == "stdout"
            )
            self.assertEqual(
                f"ROLLBACK_REHEARSAL=PASS target={base}\n".encode("ascii"),
                (repository / stdout["path"]).read_bytes(),
            )
            arguments.proposed_policy = None
            with self.assertRaisesRegex(ValueError, "require a proposed policy"):
                cli._run_gates(arguments)

    def test_manifest_assembly_is_content_addressed_and_schema_valid(self) -> None:
        example = json.loads(
            (self.ROOT / "examples/evidence-manifest.json").read_text(encoding="utf-8")
        )
        required = {
            key: example[key]
            for key in (
                "repository_id", "candidate_id", "task_contract",
                "effective_policy", "lkg_policy_decision",
                "authenticated_decisions", "evidence_locators",
                "sandbox_capabilities", "provenance_statements", "gate_manifest",
                "required_gate_ids", "mutation_corpus", "mutation_baseline",
                "mutant_records", "reviewer_qualification",
                "rapid_review_qualification", "reviewer_qualification_cases",
                "rapid_review_qualification_cases",
                "reviewer_qualification_corpus",
                "reviewer_qualification_label_decision", "context_sources",
                "context_projection", "context_qualification", "context_receipt",
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
