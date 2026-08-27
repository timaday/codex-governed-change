import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from codex_governance.candidate import GitCliRepositoryAdapter
from codex_governance.canonical import canonical_json_bytes, sha256_canonical


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
        scoped = self.run_cli(
            "scope", "--task", "examples/task-contract.json",
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
            output = root / "scope.json"
            arguments = (
                "scope", "--task", "examples/task-contract.json",
                "--policy", "examples/effective-policy.json", "--output", str(output),
            )
            first = self.run_cli(*arguments)
            self.assertEqual(0, first.returncode, first.stderr.decode())
            original = output.read_bytes()
            replay = self.run_cli(*arguments)
            self.assertEqual(0, replay.returncode, replay.stderr.decode())
            self.assertEqual(original, output.read_bytes())

            conflicting = self.run_cli(
                *arguments, "--evidence-root", "different-evidence-root"
            )
            self.assertEqual(2, conflicting.returncode)
            self.assertEqual("UNKNOWN", json.loads(conflicting.stdout)["state"])
            self.assertEqual(original, output.read_bytes())

            victim = root / "victim.json"
            victim.write_bytes(b"unchanged")
            linked_output = root / "linked.json"
            try:
                linked_output.symlink_to(victim)
            except OSError:
                self.assertFalse(linked_output.exists())
            else:
                linked = self.run_cli(
                    "scope", "--task", "examples/task-contract.json",
                    "--policy", "examples/effective-policy.json",
                    "--output", str(linked_output),
                )
                self.assertEqual(2, linked.returncode)
                self.assertEqual(b"unchanged", victim.read_bytes())

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
            projection = root / "projection.json"
            receipt = root / "receipt.json"
            prepared = self.run_cli(
                "prepare-review", "--repository", str(repository),
                "--policy", str(policy_path),
                "--sources", str(sources),
                "--candidate", str(candidate_path), "--profile", "STANDARD",
                "--token-budget", "24000",
                "--model", "gpt-5.6-sol", "--reasoning-effort", "xhigh",
                "--projection-output", str(projection), "--receipt-output", str(receipt),
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
                "--projection-output", str(root / "small-projection.json"),
                "--receipt-output", str(root / "small-receipt.json"),
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
                "--projection-output", str(root / "tampered-projection.json"),
                "--receipt-output", str(root / "tampered-receipt.json"),
            )
            self.assertEqual(2, mismatch.returncode)
            self.assertEqual("UNKNOWN", json.loads(mismatch.stdout)["state"])

    def test_illustrative_disposition_never_reports_ready(self) -> None:
        status = self.run_cli("status", "--disposition", "examples/disposition.json")
        self.assertEqual(2, status.returncode)
        self.assertEqual("UNKNOWN", json.loads(status.stdout)["state"])

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
            inputs = root / "assembly.json"
            output = root / "manifest.json"
            inputs.write_bytes(canonical_json_bytes(required))
            assembled = self.run_cli(
                "assemble-manifest", "--repository", str(self.ROOT),
                "--policy", "examples/effective-policy.json",
                "--input", str(inputs), "--output", str(output)
            )
            self.assertEqual(0, assembled.returncode, assembled.stderr.decode())
            verified = self.run_cli(
                "verify", "--artifact", str(output), "--schema", "evidence-manifest",
                "--identity-field", "manifest_id",
            )
            self.assertEqual(0, verified.returncode, verified.stderr.decode())


if __name__ == "__main__":
    unittest.main()
