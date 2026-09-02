import unittest
import shutil
import subprocess
import tempfile
from unittest.mock import patch
from pathlib import Path

from codex_governance.canonical import (
    canonical_json_bytes,
    content_address,
    sha256_bytes,
)
from codex_governance.domain.model import DispositionState


class MutationGovernanceAcceptanceTest(unittest.TestCase):
    def record(self, outcome: str = "KILLED") -> dict:
        document = {
            "repository_id": "repo:example/project",
            "task_contract_sha256": "sha256:" + "1" * 64,
            "effective_policy_sha256": "sha256:" + "2" * 64,
            "candidate_id": "sha256:" + "3" * 64,
            "corpus_id": "sha256:" + "4" * 64,
            "mutant_id": "MUTANT-AUTHORITY",
            "patch_sha256": "sha256:" + "a" * 64,
            "operator": "remove-authority-check",
            "tool": "curated-governance-corpus",
            "tool_version": "1.0.0",
            "location": {"path": "src/codex_governance/authority.py", "line": 1},
            "requirement_id": "GOV-048",
            "selected_command": ["python3", "-m", "unittest"],
            "selected_tests": ["tests/acceptance/test_trusted_authority.py"],
            "outcome": outcome,
            "causal_evidence": ["expected test failed"] if outcome == "KILLED" else [],
            "triage": {"identity": "", "rationale": "", "human_reviewed": False},
            "limitations": [],
            "sandbox_capability": {"path": "evidence/capability.json", "sha256": "sha256:" + "5" * 64},
            "provenance_statement": {"path": "evidence/provenance.json", "sha256": "sha256:" + "6" * 64},
            "execution_result": {"path": "evidence/result.json", "sha256": "sha256:" + "7" * 64},
        }
        return content_address(document, "mutant_record_id")

    def test_only_causal_kill_of_valid_non_equivalent_mutant_passes(self) -> None:
        from codex_governance.mutation import evaluate_mutation_record

        self.assertEqual(DispositionState.READY_FOR_HUMAN, evaluate_mutation_record(self.record()))
        for outcome in ("SURVIVED", "INVALID", "TIMEOUT", "EQUIVALENT_CLAIMED", "UNKNOWN"):
            with self.subTest(outcome=outcome):
                self.assertNotEqual(DispositionState.READY_FOR_HUMAN, evaluate_mutation_record(self.record(outcome)))
        no_cause = self.record()
        no_cause["causal_evidence"] = []
        no_cause = content_address(no_cause, "mutant_record_id")
        self.assertEqual(DispositionState.UNKNOWN, evaluate_mutation_record(no_cause))

    def test_mandatory_corpus_contains_all_known_bypass_classes(self) -> None:
        from codex_governance.mutation import REQUIRED_CURATED_MUTANTS, load_curated_corpus

        expected = {
            "missing-reviewer-pass", "timeout-soft-success", "omit-untracked",
            "omit-post-identity", "reviewer-pass-authorizes", "expired-waiver",
            "artifact-symlink", "reviewer-shell", "stop-loop", "candidate-gates",
            "redaction-hides-failure", "skipped-final", "cross-repository-replay",
            "forged-task-authorization", "writable-protected-paths",
            "manifest-overwrite", "cli-output-overwrite", "raw-stream-success",
            "unverified-reviewer-reference", "risk-downgrade",
            "protected-risk-floor-downgrade",
            "old-policy-self-replacement", "missing-provenance",
            "nested-source-credential", "rollback-output-unbound",
            "legacy-context-schema",
            "gate-copy-source-identity", "mutation-copy-source-identity",
            "candidate-owned-corpus", "candidate-owned-rollback",
            "incomplete-migration-registry", "ignored-submodule-copy",
            "unframed-rollback-package",
        }
        self.assertTrue(expected.issubset(REQUIRED_CURATED_MUTANTS))
        corpus = load_curated_corpus(Path("tests/mutation/corpus.json"))
        self.assertEqual(expected, {item["mutant_id"] for item in corpus["mutants"]})

    def test_every_curated_mutation_matches_exactly_one_current_source_location(self) -> None:
        from codex_governance.mutation import apply_curated_mutant, load_curated_corpus

        corpus = load_curated_corpus(Path("tests/mutation/corpus.json"))
        for mutant in corpus["mutants"]:
            with self.subTest(mutant=mutant["mutant_id"]), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = Path(mutant["path"])
                target = root / mutant["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
                digest = apply_curated_mutant(root, mutant)
                self.assertTrue(digest.startswith("sha256:"))
                self.assertIn(mutant["new"], target.read_text(encoding="utf-8"))

    def test_generated_adapter_budget_is_bounded_and_percentage_is_not_oracle(self) -> None:
        from codex_governance.mutation import select_generated_mutants

        selected = select_generated_mutants(
            candidates=[{"id": str(index), "changed_line": index < 3, "risk": "high" if index == 4 else "low"} for index in range(20)],
            budget=5,
        )
        self.assertLessEqual(len(selected), 5)
        self.assertTrue(all(item["changed_line"] or item["risk"] == "high" for item in selected))

    def test_mutant_identity_binds_the_complete_concrete_tree_and_copy_drift(self) -> None:
        from codex_governance.mutation import (
            apply_curated_mutant,
            expected_mutated_tree_sha256,
            git_visible_tree_sha256,
            mutated_source_identity,
        )
        from codex_governance.sandbox import prepare_candidate_copy

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repository"
            repository.mkdir()
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
            (repository / "module.py").write_text("ENFORCE = True\n", encoding="utf-8")
            (repository / "other.py").write_text("VALUE = 1\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(repository), "commit", "--quiet", "-m", "fixture"],
                check=True,
            )
            mutant = {
                "path": "module.py",
                "old": "ENFORCE = True",
                "new": "ENFORCE = False",
                "operator": "disable enforcement",
            }
            expected_tree = expected_mutated_tree_sha256(
                repository=repository,
                evidence_root="evidence",
                mutant=mutant,
            )
            copied = prepare_candidate_copy(
                repository=repository,
                destination=(root / "copy").resolve(),
                evidence_root="evidence",
            )
            patch_sha = apply_curated_mutant(copied, mutant)
            self.assertEqual(
                expected_tree,
                git_visible_tree_sha256(copied, evidence_root="evidence"),
            )
            source = mutated_source_identity(
                candidate_id="sha256:" + "1" * 64,
                corpus_id="sha256:" + "2" * 64,
                mutant_id="fixture",
                patch_sha256=patch_sha,
                tree_sha256=expected_tree,
            )
            (copied / "other.py").write_text("VALUE = 2\n", encoding="utf-8")
            drifted = mutated_source_identity(
                candidate_id="sha256:" + "1" * 64,
                corpus_id="sha256:" + "2" * 64,
                mutant_id="fixture",
                patch_sha256=patch_sha,
                tree_sha256=git_visible_tree_sha256(
                    copied, evidence_root="evidence"
                ),
            )
            self.assertNotEqual(source, drifted)

    def test_policy_digest_rejects_readdressed_candidate_corpus_substitution(self) -> None:
        from codex_governance.mutation_runner import parse_protected_corpus

        original = Path("tests/mutation/corpus.json").read_bytes()
        parsed = parse_protected_corpus(
            original, expected_sha256=sha256_bytes(original)
        )
        substituted = dict(parsed)
        substituted["baseline_command"] = ["python3", "-c", "pass"]
        substituted = content_address(substituted, "corpus_id")
        with self.assertRaisesRegex(ValueError, "digest"):
            parse_protected_corpus(
                canonical_json_bytes(substituted),
                expected_sha256=sha256_bytes(original),
            )

    def test_unavailable_container_never_falls_back_to_host_mutation_execution(self) -> None:
        from codex_governance.candidate import GitCliRepositoryAdapter
        from codex_governance.canonical import sha256_canonical
        from codex_governance.mutation_runner import run_governed_mutation_corpus

        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            repository.mkdir()
            subprocess.run(["git", "-C", str(repository), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repository), "config", "user.name", "Fixture"], check=True)
            subprocess.run(["git", "-C", str(repository), "config", "user.email", "fixture@example.invalid"], check=True)
            (repository / ".gitignore").write_text("evidence/\n", encoding="utf-8")
            corpus = repository / "tests/mutation/corpus.json"
            corpus.parent.mkdir(parents=True)
            shutil.copyfile(Path("tests/mutation/corpus.json"), corpus)
            subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repository), "commit", "-qm", "fixture"], check=True)
            base = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True, stdout=subprocess.PIPE, text=True,
            ).stdout.strip()
            policy = {
                "repository_id": "repo:example/project", "evidence_root": "evidence",
                "mutation": {
                    "corpus_path": "tests/mutation/corpus.json",
                    "corpus_sha256": sha256_bytes(corpus.read_bytes()),
                },
                "sandbox": {
                    "provider": "docker", "image": "python@sha256:" + "a" * 64,
                    "process_limit": 8, "memory_bytes": 1000000,
                },
                "gates": [{"timeout_seconds": 10, "max_output_bytes": 1000}],
            }
            policy_sha = sha256_canonical(policy)
            candidate = GitCliRepositoryAdapter(repository).identify(
                repository_id=policy["repository_id"], mode="working_tree",
                base_commit=base, effective_policy_sha256=policy_sha,
                evidence_root="evidence",
            )
            task = {"profile": "code"}
            with patch(
                "codex_governance.mutation_runner.observe_container_provider",
                side_effect=RuntimeError("unavailable"),
            ):
                result = run_governed_mutation_corpus(
                    repository=repository, policy=policy, task=task,
                    candidate=candidate, task_contract_sha256="sha256:" + "b" * 64,
                    effective_policy_sha256=policy_sha,
                    reviewer_prompt_sha256="sha256:" + "c" * 64,
                    run_id="fixture", attempt=1, workflow_system="unit",
                    observed_at="2026-08-26T10:00:00Z",
                    implementation_sha256="sha256:" + "d" * 64,
                    corpus_bytes=corpus.read_bytes(),
                )
            self.assertEqual("UNKNOWN", result["state"])
            self.assertEqual([], result["mutant_records"])


if __name__ == "__main__":
    unittest.main()
