import json
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

    def test_each_mutant_requires_exact_source_and_copy_identity_before_patch(self) -> None:
        from codex_governance.mutation_runner import original_candidate_copy_is_exact

        expected = "sha256:" + "a" * 64
        self.assertTrue(
            original_candidate_copy_is_exact(
                source_before=expected,
                copied_candidate=expected,
                source_after=expected,
                expected_candidate=expected,
            )
        )
        for field in ("source_before", "copied_candidate", "source_after"):
            values = {
                "source_before": expected,
                "copied_candidate": expected,
                "source_after": expected,
                "expected_candidate": expected,
            }
            values[field] = "sha256:" + "b" * 64
            with self.subTest(field=field):
                self.assertFalse(original_candidate_copy_is_exact(**values))

    def test_mutation_git_observations_use_the_shared_absolute_deadline(self) -> None:
        from codex_governance.mutation import _git

        deadline = __import__("time").monotonic() + 2
        with patch(
            "codex_governance.mutation.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, stdout=b"", stderr=b""),
        ) as run:
            self.assertEqual(b"", _git(Path("."), "status", deadline=deadline))
        timeout = run.call_args.kwargs["timeout"]
        self.assertIsNotNone(timeout)
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 2)

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
            "reviewer-command-payload-unprojected", "rollback-output-unbound",
            "legacy-context-schema",
            "gate-copy-source-identity", "mutation-copy-source-identity",
            "candidate-owned-corpus", "candidate-owned-rollback",
            "incomplete-migration-registry", "ignored-submodule-copy",
            "unframed-rollback-package", "rollback-sibling-sitecustomize",
            "noncausal-mutation-kill", "submodule-head-only",
            "host-value-redaction-nonblocking", "qualification-output-unchecked",
            "artifact-leaf-rebind", "fcntl-signal-escape",
            "qualification-blanket-block", "mutant-subject-confusion",
            "provenance-prompt-unchecked", "provenance-materials-unchecked",
            "rapid-defect-id-unchecked", "rapid-finding-line-unchecked",
            "reviewer-output-canonicalized", "reviewer-output-leaf-rebind",
            "fcntl-benign-status-denied", "short-host-value-unredacted",
            "gate-endpoint-unredacted", "review-snapshot-source-only",
            "assurance-fixed-set-removed", "status-ready-passthrough",
            "reviewer-finding-location-unchecked",
            "shared-host-root-truncated", "named-endpoint-unredacted",
            "ioctl-signal-escape", "authoritative-json-pathname-read",
            "authoritative-json-reopened", "untracked-pathname-read",
            "candidate-clone-unbounded", "preparation-error-launches",
            "candidate-entry-pathname-copy", "reviewer-entry-pathname-copy",
            "reviewer-permission-deadline-omitted",
            "mutant-copy-identity-omitted", "mutation-git-deadline-omitted",
            "reviewer-argv-unchecked", "reviewer-stdin-unchecked",
            "reviewer-permitted-input-unchecked",
            "rapid-risk-material-unchecked",
            "rapid-charter-material-unchecked",
            "authoritative-reference-reopened", "bare-ipv6-unredacted",
            "admission-candidate-prompt-read",
            "mutation-control-credit-without-survival",
            "mutation-control-admission-omitted",
            "review-deadline-start-delayed",
            "untracked-read-deadline-omitted",
            "reviewer-final-output-deadline-omitted",
            "authorization-tail-truncated",
            "colon-delimited-posix-unredacted",
            "unqualified-finding-confirmed",
            "reviewer-version-deadline-omitted",
            "local-mutation-timeout-regression",
            "unreconstructable-reviewer-input-accepted",
            "admission-schema-root-unprotected",
            "qualification-schema-cache-bypassed",
            "launcher-closure-deadline-omitted",
            "launcher-closure-recheck-omitted",
            "permission-profile-prefix-only",
            "executed-reviewer-argv-unchecked",
            "executed-reviewer-argv-not-recorded",
            "reviewer-evidence-root-optional",
            "conformance-rapid-input-accepted",
            "qualification-permitted-input-partial",
            "admission-preflight-schema-unprotected",
            "reference-evaluate-schema-prefixed",
            "qualification-executed-argv-unreconciled",
            "reviewer-output-schema-reopened",
            "container-create-cidfile-pathname-read",
            "container-cleanup-cidfile-deadline-omitted",
            "container-helper-deadline-rebased",
            "multi-leading-posix-unredacted",
            "unc-share-root-unredacted",
            "permission-finalization-deadline-rebased",
            "colon-multi-posix-unredacted",
            "malformed-scheme-endpoint-family-omitted",
            "procfs-containment-preflight-omitted",
            "rapid-evidence-resolution-omitted",
            "rst-presence-promotes-readiness",
            "context-artifact-recursion-omitted",
            "context-artifacts-not-compiled",
            "synthetic-context-qualification-promoted",
            "effective-profile-budget-unchecked",
            "reviewer-runtime-overlap-accepted",
            "schema-json-equality-collapsed",
            "schema-ref-siblings-ignored",
            "schema-additional-properties-ignored",
            "schema-integral-float-rejected",
            "rapid-finding-location-unchecked",
            "rapid-retrieval-index-unchecked",
            "context-qualification-raw-evidence-unchecked",
            "rst-duplicate-risk-charter-accepted",
            "finding-target-pathname-reopened",
            "context-qualification-deadline-dropped",
            "schema-python-pattern-extension-accepted",
            "initial-bootstrap-forced-through-previous-lkg",
            "prepare-review-policy-verifies-labels",
            "review-policy-verifies-labels",
            "initial-bootstrap-authority-state-unchecked",
            "public-authority-visibility-unchecked",
            "initial-bootstrap-hosted-ruleset-shape-unchecked",
            "initial-bootstrap-plan-limitations-accepted",
            "initial-bootstrap-capability-limitations-accepted",
            "reviewer-os-home-unchecked",
            "schema-unicode-shorthands-accepted",
            "rst-requirement-change-kinds-collapsed",
            "rst-uncovered-oracle-accepted",
            "rst-uncovered-session-accepted",
            "rst-duplicate-session-coverage-accepted",
            "rst-risk-update-subset-accepted",
            "prepare-review-deadline-not-started",
            "admission-deadline-dropped",
            "schema-backreference-accepted",
            "admission-retrieval-digest-deadline-unchecked",
            "rst-missing-required-follow-up-accepted",
            "context-reasoning-tokens-double-counted",
            "context-token-subsets-unchecked",
            "context-reviewer-identity-self-asserted",
            "rfc3339-lossy-fractional-precision-accepted",
            "qualification-timeout-enforcement-omitted",
            "qualification-timeout-identity-omitted",
            "reviewer-result-semantic-uniqueness-omitted",
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

    def test_concrete_tree_recursively_binds_dirty_submodule_bytes(self) -> None:
        from codex_governance.mutation import git_visible_tree_sha256

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            child = root / "child"
            parent = root / "parent"
            for repository in (child, parent):
                repository.mkdir()
                subprocess.run(
                    ["git", "-C", str(repository), "init", "--quiet"], check=True
                )
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
            (child / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(child), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(child), "commit", "--quiet", "-m", "child"],
                check=True,
            )
            (parent / "root.py").write_text("ROOT = True\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(parent), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(parent), "commit", "--quiet", "-m", "parent"],
                check=True,
            )
            subprocess.run(
                [
                    "git", "-c", "protocol.file.allow=always", "-C", str(parent),
                    "submodule", "add", "--quiet", str(child), "vendor/child",
                ],
                check=True,
            )
            subprocess.run(["git", "-C", str(parent), "commit", "--quiet", "-am", "submodule"], check=True)

            clean = git_visible_tree_sha256(parent, evidence_root="evidence")
            nested = parent / "vendor/child"
            (nested / "module.py").write_text("VALUE = 2\n", encoding="utf-8")
            self.assertNotEqual(
                clean, git_visible_tree_sha256(parent, evidence_root="evidence")
            )
            subprocess.run(
                ["git", "-C", str(nested), "checkout", "--", "module.py"], check=True
            )
            (nested / "new.py").write_text("NEW = True\n", encoding="utf-8")
            self.assertNotEqual(
                clean, git_visible_tree_sha256(parent, evidence_root="evidence")
            )

    def test_mutation_probe_requires_a_causal_unittest_assertion_failure(self) -> None:
        from codex_governance.mutation import (
            MUTATION_INVALID_EXIT,
            MUTATION_KILLED_EXIT,
            MUTATION_PATH_SENTINEL,
            MUTATION_PROBE_PREFIX,
            MUTATION_PROBE_SENTINEL,
            MUTATION_PROBE_SOURCE,
            MUTATION_UNKNOWN_EXIT,
            build_mutation_probe_command,
            mutation_probe_outcome,
        )

        def template(*tests: str) -> list[str]:
            return [
                "python3", "-I", "-S", "-c", MUTATION_PROBE_SENTINEL,
                MUTATION_PATH_SENTINEL, *tests,
            ]

        cases = (
            ("self.fail('mutant survived oracle')", "KILLED", MUTATION_KILLED_EXIT),
            ("self.assertTrue(True)", "SURVIVED", 0),
            ("raise RuntimeError('harness error')", "UNKNOWN", MUTATION_UNKNOWN_EXIT),
            ("__import__('os')._exit(7)", "UNKNOWN", 7),
        )
        for body, expected, exit_code in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
                (root / "tests").mkdir()
                (root / "tests/__init__.py").write_text("", encoding="utf-8")
                (root / "tests/test_probe.py").write_text(
                    "import unittest\n"
                    "class ProbeTest(unittest.TestCase):\n"
                    "    def test_selected(self):\n"
                    f"        {body}\n",
                    encoding="utf-8",
                )
                command = build_mutation_probe_command(
                    "module.py",
                    template("tests.test_probe.ProbeTest.test_selected"),
                )
                self.assertEqual("python3", command[0])
                self.assertEqual(MUTATION_PROBE_SOURCE, command[4])
                self.assertEqual("module.py", command[5])
                self.assertNotIn(MUTATION_PROBE_SENTINEL, command)
                self.assertNotIn(MUTATION_PATH_SENTINEL, command)
                completed = subprocess.run(
                    command, cwd=root, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                self.assertEqual(exit_code, completed.returncode)
                self.assertEqual(
                    expected,
                    mutation_probe_outcome(completed.stdout, completed.returncode),
                )

        multiple_subtest_failures = {
            "schema_version": "1.0.0",
            "outcome": "KILLED",
            "tests_run": 1,
            "failures": 2,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
        }
        self.assertEqual(
            "KILLED",
            mutation_probe_outcome(
                MUTATION_PROBE_PREFIX
                + canonical_json_bytes(multiple_subtest_failures)
                + b"\n",
                MUTATION_KILLED_EXIT,
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "module.py").write_text("def broken(:\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests/__init__.py").write_text("", encoding="utf-8")
            command = build_mutation_probe_command(
                "module.py", template("tests.missing")
            )
            completed = subprocess.run(
                command, cwd=root, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(MUTATION_INVALID_EXIT, completed.returncode)
            self.assertEqual(
                "INVALID", mutation_probe_outcome(completed.stdout, completed.returncode)
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests/__init__.py").write_text("", encoding="utf-8")
            command = build_mutation_probe_command(
                "module.py", template("tests.missing")
            )
            completed = subprocess.run(
                command, cwd=root, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(MUTATION_UNKNOWN_EXIT, completed.returncode)
            self.assertEqual(
                "UNKNOWN", mutation_probe_outcome(completed.stdout, completed.returncode)
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests/__init__.py").write_text("", encoding="utf-8")
            (root / "tests/test_metadata.py").write_text(
                "import os, unittest\n"
                "class MetadataTest(unittest.TestCase):\n"
                "    def test_selected(self):\n"
                "        self.assertNotIn('CODEX_MUTATION_PROBE_TARGET', os.environ)\n",
                encoding="utf-8",
            )
            command = build_mutation_probe_command(
                "module.py",
                template(
                    "tests.test_metadata.MetadataTest.test_selected"
                ),
            )
            completed = subprocess.run(
                command, cwd=root, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(0, completed.returncode)
            self.assertEqual(
                "SURVIVED",
                mutation_probe_outcome(completed.stdout, completed.returncode),
            )

    def test_mutation_kill_requires_matching_surviving_control(self) -> None:
        from codex_governance.mutation import (
            MUTATION_PATH_SENTINEL,
            MUTATION_PROBE_SENTINEL,
            MUTATION_UNKNOWN_EXIT,
            build_mutation_probe_command,
            causal_mutation_pair_outcome,
            mutation_probe_outcome,
        )

        def template(test: str) -> list[str]:
            return [
                "python3", "-I", "-S", "-c", MUTATION_PROBE_SENTINEL,
                MUTATION_PATH_SENTINEL, test,
            ]

        self.assertEqual(
            "KILLED", causal_mutation_pair_outcome("SURVIVED", "KILLED")
        )
        for control in ("KILLED", "UNKNOWN", "INVALID", "TIMEOUT"):
            with self.subTest(control=control):
                self.assertEqual(
                    "UNKNOWN", causal_mutation_pair_outcome(control, "KILLED")
                )
        self.assertEqual(
            "SURVIVED", causal_mutation_pair_outcome("SURVIVED", "SURVIVED")
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests/__init__.py").write_text("", encoding="utf-8")
            (root / "tests/test_mixed.py").write_text(
                "import unittest\n"
                "class MixedTest(unittest.TestCase):\n"
                "    def test_failure(self): self.fail('failure')\n"
                "    def test_error(self): raise RuntimeError('error')\n",
                encoding="utf-8",
            )
            command = build_mutation_probe_command(
                "module.py",
                template("tests.test_mixed.MixedTest"),
            )
            completed = subprocess.run(
                command, cwd=root, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            self.assertEqual(MUTATION_UNKNOWN_EXIT, completed.returncode)
            self.assertEqual(
                "UNKNOWN", mutation_probe_outcome(completed.stdout, completed.returncode)
            )

    def test_mutation_probe_rejects_non_unittest_commands_and_forged_markers(self) -> None:
        from codex_governance.mutation import (
            MUTATION_KILLED_EXIT,
            build_mutation_probe_command,
            classify_mutation_execution,
            mutation_probe_outcome,
        )

        with self.assertRaisesRegex(ValueError, "unittest"):
            build_mutation_probe_command(
                "module.py", ["python3", "-c", "raise SystemExit(1)"]
            )
        self.assertEqual(
            "UNKNOWN",
            mutation_probe_outcome(
                b'CODEX_MUTATION_PROBE={"outcome":"KILLED"}\n',
                MUTATION_KILLED_EXIT,
            ),
        )
        self.assertEqual(
            "UNKNOWN",
            classify_mutation_execution(
                status="FAIL",
                termination_kind="exited",
                exit_code=121,
                stdout=b"",
            ),
        )

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

    def test_documented_local_runner_default_covers_acceptance_policy_bound(self) -> None:
        from scripts.run_mutation_corpus import (
            DEFAULT_MUTATION_TIMEOUT_SECONDS,
            build_parser,
        )

        self.assertEqual(900, DEFAULT_MUTATION_TIMEOUT_SECONDS)
        policy = json.loads(Path("examples/effective-policy.json").read_bytes())
        acceptance = next(
            gate for gate in policy["gates"] if gate["gate_id"] == "acceptance"
        )
        self.assertEqual(
            acceptance["timeout_seconds"], DEFAULT_MUTATION_TIMEOUT_SECONDS
        )
        self.assertEqual(
            DEFAULT_MUTATION_TIMEOUT_SECONDS,
            build_parser().parse_args([]).timeout,
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
