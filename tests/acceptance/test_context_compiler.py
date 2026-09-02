import os
import subprocess
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from codex_governance.candidate import GitCliRepositoryAdapter, candidate_id_from_components
from codex_governance.canonical import content_address, sha256_bytes
from codex_governance.domain.model import DispositionState


class ContextCompilerAcceptanceTest(unittest.TestCase):
    def qualification(self, profile: str) -> dict:
        return content_address(
            {
                "schema_version": "1.0.0",
                "projection_version": "1.0.0",
                "profile": profile,
                "baseline": {
                    "critical_recall": 1.0, "false_passes": 0,
                    "traceability": 1.0, "disposition_correct": True,
                    "tokens": 30000,
                },
                "candidate": {
                    "critical_recall": 1.0, "false_passes": 0,
                    "traceability": 1.0, "disposition_correct": True,
                    "tokens": 12000,
                },
                "qualified": True,
                "created_at": "2026-08-26T10:00:00Z",
                "limitations": [],
            },
            "qualification_id",
        )

    def qualification_ids(self) -> dict[str, str]:
        return {
            profile: self.qualification(profile)["qualification_id"]
            for profile in ("COMPACT", "STANDARD", "DEEP")
        }

    def candidate(self, changed_paths=None) -> dict:
        changed_paths = changed_paths or ["src/service.py"]
        components = {
            "repository_id": "repo:example/project",
            "mode": "working_tree",
            "base_commit": "1" * 40,
            "head_commit": "1" * 40,
            "tracked_diff_sha256": "sha256:" + "7" * 64,
            "changed_paths": list(changed_paths),
            "untracked_entries": [],
            "submodules": [],
            "effective_policy_sha256": "sha256:" + "c" * 64,
        }
        return {
            "schema_version": "1.0.0",
            **components,
            "candidate_id": candidate_id_from_components(**components),
            "dirty": True,
        }

    def sources(self, changed_paths=None) -> dict:
        digest = lambda character: "sha256:" + character * 64
        candidate = self.candidate(changed_paths)
        return {
            "repository_id": "repo:example/project",
            "candidate_id": candidate["candidate_id"],
            "created_at": "2026-08-26T10:00:00Z",
            "task_authority": {"summary": "authenticated task", "sha256": digest("b")},
            "policy": {"summary": "protected policy", "sha256": digest("c")},
            "repository_inventory": {"summary": "inventory", "sha256": digest("d")},
            "changed_files": list(changed_paths or ["src/service.py"]),
            "affected_closure": sorted(
                {
                    "src/caller.py",
                    "src/service.py",
                    "tests/test_service.py",
                    *(changed_paths or ["src/service.py"]),
                }
            ),
            "gate_results": [{"id": "unit", "status": "PASS", "sha256": digest("e")}],
            "risks": ["authorization regression"],
            "failures": [],
            "conflicts": [],
            "survivors": [],
            "limitations": ["hosted ruleset not observed"],
            "unknowns": [],
            "rubric": {"summary": "fixed rubric", "sha256": digest("f")},
            "disposition_contract": "READY_FOR_HUMAN requires every fixed claim",
            "artifacts": [
                {"reference": "evidence/large.log", "sha256": digest("1"), "bytes": 5000000, "relevant": False},
                {"reference": "evidence/unit.json", "sha256": digest("2"), "bytes": 500, "relevant": True},
            ],
        }

    def compile(self, *, budget: int = 24000, changed_paths=None, **signals):
        from codex_governance.context import compile_context

        changed_paths = changed_paths or ["src/service.py"]
        sources = self.sources(changed_paths)
        if signals.get("gate_failed"):
            sources["gate_results"][0]["status"] = "FAIL"
            sources["failures"] = ["unit gate failed"]
        if signals.get("surviving_mutant"):
            sources["survivors"] = ["MUTANT-AUTH"]
        if signals.get("selector_uncertain"):
            sources["conflicts"] = ["selector uncertainty"]
        profile = "DEEP" if signals or budget == 1 or any(
            path.startswith(("schemas/", "src/codex_governance/context"))
            for path in changed_paths
        ) else "STANDARD"
        return compile_context(
            sources=sources, candidate=self.candidate(changed_paths),
            requested_profile="STANDARD", token_budget=budget,
            changed_paths=changed_paths,
            affected_closure=sources["affected_closure"], model="gpt-5.6-sol",
            reasoning_effort="xhigh",
            context_qualification=self.qualification(profile),
            protected_qualification_ids=self.qualification_ids(),
        )

    def test_identical_inputs_produce_identical_projection_and_source_receipts(self) -> None:
        left = self.compile()
        right = self.compile()
        self.assertEqual(left["projection"], right["projection"])
        self.assertEqual(left["receipt"]["source_sha256"], right["receipt"]["source_sha256"])
        self.assertEqual(left["receipt"]["projection_sha256"], right["receipt"]["projection_sha256"])

    def test_assurance_kernel_and_independent_affected_test_closure_are_non_droppable(self) -> None:
        compiled = self.compile()
        kernel = compiled["projection"]["assurance_kernel"]
        for field in (
            "task_authority", "policy", "repository_id", "candidate_id",
            "changed_files", "affected_closure", "gate_results", "risks",
            "failures", "conflicts", "survivors", "limitations", "unknowns",
            "rubric", "disposition_contract",
        ):
            self.assertIn(field, kernel)
        self.assertIn("src/caller.py", kernel["affected_closure"])
        self.assertIn("tests/test_service.py", kernel["affected_closure"])

    def test_irrelevant_large_artifact_is_omitted_initially_but_retrievable(self) -> None:
        compiled = self.compile()
        rendered = str(compiled["projection"])
        self.assertNotIn("5000000", rendered)
        excluded = {item["reference"]: item["reason"] for item in compiled["receipt"]["excluded_sources"]}
        self.assertEqual("available_by_retrieval", excluded["evidence/large.log"])
        self.assertIn("evidence/large.log", compiled["retrieval_index"])

    def test_failures_survivors_limitations_and_unknowns_survive_compression(self) -> None:
        sources = self.sources()
        sources["failures"] = ["security gate failed"]
        sources["survivors"] = ["MUTANT-AUTH"]
        sources["unknowns"] = ["reviewer evidence unavailable"]
        from codex_governance.context import compile_context

        compiled = compile_context(
            sources=sources, candidate=self.candidate(),
            requested_profile="COMPACT", token_budget=24000,
            changed_paths=["src/service.py"],
            affected_closure=sources["affected_closure"],
            model="gpt-5.6-sol", reasoning_effort="xhigh",
            context_qualification=self.qualification("DEEP"),
            protected_qualification_ids=self.qualification_ids(),
        )
        kernel = compiled["projection"]["assurance_kernel"]
        self.assertEqual(["security gate failed"], kernel["failures"])
        self.assertEqual(["MUTANT-AUTH"], kernel["survivors"])
        self.assertTrue(kernel["limitations"])
        self.assertTrue(kernel["unknowns"])

    def test_high_risk_or_selector_uncertainty_automatically_selects_deep(self) -> None:
        for changed, signals in (
            (["schemas/authority.schema.json"], {}),
            (["src/service.py"], {"selector_uncertain": True}),
            (["src/service.py"], {"gate_failed": True}),
            (["src/service.py"], {"surviving_mutant": True}),
        ):
            with self.subTest(changed=changed, signals=signals):
                self.assertEqual("DEEP", self.compile(changed_paths=changed, **signals)["receipt"]["profile"])

    def test_insufficient_kernel_budget_blocks_without_truncation(self) -> None:
        compiled = self.compile(budget=1)
        self.assertEqual("CONTEXT_BUDGET_INSUFFICIENT", compiled["receipt"]["truncation_status"])
        self.assertEqual(DispositionState.UNKNOWN, compiled["state"])

    def test_unchanged_evidence_is_referenced_not_duplicated(self) -> None:
        compiled = self.compile()
        references = {item["reference"] for item in compiled["receipt"]["excluded_sources"]}
        self.assertIn("evidence/large.log", references)
        self.assertNotIn("complete_artifact_bytes", str(compiled["projection"]))

    def test_profiles_change_optional_projection_without_dropping_kernel(self) -> None:
        from codex_governance.context import compile_context

        sources = self.sources()
        sources["artifacts"][1].update(summary={"status": "PASS"}, excerpt="bounded")
        compact = compile_context(
            sources=sources, candidate=self.candidate(),
            requested_profile="COMPACT", token_budget=64000,
            changed_paths=["src/service.py"],
            affected_closure=sources["affected_closure"],
            model="gpt-5.6-sol", reasoning_effort="xhigh",
            context_qualification=self.qualification("COMPACT"),
            protected_qualification_ids=self.qualification_ids(),
        )
        standard = compile_context(
            sources=sources, candidate=self.candidate(),
            requested_profile="STANDARD", token_budget=64000,
            changed_paths=["src/service.py"],
            affected_closure=sources["affected_closure"],
            model="gpt-5.6-sol", reasoning_effort="xhigh",
            context_qualification=self.qualification("STANDARD"),
            protected_qualification_ids=self.qualification_ids(),
        )
        self.assertNotIn("typed_summary", compact["projection"]["evidence_index"][0])
        self.assertIn("typed_summary", standard["projection"]["evidence_index"][0])
        self.assertEqual(
            compact["projection"]["assurance_kernel"],
            standard["projection"]["assurance_kernel"],
        )

    def test_duplicate_content_and_retrieval_expansion_are_receipted(self) -> None:
        from codex_governance.context import compile_context, record_retrieval_expansion

        sources = self.sources()
        sources["artifacts"].append(
            {"reference": "evidence/copy.log", "sha256": "sha256:" + "1" * 64,
             "bytes": 5000000, "relevant": False}
        )
        compiled = compile_context(
            sources=sources, candidate=self.candidate(),
            requested_profile="STANDARD", token_budget=64000,
            changed_paths=["src/service.py"],
            affected_closure=sources["affected_closure"],
            model="gpt-5.6-sol", reasoning_effort="xhigh",
            context_qualification=self.qualification("STANDARD"),
            protected_qualification_ids=self.qualification_ids(),
        )
        reasons = {item["reference"]: item["reason"] for item in compiled["receipt"]["excluded_sources"]}
        self.assertEqual("duplicate", reasons["evidence/copy.log"])
        expanded = record_retrieval_expansion(
            receipt=compiled["receipt"], retrieval_index=compiled["retrieval_index"],
            reference="evidence/large.log", level="complete_artifact",
            reason="inspect the complete failing output",
        )
        self.assertNotEqual(compiled["receipt"]["receipt_id"], expanded["receipt_id"])
        self.assertEqual("evidence/large.log", expanded["retrieval_expansions"][0]["reference"])

    def test_author_chat_and_persisted_reasoning_are_rejected_sources(self) -> None:
        from codex_governance.context import compile_context

        for forbidden in ("author_conversation", "author_hidden_reasoning", "persisted_reasoning"):
            sources = deepcopy(self.sources())
            sources[forbidden] = "must not cross boundary"
            with self.subTest(forbidden=forbidden), self.assertRaises(ValueError):
                compile_context(
                    sources=sources, candidate=self.candidate(),
                    requested_profile="DEEP", token_budget=64000,
                    changed_paths=["src/service.py"],
                    affected_closure=sources["affected_closure"],
                    model="gpt-5.6-sol", reasoning_effort="xhigh",
                    context_qualification=self.qualification("DEEP"),
                    protected_qualification_ids=self.qualification_ids(),
                )

    def test_changed_file_inventory_and_selector_are_exact_candidate_derived(self) -> None:
        from codex_governance.context import compile_context

        for source_paths, selector_paths in (
            (["src/"], ["src/service.py"]),
            ([], ["src/service.py"]),
            (["src/service.py", "tests/extra.py"], ["src/service.py"]),
            (["src/service.py"], ["src/"]),
        ):
            sources = self.sources()
            sources["changed_files"] = source_paths
            with self.subTest(source_paths=source_paths, selector_paths=selector_paths):
                with self.assertRaisesRegex(ValueError, "exactly match"):
                    compile_context(
                        sources=sources,
                        candidate=self.candidate(),
                        requested_profile="STANDARD",
                        token_budget=24000,
                        changed_paths=selector_paths,
                        affected_closure=sources["affected_closure"],
                        model="gpt-5.6-sol",
                        reasoning_effort="xhigh",
                        context_qualification=self.qualification("STANDARD"),
                        protected_qualification_ids=self.qualification_ids(),
                    )

    def test_profile_version_metrics_and_protected_qualification_must_match(self) -> None:
        from codex_governance.context import compile_context

        for defect in ("profile", "version", "regression", "protected-id"):
            qualification = self.qualification("STANDARD")
            protected_ids = self.qualification_ids()
            if defect == "profile":
                qualification["profile"] = "COMPACT"
                qualification = content_address(qualification, "qualification_id")
            elif defect == "version":
                qualification["projection_version"] = "2.0.0"
                qualification = content_address(qualification, "qualification_id")
            elif defect == "regression":
                qualification["candidate"]["critical_recall"] = 0.5
                qualification = content_address(qualification, "qualification_id")
            else:
                protected_ids["STANDARD"] = "sha256:" + "0" * 64
            sources = self.sources()
            with self.subTest(defect=defect), self.assertRaisesRegex(
                ValueError, "qualification is unavailable"
            ):
                compile_context(
                    sources=sources,
                    candidate=self.candidate(),
                    requested_profile="STANDARD",
                    token_budget=64000,
                    changed_paths=["src/service.py"],
                    affected_closure=sources["affected_closure"],
                    model="gpt-5.6-sol",
                    reasoning_effort="xhigh",
                    context_qualification=qualification,
                    protected_qualification_ids=protected_ids,
                )

    def test_protected_closure_includes_unchanged_caller_and_test_and_rejects_omission(self) -> None:
        from codex_governance.context import compile_context

        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
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
            adapter = GitCliRepositoryAdapter(repository)
            candidate = adapter.identify(
                repository_id="repo:example/project",
                mode="working_tree",
                base_commit=base,
                head_commit=base,
                effective_policy_sha256="sha256:" + "c" * 64,
                evidence_root="artifacts/governance",
            )
            closure = adapter.conservative_affected_closure(
                candidate=candidate, evidence_root="artifacts/governance"
            )
            self.assertIn("src/caller.py", closure)
            self.assertIn("tests/test_service.py", closure)

            sources = self.sources(candidate["changed_paths"])
            sources["candidate_id"] = candidate["candidate_id"]
            sources["affected_closure"] = ["src/service.py"]
            sources["repository_inventory"]["sha256"] = sha256_bytes(
                "\n".join(closure).encode("utf-8")
            )
            with self.assertRaisesRegex(ValueError, "protected repository derivation"):
                compile_context(
                    sources=sources,
                    candidate=candidate,
                    requested_profile="STANDARD",
                    token_budget=24000,
                    changed_paths=candidate["changed_paths"],
                    affected_closure=closure,
                    model="gpt-5.6-sol",
                    reasoning_effort="xhigh",
                    context_qualification=self.qualification("STANDARD"),
                    protected_qualification_ids=self.qualification_ids(),
                )

    def test_post_run_receipt_is_separate_exact_and_fail_closed_on_missing_usage(self) -> None:
        from codex_governance.canonical import sha256_canonical
        from codex_governance.context import finalize_context_receipt

        prepared = self.compile()["receipt"]
        original = deepcopy(prepared)
        output_sha = "sha256:" + "9" * 64
        expansion = {
            "reference": "evidence/large.log",
            "sha256": "sha256:" + "1" * 64,
            "level": "complete_artifact",
            "reason": "inspect complete evidence",
        }
        completed = finalize_context_receipt(
            prepared,
            review_mode="conformance",
            reviewer_output_sha256=output_sha,
            retrieval_expansions=[expansion],
            usage_observed=True,
            actual_input_tokens=120,
            actual_output_tokens=30,
            cached_input_tokens=40,
            reasoning_output_tokens=10,
            latency_ms=500,
            cost="unavailable",
            created_at="2026-08-26T10:01:00Z",
        )
        self.assertEqual(original, prepared)
        self.assertEqual(sha256_canonical(prepared), completed["input_context_receipt_sha256"])
        self.assertEqual(output_sha, completed["reviewer_output_sha256"])
        self.assertEqual([expansion], completed["retrieval_expansions"])
        self.assertTrue(completed["usage_observed"])

        unavailable = finalize_context_receipt(
            prepared,
            review_mode="conformance",
            reviewer_output_sha256=output_sha,
            retrieval_expansions=[],
            usage_observed=False,
            actual_input_tokens=0,
            actual_output_tokens=0,
            cached_input_tokens=0,
            reasoning_output_tokens=0,
            latency_ms=500,
            cost="unavailable",
            created_at="2026-08-26T10:01:00Z",
            limitations=["Codex JSONL usage unavailable"],
        )
        self.assertFalse(unavailable["usage_observed"])
        self.assertNotEqual(completed["execution_receipt_id"], unavailable["execution_receipt_id"])


if __name__ == "__main__":
    unittest.main()
