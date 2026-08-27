import unittest


class ContextQualificationAcceptanceTest(unittest.TestCase):
    def test_token_savings_never_promote_a_quality_regression(self) -> None:
        from codex_governance.qualification import context_variant_qualified

        baseline = {"critical_recall": 1.0, "false_passes": 0, "traceability": 1.0, "disposition_correct": True, "tokens": 30000}
        cheaper_bad = {"critical_recall": 0.8, "false_passes": 1, "traceability": 0.9, "disposition_correct": False, "tokens": 5000}
        cheaper_good = {"critical_recall": 1.0, "false_passes": 0, "traceability": 1.0, "disposition_correct": True, "tokens": 12000}
        self.assertFalse(context_variant_qualified(baseline, cheaper_bad))
        self.assertTrue(context_variant_qualified(baseline, cheaper_good))

    def test_efficiency_and_quality_metrics_remain_independent(self) -> None:
        from codex_governance.qualification import validate_context_metrics

        metrics = {
            "input_tokens": 1000, "output_tokens": 100, "cached_tokens": 0,
            "prompt_bytes": 4000, "evidence_bytes": 2000, "retrieval_expansions": 2,
            "latency_ms": 100, "cost": "unavailable", "critical_recall": 1.0,
            "false_passes": 0, "false_blocks": 0, "mutation_kill_rate": 1.0,
            "rst_findings": 1, "traceability": 1.0, "unresolved_unknowns": 0,
        }
        self.assertEqual([], validate_context_metrics(metrics))


if __name__ == "__main__":
    unittest.main()
