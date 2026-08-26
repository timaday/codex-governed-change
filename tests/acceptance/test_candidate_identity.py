import unittest

from codex_governance.candidate import candidate_id_from_components


class CandidateIdentityAcceptanceTest(unittest.TestCase):
    def components(self) -> dict:
        return {
            "mode": "working_tree",
            "base_commit": "1" * 40,
            "head_commit": "1" * 40,
            "tracked_diff_sha256": "sha256:" + "2" * 64,
            "untracked_entries": [
                {"path": "src/new.py", "mode": "100644", "sha256": "sha256:" + "3" * 64}
            ],
            "submodules": [],
            "effective_policy_sha256": "sha256:" + "4" * 64,
        }

    def test_identity_is_stable_when_ordered_components_are_equivalent(self) -> None:
        left = self.components()
        left["untracked_entries"].append(
            {"path": "docs/new.md", "mode": "100644", "sha256": "sha256:" + "5" * 64}
        )
        right = self.components()
        right["untracked_entries"].insert(
            0, {"path": "docs/new.md", "mode": "100644", "sha256": "sha256:" + "5" * 64}
        )
        self.assertEqual(candidate_id_from_components(**left), candidate_id_from_components(**right))

    def test_untracked_content_changes_identity(self) -> None:
        before = self.components()
        after = self.components()
        after["untracked_entries"][0]["sha256"] = "sha256:" + "6" * 64
        self.assertNotEqual(candidate_id_from_components(**before), candidate_id_from_components(**after))

    def test_effective_policy_changes_identity(self) -> None:
        before = self.components()
        after = self.components()
        after["effective_policy_sha256"] = "sha256:" + "7" * 64
        self.assertNotEqual(candidate_id_from_components(**before), candidate_id_from_components(**after))

    def test_path_escape_is_rejected(self) -> None:
        values = self.components()
        values["untracked_entries"][0]["path"] = "../escape.py"
        with self.assertRaises(ValueError):
            candidate_id_from_components(**values)


if __name__ == "__main__":
    unittest.main()
