import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from codex_governance.candidate import GitCliRepositoryAdapter, candidate_id_from_components
from codex_governance.reviewer import prepare_sanitized_harness


class CandidateIdentityAcceptanceTest(unittest.TestCase):
    def components(self) -> dict:
        return {
            "repository_id": "repo:example/project",
            "mode": "working_tree",
            "base_commit": "1" * 40,
            "head_commit": "1" * 40,
            "tracked_diff_sha256": "sha256:" + "2" * 64,
            "changed_paths": ["src/new.py"],
            "untracked_entries": [
                {"path": "src/new.py", "mode": "100644", "sha256": "sha256:" + "3" * 64}
            ],
            "submodules": [],
            "effective_policy_sha256": "sha256:" + "4" * 64,
        }

    def test_identity_is_stable_when_ordered_components_are_equivalent(self) -> None:
        left = self.components()
        left["changed_paths"].append("docs/new.md")
        left["untracked_entries"].append(
            {"path": "docs/new.md", "mode": "100644", "sha256": "sha256:" + "5" * 64}
        )
        right = self.components()
        right["changed_paths"].insert(0, "docs/new.md")
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

    def test_changed_path_set_changes_identity(self) -> None:
        before = self.components()
        after = self.components()
        after["changed_paths"] = ["schemas/disposition.schema.json", "src/new.py"]
        self.assertNotEqual(candidate_id_from_components(**before), candidate_id_from_components(**after))

    def test_repository_identity_changes_identity(self) -> None:
        before = self.components()
        after = self.components()
        after["repository_id"] = "repo:other/project"
        self.assertNotEqual(candidate_id_from_components(**before), candidate_id_from_components(**after))

    def test_path_escape_is_rejected(self) -> None:
        values = self.components()
        values["untracked_entries"][0]["path"] = "../escape.py"
        with self.assertRaises(ValueError):
            candidate_id_from_components(**values)

    def test_dirty_submodule_and_unmaterialized_reviewer_submodule_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            submodule = root / "submodule-source"
            repository = root / "repository"
            submodule.mkdir()
            repository.mkdir()
            environment = dict(os.environ)
            environment.update(
                GIT_AUTHOR_NAME="fixture",
                GIT_AUTHOR_EMAIL="fixture@example.invalid",
                GIT_COMMITTER_NAME="fixture",
                GIT_COMMITTER_EMAIL="fixture@example.invalid",
            )

            def git(path: Path, *arguments: str) -> bytes:
                return subprocess.run(
                    ["git", "-C", str(path), *arguments],
                    env=environment,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ).stdout

            git(submodule, "init", "-q", "-b", "main")
            (submodule / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
            git(submodule, "add", ".")
            git(submodule, "commit", "-q", "-m", "module")
            git(repository, "init", "-q", "-b", "main")
            (repository / "README.md").write_text("fixture\n", encoding="utf-8")
            git(repository, "add", ".")
            git(repository, "commit", "-q", "-m", "base")
            git(
                repository,
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                str(submodule),
                "module",
            )
            git(repository, "commit", "-q", "-am", "add module")
            base = git(repository, "rev-parse", "HEAD").decode("ascii").strip()
            adapter = GitCliRepositoryAdapter(repository)
            candidate = adapter.identify(
                repository_id="repo:example/submodule-project",
                mode="working_tree",
                base_commit=base,
                head_commit=base,
                effective_policy_sha256="sha256:" + "4" * 64,
                evidence_root="evidence",
            )
            self.assertEqual(["module"], [item["path"] for item in candidate["submodules"]])
            with self.assertRaisesRegex(ValueError, "immutable recursive materialization"):
                prepare_sanitized_harness(
                    candidate_repository=repository,
                    harness_root=root / "harness",
                    fixed_prompt_path=Path(".codex/review/reviewer.prompt.md"),
                    output_schema_path=Path("schemas/reviewer-result.schema.json"),
                    permitted_inputs={"candidate_id": candidate["candidate_id"]},
                    expected_candidate=candidate,
                    evidence_root="evidence",
                )
            (repository / "module/dirty.txt").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "dirty submodule"):
                adapter.identify(
                    repository_id="repo:example/submodule-project",
                    mode="working_tree",
                    base_commit=base,
                    head_commit=base,
                    effective_policy_sha256="sha256:" + "4" * 64,
                    evidence_root="evidence",
                )


if __name__ == "__main__":
    unittest.main()
