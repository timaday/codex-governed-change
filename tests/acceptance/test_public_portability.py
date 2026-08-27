import unittest
import tomllib
from pathlib import Path


class PublicPortabilityAcceptanceTest(unittest.TestCase):
    def repository_text(self):
        excluded = {".git", "artifacts", "__pycache__", "build", "dist"}
        suffixes = {".md", ".py", ".json", ".toml", ".yaml", ".yml", ".txt", ".example"}
        for path in Path(".").rglob("*"):
            if not path.is_file() or any(part in excluded for part in path.parts):
                continue
            if path.suffix.lower() in suffixes or path.name in {"CODEOWNERS", ".gitignore"}:
                yield path, path.read_text(encoding="utf-8")

    def test_no_developer_machine_paths_hosts_or_local_endpoints_are_committed(self) -> None:
        forbidden = (
            "/" + "home" + "/",
            "/" + "Users" + "/",
            "C:" + "\\" + "Users" + "\\",
            "/" + "tmp" + "/",
            "127.0.0." + "1",
            "local" + "host",
            "file:" + "//",
        )
        for path, text in self.repository_text():
            for marker in forbidden:
                with self.subTest(path=path, marker=marker):
                    self.assertNotIn(marker, text)

    def test_runtime_has_no_hivegate_or_non_standard_python_dependency(self) -> None:
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
        source = "\n".join(path.read_text(encoding="utf-8") for path in Path("src").rglob("*.py"))
        self.assertNotIn("hive" + "gate", pyproject.lower())
        self.assertNotIn("import hive" + "gate", source.lower())
        self.assertNotIn("from hive" + "gate", source.lower())
        self.assertEqual([], tomllib.loads(pyproject)["project"].get("dependencies"))

    def test_public_examples_use_repository_relative_paths(self) -> None:
        from codex_governance.canonical import normalize_repo_path

        for value in (
            "artifacts/governance", "docs/requirements.md",
            "tests/acceptance/test_public_portability.py",
        ):
            self.assertEqual(value, normalize_repo_path(value))


if __name__ == "__main__":
    unittest.main()
