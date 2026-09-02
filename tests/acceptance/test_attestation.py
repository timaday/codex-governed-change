import tempfile
import unittest
import shutil
from copy import deepcopy
from pathlib import Path

from codex_governance.artifacts import FilesystemArtifactStore
from codex_governance.canonical import canonical_json_bytes


class AttestationAcceptanceTest(unittest.TestCase):
    REPOSITORY = "repo:example/project"
    CANDIDATE = "sha256:" + "a" * 64

    def test_producer_identity_covers_the_complete_framed_package(self) -> None:
        from codex_governance.attestation import (
            gate_implementation_sha256,
            mutation_implementation_sha256,
            producer_implementation_manifest,
        )

        source = Path("src/codex_governance")
        expected_paths = sorted(
            path.relative_to(source).as_posix() for path in source.rglob("*.py")
        )
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "codex_governance"
            shutil.copytree(source, package)
            gate_baseline = gate_implementation_sha256(package)
            mutation_baseline = mutation_implementation_sha256(package)
            self.assertNotEqual(gate_baseline, mutation_baseline)
            manifest = producer_implementation_manifest("gate", package)
            self.assertEqual(
                expected_paths, [item["path"] for item in manifest["files"]]
            )
            self.assertTrue(
                all(set(item) == {"path", "bytes", "sha256"} for item in manifest["files"])
            )
            for relative in expected_paths:
                target = package.joinpath(*relative.split("/"))
                original = target.read_bytes()
                target.write_bytes(original + b"\n# producer identity drift\n")
                with self.subTest(relative=relative):
                    self.assertNotEqual(
                        gate_baseline, gate_implementation_sha256(package)
                    )
                    self.assertNotEqual(
                        mutation_baseline,
                        mutation_implementation_sha256(package),
                    )
                target.write_bytes(original)

    def statement(self) -> dict:
        from codex_governance.attestation import build_provenance_statement

        return build_provenance_statement(
            repository_id=self.REPOSITORY,
            candidate_id=self.CANDIDATE,
            repository_digest="sha256:" + "b" * 64,
            task_contract_sha256="sha256:" + "c" * 64,
            effective_policy_sha256="sha256:" + "d" * 64,
            gate_definition_sha256="sha256:" + "e" * 64,
            reviewer_prompt_sha256="sha256:" + "f" * 64,
            producer={"builder_id": "codex-governed-change", "implementation_sha256": "sha256:" + "1" * 64, "version": "0.1.0"},
            workflow={"system": "local", "run_id": "fixture", "attempt": 1},
            tools=[{"name": "python", "version": "3.12"}],
            environment={"source_identity": "sha256:" + "2" * 64, "execution_identity": "sha256:" + "3" * 64, "sandbox_capability_sha256": "sha256:" + "4" * 64},
            materials=[{"name": "candidate", "sha256": self.CANDIDATE}],
            started_at="2026-08-26T10:00:00Z",
            ended_at="2026-08-26T10:01:00Z",
            result="PASS",
            limits={"timeout_seconds": 60, "max_output_bytes": 1000, "process_limit": 16, "memory_bytes": 1000000, "cpu_seconds": 60},
            artifacts=[{"name": "result", "sha256": "sha256:" + "5" * 64}],
            limitations=["unsigned provenance"],
        )

    def test_statement_is_in_toto_shaped_and_self_id_reconstructs(self) -> None:
        from codex_governance.attestation import verify_provenance_statement

        statement = self.statement()
        self.assertEqual("https://in-toto.io/Statement/v1", statement["_type"])
        self.assertFalse(statement["predicate"]["signed"])
        self.assertTrue(verify_provenance_statement(statement, self.REPOSITORY, self.CANDIDATE))

    def test_cross_repository_or_environment_replay_is_rejected(self) -> None:
        from codex_governance.attestation import verify_provenance_statement

        statement = self.statement()
        self.assertFalse(verify_provenance_statement(statement, "repo:other/project", self.CANDIDATE))
        replay = deepcopy(statement)
        replay["predicate"]["environment"]["execution_identity"] = "sha256:" + "9" * 64
        self.assertFalse(verify_provenance_statement(replay, self.REPOSITORY, self.CANDIDATE))

    def test_repository_subject_digest_is_checked_when_reconstructing_execution(self) -> None:
        from codex_governance.attestation import verify_provenance_statement

        statement = self.statement()
        self.assertTrue(
            verify_provenance_statement(
                statement, self.REPOSITORY, self.CANDIDATE, "sha256:" + "b" * 64
            )
        )
        self.assertFalse(
            verify_provenance_statement(
                statement, self.REPOSITORY, self.CANDIDATE, "sha256:" + "9" * 64
            )
        )

    def test_write_once_store_is_idempotent_but_conflicts_block(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            (repository / "evidence").mkdir()
            store = FilesystemArtifactStore(repository=repository, root=Path("evidence"))
            digest = store.write_bytes("objects/result.json", b"same")
            self.assertEqual(digest, store.write_bytes("objects/result.json", b"same"))
            with self.assertRaises(FileExistsError):
                store.write_bytes("objects/result.json", b"different")

    def test_statement_id_excludes_only_itself(self) -> None:
        from codex_governance.evidence import verify_content_address

        statement = self.statement()
        self.assertTrue(verify_content_address(statement, "statement_id"))
        changed = deepcopy(statement)
        changed["predicate"]["result"] = "UNKNOWN"
        self.assertFalse(verify_content_address(changed, "statement_id"))
        self.assertNotEqual(canonical_json_bytes(statement), canonical_json_bytes(changed))


if __name__ == "__main__":
    unittest.main()
