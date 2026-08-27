import tempfile
import unittest
from pathlib import Path

from codex_governance.artifacts import ArtifactSafetyError, FilesystemArtifactStore


class ArtifactStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name) / "repository"
        self.repository.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def store(self, *, max_bytes: int = 32) -> FilesystemArtifactStore:
        return FilesystemArtifactStore(
            repository=self.repository,
            root=Path("evidence"),
            max_bytes=max_bytes,
        )

    def test_atomic_immutable_write_read_and_rehash(self) -> None:
        store = self.store()
        digest = store.write_bytes("candidate/result.json", b"{}")
        self.assertEqual(b"{}", store.read_bytes("candidate/result.json", expected_sha256=digest))
        self.assertTrue(store.verify("candidate/result.json", digest))
        with self.assertRaises(FileExistsError):
            store.write_bytes("candidate/result.json", b"changed")
        (self.repository / "evidence/candidate/result.json").write_bytes(b"tampered")
        self.assertFalse(store.verify("candidate/result.json", digest))

    def test_bounds_traversal_and_repository_root_are_rejected(self) -> None:
        store = self.store(max_bytes=2)
        with self.assertRaises(ArtifactSafetyError):
            store.write_bytes("large.bin", b"123")
        for path in ("../escape", "/absolute", "nested/../../escape", "windows\\escape"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                store.write_bytes(path, b"x")
        with self.assertRaises(ArtifactSafetyError):
            FilesystemArtifactStore(repository=self.repository, root=Path("."))

    def test_symlink_root_parent_and_leaf_are_rejected(self) -> None:
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (self.repository / "linked-root").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ArtifactSafetyError):
            FilesystemArtifactStore(repository=self.repository, root=Path("linked-root"))

        store = self.store()
        (self.repository / "evidence").mkdir()
        (self.repository / "evidence/linked-parent").symlink_to(
            outside, target_is_directory=True
        )
        with self.assertRaises(ArtifactSafetyError):
            store.write_bytes("linked-parent/result.json", b"{}")
        (self.repository / "evidence/leaf").symlink_to(outside / "target")
        with self.assertRaises(ArtifactSafetyError):
            store.write_bytes("leaf", b"{}", overwrite=True)


if __name__ == "__main__":
    unittest.main()
