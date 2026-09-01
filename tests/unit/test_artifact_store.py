import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

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
        (outside / "target").write_bytes(b"{}")
        (self.repository / "evidence/leaf").symlink_to(outside / "target")
        with self.assertRaises(ArtifactSafetyError):
            store.write_bytes("leaf", b"{}", overwrite=True)

    def test_missing_secure_directory_capability_blocks_io(self) -> None:
        store = self.store()
        (self.repository / "evidence").mkdir()
        (self.repository / "evidence/existing.json").write_bytes(b"{}")
        with patch.object(
            FilesystemArtifactStore, "_secure_dir_fd_available", return_value=False
        ):
            with self.assertRaisesRegex(ArtifactSafetyError, "unavailable"):
                store.write_bytes("new.json", b"{}")
            with self.assertRaisesRegex(ArtifactSafetyError, "unavailable"):
                store.read_bytes("existing.json")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO contract is unavailable")
    def test_fifo_leaf_is_rejected_without_blocking(self) -> None:
        store = self.store()
        (self.repository / "evidence").mkdir()
        os.mkfifo(self.repository / "evidence/fifo")
        started = time.monotonic()
        with self.assertRaises(ArtifactSafetyError):
            store.read_bytes("fifo")
        with self.assertRaises(ArtifactSafetyError):
            store.write_bytes("fifo", b"{}")
        self.assertLess(time.monotonic() - started, 0.5)

    def test_parent_replacement_cannot_redirect_publication(self) -> None:
        if not FilesystemArtifactStore._secure_dir_fd_available():
            with self.assertRaisesRegex(ArtifactSafetyError, "unavailable"):
                self.store().write_bytes("candidate/result.json", b"{}")
            return
        store = self.store()
        parent = self.repository / "evidence/candidate"
        parent.mkdir(parents=True)
        moved = self.repository / "evidence/original-parent"
        outside = Path(self.temporary.name) / "outside-publication"
        outside.mkdir()
        real_open = os.open
        swapped = False

        def replace_parent(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swapped
            if (
                not swapped
                and dir_fd is not None
                and isinstance(path, str)
                and path.startswith(".result.json.tmp-")
                and flags & os.O_EXCL
            ):
                parent.rename(moved)
                parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with (
            patch.object(
                FilesystemArtifactStore,
                "_secure_dir_fd_available",
                return_value=True,
            ),
            patch("codex_governance.artifacts.os.open", side_effect=replace_parent),
        ):
            with self.assertRaises(ArtifactSafetyError):
                store.write_bytes("candidate/result.json", b"{}")
        self.assertTrue(swapped)
        self.assertEqual([], list(outside.iterdir()))
        self.assertFalse((moved / "result.json").exists())


if __name__ == "__main__":
    unittest.main()
