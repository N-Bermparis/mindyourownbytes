"""Collections and the library scan. No gpg needed: these only move ciphertext."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from mindyourownbytes.library import (
    create_collection,
    list_collections,
    move_to_collection,
    scan_library,
    validate_collection_name,
)


class LibraryCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="myobtest")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve() / "exports"
        self.root.mkdir()

    def file(self, relative: str, content: bytes = b"ciphertext") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path


class CollectionNameTests(unittest.TestCase):
    def test_accepts_normal_names(self):
        for name in ("Taxes", "Taxes 2026", "Φορολογικά", "client_a-1"):
            self.assertEqual(validate_collection_name(f"  {name} "), name)

    def test_rejects_anything_that_is_not_one_safe_folder(self):
        for name in ("", "   ", "..", ".", "../escape", "..\\escape", "a/b", "a\\b", "C:", "C:\\x", ".hidden",
                     "trailing.", "con", "NUL", "com1.txt", "a?b", "x" * 65, "tab\tname", "<x>"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_collection_name(name)


class ScanTests(LibraryCase):
    def test_finds_encrypted_files_and_their_collections(self):
        self.file("loose.pdf.gpg")
        self.file("Taxes/2026/return.pdf.gpg")
        self.file("Taxes/receipt.PGP")
        entries = {str(entry.relative): entry for entry in scan_library(self.root)}
        self.assertEqual(entries[str(Path("loose.pdf.gpg"))].collection, "")
        self.assertEqual(entries[str(Path("Taxes/2026/return.pdf.gpg"))].collection, "Taxes")
        self.assertEqual(entries[str(Path("Taxes/2026/return.pdf.gpg"))].display_name, "return.pdf")
        self.assertEqual(entries[str(Path("Taxes/receipt.PGP"))].display_name, "receipt")

    def test_ignores_everything_that_is_not_a_finished_encrypted_file(self):
        self.file("notes.txt")
        self.file(".myob-0123456789abcdef.partial")
        self.file("Taxes/plain.pdf")
        self.assertEqual(scan_library(self.root), [])

    def test_missing_root_is_an_empty_library(self):
        self.assertEqual(scan_library(self.root / "nope"), [])
        self.assertEqual(list_collections(self.root / "nope"), [])

    @unittest.skipUnless(os.name == "nt", "Windows junctions")
    def test_does_not_follow_junctions(self):
        outside = self.root.parent / "outside"
        outside.mkdir()
        (outside / "elsewhere.gpg").write_bytes(b"x")
        subprocess.run(["cmd", "/c", "mklink", "/J", str(self.root / "jump"), str(outside)],
                       check=True, capture_output=True)
        self.assertEqual(scan_library(self.root), [])
        self.assertEqual(list_collections(self.root), [])


class CollectionTests(LibraryCase):
    def test_create_and_list_sorted(self):
        create_collection(self.root, "taxes")
        create_collection(self.root, "Archive")
        (self.root / ".hidden").mkdir()
        self.assertEqual(list_collections(self.root), ["Archive", "taxes"])

    def test_create_rejects_traversal(self):
        with self.assertRaises(ValueError):
            create_collection(self.root, "../escape")
        self.assertFalse((self.root.parent / "escape").exists())


class MoveTests(LibraryCase):
    def test_moves_between_collections_keeping_content_and_subfolders(self):
        source = self.file("Old/2026/a.pdf.gpg", b"keep me")
        moved = move_to_collection(self.root, [source], "New")
        self.assertEqual(moved, [self.root / "New" / "2026" / "a.pdf.gpg"])
        self.assertEqual(moved[0].read_bytes(), b"keep me")
        self.assertFalse(source.exists())

    def test_never_overwrites_a_file_already_there(self):
        source = self.file("Old/a.pdf.gpg", b"incoming")
        existing = self.file("New/a.pdf.gpg", b"already here")
        moved = move_to_collection(self.root, [source], "New")
        self.assertEqual(moved[0].name, "a (2).pdf.gpg")
        self.assertEqual(existing.read_bytes(), b"already here")
        self.assertEqual(moved[0].read_bytes(), b"incoming")

    def test_empty_name_moves_out_of_collection(self):
        source = self.file("Old/a.gpg")
        self.assertEqual(move_to_collection(self.root, [source], ""), [self.root / "a.gpg"])

    def test_moving_to_the_current_collection_changes_nothing(self):
        source = self.file("Same/a.gpg", b"unchanged")
        self.assertEqual(move_to_collection(self.root, [source], "Same"), [source])
        self.assertEqual(source.read_bytes(), b"unchanged")

    def test_refuses_files_outside_the_library(self):
        outside = self.root.parent / "outside.gpg"
        outside.write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "not in the library"):
            move_to_collection(self.root, [outside], "New")
        self.assertTrue(outside.exists())

    def test_refuses_traversal_in_the_target(self):
        source = self.file("a.gpg")
        with self.assertRaises(ValueError):
            move_to_collection(self.root, [source], "../../escape")
        self.assertTrue(source.exists())


if __name__ == "__main__":
    unittest.main()
