"""Packing and unpacking archives. No GnuPG here: tests/test_gpg_integration.py encrypts them for real."""

import hashlib
import io
import os
import random
import shutil
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mindyourownbytes import archive


class Stop(Exception):
    pass


def never() -> None:
    pass


class ArchiveCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="myobtest")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()

    def write(self, name: str, content: bytes = b"private") -> Path:
        path = self.root / "originals" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def zip_of(self, entries, comment=archive.MARKER, name="hand-made.zip") -> Path:
        """A zip written entry by entry, including names this app would never write."""
        path = self.root / name
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as made:
            for entry, content in entries:
                made.writestr(entry, content)
            made.comment = comment
        return path

    def unpack(self, path: Path, stop=never):
        leftovers: list[Path] = []
        target = self.root / "restored" / "Archive"
        target.parent.mkdir(exist_ok=True)
        try:
            return archive.unpack(path, target, stop, leftovers), target, leftovers
        finally:
            self.assertEqual(leftovers, [])

    def assert_nothing_unpacked(self) -> None:
        folder = self.root / "restored"
        left = list(folder.iterdir()) if folder.exists() else []
        self.assertEqual(left, [], "a refused archive must leave nothing behind")


class NameTests(unittest.TestCase):
    def test_a_good_name_is_kept_without_its_extensions(self):
        for typed, kept in (("Taxes 2026", "Taxes 2026"), ("  Archive  ", "Archive"), ("Photos.zip", "Photos"),
                            ("Photos.zip.gpg", "Photos"), ("Photos.ZIP.GPG", "Photos"), ("Ελληνικά", "Ελληνικά"),
                            ("v1.2 notes", "v1.2 notes")):
            with self.subTest(typed):
                self.assertEqual(archive.check_name(typed), kept)

    def test_names_that_are_paths_or_that_windows_refuses_are_refused(self):
        for typed in ("", "   ", ".zip", "..", "../Startup", "a/b", "a\\b", "C:evil", "what?", "pipe|", "CON",
                      "nul.txt", "com1", "LPT9.txt", "ends with a dot.", ".hidden", "tab\there", "x" * 101):
            with self.subTest(typed), self.assertRaises(ValueError):
                archive.check_name(typed)

    def test_names_inside_never_repeat_even_when_only_their_case_differs(self):
        names = archive.member_names(["Docs/a.txt", "Docs/a.txt", "docs/A.TXT", "Docs/b", "Docs/b", "c.tar.gz"])
        self.assertEqual(names, ["Docs/a.txt", "Docs/a (2).txt", "Docs/A (3).TXT", "Docs/b", "Docs/b (2)",
                                 "c.tar.gz"])

    def test_a_file_and_a_folder_with_the_same_name_both_fit(self):
        # Regression: a file called "docs" and a folder called "docs" went in under clashing names, so
        # the archive couldn't be unpacked. Everything in a renamed folder moves with it.
        self.assertEqual(archive.member_names(["docs", "docs/inside.txt", "Docs/sub/deeper.txt", "docs (2)"]),
                         ["docs", "docs (2)/inside.txt", "docs (2)/sub/deeper.txt", "docs (2) (2)"])
        self.assertEqual(archive.member_names(["docs/inside.txt", "DOCS", "a/b", "a/b/c.txt"]),
                         ["docs/inside.txt", "DOCS (2)", "a/b", "a/b (2)/c.txt"])

    def test_names_that_windows_cant_use_are_made_usable(self):
        # Linux and macOS allow them, but no archive holding them could be unpacked.
        names = archive.member_names(["a:b?.txt", "CON.txt", "ends with a dot.", "x/nul", "tab\there", "a_b_.txt"])
        self.assertEqual(names, ["a_b_.txt", "_CON.txt", "ends with a dot._", "x/_nul", "tab_here", "a_b_ (2).txt"])

    def test_any_list_of_names_can_be_unpacked_side_by_side(self):
        pick = random.Random(5)
        pieces = ["a", "A", "b", "a.txt", "A.TXT", "a (2)", "a (2).txt", "b?"]
        for _ in range(500):
            relatives = ["/".join(pick.choice(pieces) for _ in range(pick.randint(1, 3)))
                         for _ in range(pick.randint(1, 8))]
            names = archive.member_names(relatives)
            keys = [tuple(part.casefold() for part in name.split("/")) for name in names]
            folders = {key[:depth] for key in keys for depth in range(1, len(key))}
            self.assertEqual(len(set(keys)), len(keys), relatives)
            self.assertFalse(set(keys) & folders, relatives)
            self.assertEqual([len(key) for key in keys], [relative.count("/") + 1 for relative in relatives])
            self.assertTrue(all(archive.is_safe_name_part(part) for name in names for part in name.split("/")))


class PackTests(ArchiveCase):
    def pack(self, files, stop=never, on_file=None):
        target = io.BytesIO()
        digest, states = archive.pack(files, target, stop, on_file)
        return target.getvalue(), digest, states

    def test_makes_an_ordinary_zip_that_says_it_came_from_this_app(self):
        first = self.write("Taxes/return.pdf", os.urandom(50_000))
        second = self.write("Taxes/Τεστ résumé.txt", b"")
        data, digest, states = self.pack([(first, "Taxes/return.pdf"), (second, "Taxes/Τεστ résumé.txt")])
        self.assertEqual(digest, hashlib.sha256(data).digest(), "the hash must cover exactly what was written")
        with zipfile.ZipFile(io.BytesIO(data)) as made:
            self.assertEqual(made.comment, archive.MARKER)
            self.assertEqual(made.namelist(), ["Taxes/return.pdf", "Taxes/Τεστ résumé.txt"])
            self.assertEqual(made.read("Taxes/return.pdf"), first.read_bytes())
            self.assertEqual(made.read("Taxes/Τεστ résumé.txt"), b"")
            self.assertEqual({info.compress_type for info in made.infolist()}, {zipfile.ZIP_DEFLATED})
            self.assertIsNone(made.testzip())
        self.assertEqual([(name, source) for name, source, _ in states],
                         [("Taxes/return.pdf", first), ("Taxes/Τεστ résumé.txt", second)])
        self.assertEqual(states[0][2], archive.file_state(first))

    def test_keeps_each_files_time(self):
        original = self.write("a.txt")
        os.utime(original, (1_700_000_000, 1_700_000_000))
        data, _, _ = self.pack([(original, "a.txt")])
        with zipfile.ZipFile(io.BytesIO(data)) as made:
            self.assertEqual(made.getinfo("a.txt").date_time[:3], time.localtime(1_700_000_000)[:3])

    def test_reports_each_file_as_it_goes_in(self):
        files = [(self.write(f"{n}.txt"), f"{n}.txt") for n in range(3)]
        seen = []
        self.pack(files, on_file=seen.append)
        self.assertEqual(seen, [0, 1, 2])

    def test_a_missing_original_says_so(self):
        with self.assertRaisesRegex(archive.ArchiveError, "^The original is gone: gone.txt"):
            self.pack([(self.root / "gone.txt", "gone.txt")])

    def test_an_original_that_fails_to_read_says_so(self):
        original = self.write("a.txt")

        class Failing(io.BytesIO):
            def read(self, *_args):
                raise OSError(5, "Input/output error")

        with patch("mindyourownbytes.archive.open", return_value=Failing(), create=True), \
                self.assertRaisesRegex(archive.ArchiveError, "a.txt couldn't be read"):
            self.pack([(original, "a.txt")])

    def test_stop_stops_it(self):
        original = self.write("big.bin", os.urandom(3 * 1024 * 1024))
        calls = []

        def stop_after_a_few():
            calls.append(1)
            if len(calls) > 3:
                raise Stop()

        with self.assertRaises(Stop):
            self.pack([(original, "big.bin")], stop=stop_after_a_few)

    def test_a_target_that_stops_taking_data_is_reported_as_such(self):
        class Closing(io.RawIOBase):
            def writable(self):
                return True

            def write(self, data):
                raise BrokenPipeError(32, "Broken pipe")

        with self.assertRaises(archive.OutputClosed):
            archive.pack([(self.write("a.txt"), "a.txt")], Closing(), never)


class UnpackTests(ArchiveCase):
    def test_unpacks_into_the_folder_with_the_same_contents_and_times(self):
        files = {"Taxes/return.pdf": os.urandom(40_000), "Taxes/Τεστ/résumé.txt": b"hello\r\n", "empty.txt": b""}
        sources = []
        for name, content in files.items():
            path = self.write(name, content)
            os.utime(path, (1_700_000_000, 1_700_000_000))
            sources.append((path, name))
        packed = self.root / "made.zip"
        with packed.open("wb") as target:
            archive.pack(sources, target, never)
        self.assertTrue(archive.is_archive(packed))
        count, folder, _ = self.unpack(packed)
        self.assertEqual(count, 3)
        self.assertEqual({p.relative_to(folder).as_posix(): p.read_bytes() for p in folder.rglob("*") if p.is_file()},
                         files)
        self.assertEqual(int((folder / "empty.txt").stat().st_mtime) // 2, 1_700_000_000 // 2)
        self.assertEqual([p.name for p in (self.root / "restored").iterdir()], ["Archive"])

    def test_only_zips_from_this_app_count_as_archives(self):
        self.assertFalse(archive.is_archive(self.zip_of([("a.txt", b"x")], comment=b"")))
        self.assertFalse(archive.is_archive(self.zip_of([("a.txt", b"x")], comment=b"something else")))
        not_a_zip = self.root / "plain.zip"
        not_a_zip.write_bytes(b"just text")
        self.assertFalse(archive.is_archive(not_a_zip))
        self.assertFalse(archive.is_archive(self.root / "missing.zip"))

    def test_names_that_could_escape_or_that_windows_refuses_unpack_nothing(self):
        for bad in ("../escaped.txt", "a/../../escaped.txt", "/absolute.txt", "C:/drive.txt", "a\\..\\b.txt",
                    "CON", "folder/nul.txt", "trailing dot.", "trailing space /a.txt", "a//b.txt", "what?.txt",
                    "./here.txt", "tab\there.txt"):
            with self.subTest(bad):
                packed = self.zip_of([("fine.txt", b"x"), (bad, b"evil")], name="bad.zip")
                with self.assertRaisesRegex(archive.ArchiveError, "nothing was unpacked"):
                    self.unpack(packed)
                self.assert_nothing_unpacked()
                self.assertFalse((self.root.parent / "escaped.txt").exists())
                self.assertFalse((self.root / "escaped.txt").exists())

    def test_names_that_clash_are_numbered_so_that_everything_comes_out(self):
        # Archives made before names were kept apart can hold the same name twice, or a file and a folder
        # with the same name. Refusing them would keep everything in them out of reach.
        for entries, expected in (
            ([("a.txt", b"1"), ("A.TXT", b"2")], {"a.txt": b"1", "A (2).TXT": b"2"}),
            ([("a", b"file"), ("a/b.txt", b"inside")], {"a": b"file", "a (2)/b.txt": b"inside"}),
            ([("a/b.txt", b"inside"), ("a", b"file")], {"a/b.txt": b"inside", "a (2)": b"file"}),
            ([("a/", b""), ("a", b"file")], {"a (2)": b"file"}),
        ):
            with self.subTest(entries):
                count, folder, _ = self.unpack(self.zip_of(entries, name="clashing.zip"))
                self.assertEqual(count, len(expected))
                self.assertEqual({p.relative_to(folder).as_posix(): p.read_bytes() for p in folder.rglob("*")
                                  if p.is_file()}, expected)
                shutil.rmtree(self.root / "restored")

    def test_folders_listed_on_their_own_are_made(self):
        count, folder, _ = self.unpack(self.zip_of([("empty folder/", b""), ("a/b.txt", b"x")]))
        self.assertEqual(count, 1)
        self.assertTrue((folder / "empty folder").is_dir())

    def test_features_this_app_never_writes_unpack_nothing(self):
        path = self.root / "bzip2.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_BZIP2) as made:
            made.writestr("a.txt", b"x")
            made.comment = archive.MARKER
        with self.assertRaisesRegex(archive.ArchiveError, "feature this app never writes"):
            self.unpack(path)
        self.assert_nothing_unpacked()

    def test_damage_inside_unpacks_nothing(self):
        packed = self.zip_of([("first.txt", b"fine"), ("second.bin", os.urandom(20_000))])
        data = bytearray(packed.read_bytes())
        start = data.find(b"second.bin") + 200  # Inside the second file's data, past its header.
        data[start] ^= 0xFF
        packed.write_bytes(bytes(data))
        with self.assertRaisesRegex(archive.ArchiveError, "damaged"):
            self.unpack(packed)
        self.assert_nothing_unpacked()

    def test_not_enough_space_unpacks_nothing(self):
        packed = self.zip_of([("big.bin", bytes(5_000_000))])
        little = SimpleNamespace(total=10**9, used=10**9, free=1_000_000)
        with patch("mindyourownbytes.archive.shutil.disk_usage", return_value=little), \
                self.assertRaisesRegex(archive.ArchiveError, "enough space"):
            self.unpack(packed)
        self.assert_nothing_unpacked()

    def test_stopping_partway_leaves_nothing(self):
        packed = self.zip_of([(f"{n}.bin", os.urandom(1000)) for n in range(5)])
        calls = []

        def stop_on_the_third():
            calls.append(1)
            if len(calls) >= 3:
                raise Stop()

        with self.assertRaises(Stop):
            self.unpack(packed, stop=stop_on_the_third)
        self.assert_nothing_unpacked()

    def test_a_folder_that_cant_be_removed_is_reported(self):
        packed = self.zip_of([("a.txt", b"x"), ("../evil", b"x")])
        leftovers: list[Path] = []
        target = self.root / "restored" / "Archive"
        target.parent.mkdir()
        # Refused before anything is written, so there's nothing to leave behind.
        with self.assertRaises(archive.ArchiveError):
            archive.unpack(packed, target, never, leftovers)
        self.assertEqual(leftovers, [])
        good = self.zip_of([("a.txt", b"x"), ("b.txt", b"y")], name="good.zip")
        # Publishing is safefs's job, through a different call on each system, so it's stood in for there.
        with patch("mindyourownbytes.safefs.publish_directory", side_effect=OSError(13, "denied")), \
                patch("mindyourownbytes.archive.shutil.rmtree"), self.assertRaises(archive.ArchiveError):
            archive.unpack(good, target, never, leftovers)
        self.assertEqual(len(leftovers), 1)
        self.assertTrue(leftovers[0].name.startswith(".myob-"))

    def test_an_existing_folder_is_never_written_into(self):
        target = self.root / "restored" / "Archive"
        target.mkdir(parents=True)
        (target / "keep.txt").write_bytes(b"mine")
        leftovers: list[Path] = []
        with self.assertRaises(archive.ArchiveError):
            archive.unpack(self.zip_of([("a.txt", b"x")]), target, never, leftovers)
        self.assertEqual([p.name for p in target.iterdir()], ["keep.txt"])
        self.assertEqual([p.name for p in target.parent.iterdir()], ["Archive"])


if __name__ == "__main__":
    unittest.main()
