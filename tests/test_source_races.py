"""Swapping an original for something else while it's being encrypted, by each route that matters.

Someone who can write to the folder a file is encrypted from could replace it, between it being chosen
and being read, with a link to a file they can't read themselves, another file, a pipe, or a folder on
the way that now leads elsewhere, hoping that what it leads to is encrypted, and uploaded, in its place.
Each original is opened once, never through a link at its end, checked to be the very file that was
chosen, and only ever read through that open file. These tests make each swap happen, at each moment,
and check that nothing but the chosen file is ever read, and that no copy is kept when the name no
longer leads to it.
"""

from __future__ import annotations

import os
import shutil
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes import core, safefs
from mindyourownbytes.core import collect_files, encrypt_archive, process_items
from tests.support import GpgTestCase

PASSPHRASE = "correct horse battery staple, for a test only"
SECRET = b"someone else's secret, which must never be encrypted in place of the original"


def try_symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link)
    except OSError as exc:
        if os.name == "nt":
            raise unittest.SkipTest(f"this Windows account can't make symbolic links ({exc.winerror})") from exc
        raise


def take_name(name: Path, other: Path, aside: Path) -> None:
    """Give ``other`` the name ``name``, while whatever had it may be open: moved aside first, then renamed in.

    Windows can't replace a name whose file is open, but it can move that file, which is just as good.
    """
    os.rename(name, aside)
    os.rename(other, name)


def link_folder(target: Path, link: Path) -> None:
    """A link to a folder: a symbolic link, or on Windows, where those need rights, a junction."""
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    else:
        os.symlink(target, link, target_is_directory=True)


class OpenOriginalTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        temp = tempfile.TemporaryDirectory(prefix="myobtest", ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.original = self.root / "a.txt"
        self.original.write_bytes(b"the original")
        self.secret = self.root / "secret.txt"
        self.secret.write_bytes(SECRET)

    def test_what_was_opened_is_what_is_read_whatever_has_the_name_later(self):
        with safefs.open_original(self.original, safefs.identity_of(self.original)) as opened:
            take_name(self.original, self.secret, self.root / "aside.txt")
            self.assertEqual(opened.read(), b"the original")
            self.assertFalse(safefs.still_named(self.original, opened))
        self.assertEqual(self.original.read_bytes(), SECRET, "the swap itself happened")

    def test_still_named_until_moved_or_deleted(self):
        with safefs.open_original(self.original) as opened:
            self.assertTrue(safefs.still_named(self.original, opened))
            moved = self.root / "moved.txt"
            os.rename(self.original, moved)
            self.assertFalse(safefs.still_named(self.original, opened))
            os.rename(moved, self.original)
            self.assertTrue(safefs.still_named(self.original, opened))
            self.original.unlink()
            self.assertFalse(safefs.still_named(self.original, opened))

    def test_a_link_at_the_end_is_never_followed(self):
        link = self.root / "link.txt"
        try_symlink(self.secret, link)
        with self.assertRaisesRegex(safefs.NotTheOriginal, "link"):
            safefs.open_original(link)

    def test_a_link_put_in_place_between_looking_and_opening_is_never_followed(self):
        # The moment between lstat and open, made to happen every time.
        link = self.root / "swapped.txt"
        link.write_bytes(b"an ordinary file when looked at")
        real_open = safefs._open_for_reading

        def swap_then_open(path):
            path.unlink()
            try_symlink(self.secret, path)
            return real_open(path)

        with patch.object(safefs, "_open_for_reading", side_effect=swap_then_open), \
                self.assertRaises(safefs.NotTheOriginal):
            safefs.open_original(link)

    def test_another_file_put_in_place_between_looking_and_opening_is_refused(self):
        real_open = safefs._open_for_reading

        def swap_then_open(path):
            take_name(path, self.secret, self.root / "aside.txt")
            return real_open(path)

        with patch.object(safefs, "_open_for_reading", side_effect=swap_then_open), \
                self.assertRaisesRegex(safefs.NotTheOriginal, "replaced as it was being opened"):
            safefs.open_original(self.original)

    def test_a_different_file_with_the_chosen_name_is_refused(self):
        chosen = safefs.identity_of(self.original)
        replacement = self.root / "replacement.txt"
        replacement.write_bytes(b"same name, another file")
        os.replace(replacement, self.original)
        with self.assertRaisesRegex(safefs.NotTheOriginal, "isn't the file that was chosen"):
            safefs.open_original(self.original, chosen)

    def test_a_folder_is_refused(self):
        with self.assertRaisesRegex(safefs.NotTheOriginal, "isn't an ordinary file"):
            safefs.open_original(self.root)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "pipes with names are a Linux and macOS thing")
    def test_a_pipe_put_in_place_is_refused_without_waiting_for_a_writer(self):
        real_open = safefs._open_for_reading

        def swap_then_open(path):
            path.unlink()
            os.mkfifo(path)
            return real_open(path)

        done = threading.Event()

        def attempt():
            with patch.object(safefs, "_open_for_reading", side_effect=swap_then_open), \
                    self.assertRaises(safefs.NotTheOriginal):
                safefs.open_original(self.original)
            done.set()

        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(10)
        self.assertTrue(done.is_set(), "opening a pipe must never wait for something to write to it")


class SwappedOriginalTests(GpgTestCase):
    """With real GnuPG: the swap happens after the file is chosen, or while GnuPG is reading it."""

    def setUp(self):
        super().setUp()
        self.progress = []
        self.chosen = self.root / "chosen"
        self.chosen.mkdir()
        self.original = self.chosen / "report.txt"
        self.original.write_bytes(b"the report that was chosen")
        self.secret = self.root / "elsewhere" / "report.txt"
        self.secret.parent.mkdir()
        self.secret.write_bytes(SECRET)

    def choose(self) -> list[core.SourceItem]:
        items, _skipped, unreadable = collect_files([str(self.chosen)], self.root / "exports", "encrypt")
        self.assertEqual(unreadable, ())
        return items

    def encrypt(self, items, method="password", **options):
        if method == "password":
            options.setdefault("passphrases", [PASSPHRASE])
        fingerprint = options.pop("fingerprint", None)
        return process_items(self.gpg, items, self.root / "exports", "encrypt", method, fingerprint,
                             threading.Event(), lambda *args: self.progress.append(args), **options)

    def assert_nothing_kept(self, result, message: str) -> None:
        self.assertEqual((result.succeeded, result.failed, result.outputs), (0, 1, ()), self.progress)
        self.assertRegex(self.progress[-1][2], message)
        exports = self.root / "exports"
        left = [path for path in exports.rglob("*") if path.is_file()] if exports.exists() else []
        self.assertEqual(left, [], "no copy, and no temporary file, is kept")

    def decrypts_to(self, path: Path) -> bytes:
        out = self.root / "check.out"
        made = self.run_gpg("--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--output", str(out),
                            "--decrypt", str(path))
        self.assertEqual(made.returncode, 0, made.stderr)
        return out.read_bytes()

    def test_an_untouched_original_is_encrypted_as_before(self):
        result = self.encrypt(self.choose())
        self.assertEqual((result.succeeded, result.checked), (1, 1), self.progress)
        self.assertEqual(self.decrypts_to(result.outputs[0]), b"the report that was chosen")
        listing = self.run_gpg("--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--list-packets",
                               str(result.outputs[0])).stdout
        self.assertIn(b'name="report.txt"', listing, "the name inside is the original's, as before")

    def test_a_file_swapped_for_a_link_after_it_was_chosen_is_refused(self):
        items = self.choose()
        self.original.unlink()
        try_symlink(self.secret, self.original)
        self.assert_nothing_kept(self.encrypt(items), "link|isn't an ordinary file|isn't the file that was chosen")

    def test_a_file_replaced_after_it_was_chosen_is_refused(self):
        items = self.choose()
        replacement = self.root / "replacement.tmp"
        os.link(self.secret, replacement)  # The same file as the secret, under the chosen name.
        take_name(self.original, replacement, self.root / "aside.txt")
        self.assert_nothing_kept(self.encrypt(items), "isn't the file that was chosen")

    def test_a_folder_on_the_way_that_leads_elsewhere_now_is_refused(self):
        items = self.choose()
        self.chosen.rename(self.root / "chosen-before")
        link_folder(self.secret.parent, self.chosen)
        self.assertEqual(self.original.read_bytes(), SECRET, "the chosen name now leads to the secret")
        self.assert_nothing_kept(self.encrypt(items), "isn't the file that was chosen")

    def swap_while_gnupg_reads(self, method: str, **options) -> None:
        items = self.choose()
        fed = bytearray()
        real = core.run_gpg_feeding

        def swap_then_feed(argv, cancel, secret, feed):
            # The name leads to the secret from now on, before GnuPG has been given a single byte.
            take_name(self.original, self.secret, self.root / "aside.txt")

            def tee(stdin):
                class Tee:
                    def write(self, data):
                        fed.extend(data)
                        return stdin.write(data)

                feed(Tee())

            return real(argv, cancel, secret, tee)

        with patch.object(core, "run_gpg_feeding", side_effect=swap_then_feed):
            result = self.encrypt(items, method, **options)
        self.assertEqual(bytes(fed), b"the report that was chosen", "GnuPG got the chosen file, all of it")
        self.assertNotIn(SECRET, bytes(fed))
        self.assert_nothing_kept(result, "another file took its name")

    def test_a_swap_while_gnupg_reads_never_gives_it_anything_else_and_keeps_no_copy(self):
        self.swap_while_gnupg_reads("password")

    def test_the_same_for_a_key_where_nothing_is_decrypted_again_to_check(self):
        self.swap_while_gnupg_reads("public-key", fingerprint=self.generate_key())

    def test_an_archive_member_swapped_after_it_was_chosen_is_refused(self):
        (self.chosen / "first.txt").write_bytes(b"first")
        items = self.choose()
        self.assertEqual(len(items), 2)

        def swap(index: int) -> None:
            if index == 0:
                replacement = self.root / "replacement.tmp"
                shutil.copyfile(self.secret, replacement)
                take_name(self.original, replacement, self.root / "aside.txt")

        result = encrypt_archive(self.gpg, items, self.root / "exports", "Archive", "password", None,
                                 threading.Event(), lambda *args: self.progress.append(args),
                                 passphrases=[PASSPHRASE], on_packing=swap)
        self.assertEqual((result.succeeded, result.failed), (0, 2), self.progress)
        self.assertRegex(self.progress[-1][2], "isn't the file that was chosen")
        exports = self.root / "exports"
        self.assertEqual([path for path in exports.rglob("*") if path.is_file()], [])


if __name__ == "__main__":
    unittest.main()
