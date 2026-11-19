"""Where decrypted data goes during a restore, against a real GnuPG, and that every ending tidies it away.

A restore decrypts into a private workspace beside the destination, and only a finished result leaves
it, under a name that nothing else had. These tests end restores in every way they can end, including a
process that dies halfway, and look for anything readable left behind.
"""

import errno
import os
import stat
import subprocess
import sys
import textwrap
import threading
import zipfile
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes import archive, safefs, workspace
from mindyourownbytes.core import encrypt_archive
from tests.test_gpg_integration import PASSPHRASE, IntegrationCase

REPOSITORY = Path(__file__).resolve().parent.parent


class RestoreCase(IntegrationCase):
    def setUp(self):
        super().setUp()
        self.journal = workspace.Journal(self.root / "app" / "unfinished")
        self.addCleanup(self.journal.close)
        self.cancel = threading.Event()

    def restore(self, path: Path, out: str = "restored", **options):
        options.setdefault("passphrases", [PASSPHRASE])
        from mindyourownbytes.core import process_items
        return process_items(self.gpg, [self.item(path)], self.root / out, "restore", "password", None,
                             self.cancel, lambda *args: self.progress.append(args), journal=self.journal, **options)

    def made_archive(self, files: dict[str, bytes] | None = None, name: str = "Archive") -> Path:
        files = files or {"a.txt": b"first", "inner/b.txt": b"second"}
        for relative, content in files.items():
            self.write(f"Taxes/{relative}", content)
        items = [self.item(self.root / "Taxes" / relative, Path("Taxes") / relative) for relative in files]
        made = encrypt_archive(self.gpg, items, self.root / "exports", name, "password", None, threading.Event(),
                               lambda *args: None, passphrases=[PASSPHRASE])
        self.assertEqual(made.succeeded, len(files))
        return made.outputs[0]

    def notes(self) -> list[Path]:
        return sorted(self.journal.directory.glob("*.json")) if self.journal.directory.is_dir() else []

    def assert_nothing_readable_left(self, out: str = "restored") -> None:
        folder = self.root / out
        left = sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*")) if folder.exists() else []
        self.assertEqual(left, [], "nothing at all may be left: no workspace, no partial file")
        self.assertEqual(self.notes(), [], "a workspace that's gone has no note")


class WhereDecryptedDataWaitsTests(RestoreCase):
    def test_a_file_waits_in_a_private_noted_workspace_until_it_has_its_name(self):
        encrypted = self.encrypt(self.write("a.txt", b"readable"))
        seen = {}
        real_sync = safefs.sync_file

        def look(path):
            space = path.parent
            seen.update(name=space.name, marker=(space / workspace.MARKER).is_file(), notes=len(self.notes()),
                        mode=stat.S_IMODE(space.stat().st_mode), final=(self.root / "restored" / "a.txt").exists())
            real_sync(path)

        with patch("mindyourownbytes.core.safefs.sync_file", side_effect=look):
            restored = self.restore(encrypted)
        self.assertEqual(restored.outputs[0].read_bytes(), b"readable")
        self.assertRegex(seen["name"], r"^\.myob-[0-9a-f]{16}\.partial$")
        self.assertTrue(seen["marker"])
        self.assertEqual(seen["notes"], 1, "noted while readable data was inside")
        self.assertFalse(seen["final"], "the final name only appears once the file is whole")
        if os.name != "nt":
            self.assertEqual(seen["mode"], 0o700)
        self.assertEqual(sorted(p.name for p in (self.root / "restored").iterdir()), ["a.txt"])
        self.assertEqual(self.notes(), [])

    def test_an_archive_unpacks_inside_the_workspace_and_only_the_whole_folder_appears(self):
        encrypted = self.made_archive()
        seen = {}
        real_extract = archive.extract

        def look(path, folder, stop):
            count = real_extract(path, folder, stop)
            seen.update(inside=folder.parent.name, decrypted_zip=path.parent == folder.parent,
                        visible=sorted(p.name for p in (self.root / "restored").iterdir()))
            return count

        with patch("mindyourownbytes.core.archive.extract", side_effect=look):
            restored = self.restore(encrypted)
        self.assertRegex(seen["inside"], r"^\.myob-[0-9a-f]{16}\.partial$")
        self.assertTrue(seen["decrypted_zip"], "the decrypted zip waits in the same private workspace")
        self.assertEqual(len(seen["visible"]), 1, "only the workspace, before the folder gets its name")
        folder = restored.outputs[0]
        self.assertEqual(folder.name, "Archive")
        self.assertEqual((folder / "Taxes" / "inner" / "b.txt").read_bytes(), b"second")
        self.assertEqual(sorted(p.name for p in (self.root / "restored").iterdir()), ["Archive"])
        self.assertEqual(self.notes(), [])


class NothingIsReplacedTests(RestoreCase):
    """Finding A, end to end: restoring never replaces what's at the destination, even an empty folder."""

    def test_an_existing_empty_folder_of_the_same_name_is_kept(self):
        encrypted = self.made_archive()
        existing = self.root / "restored" / "Archive"
        existing.mkdir(parents=True)
        before = existing.stat().st_ino
        restored = self.restore(encrypted)
        self.assertEqual(restored.outputs[0].name, "Archive (2)")
        self.assertEqual((existing.stat().st_ino, list(existing.iterdir())), (before, []))

    def test_an_existing_file_or_folder_of_the_same_name_is_kept(self):
        encrypted = self.made_archive()
        (self.root / "restored").mkdir()
        (self.root / "restored" / "Archive").write_bytes(b"a file called Archive")
        (self.root / "restored" / "Archive (2)").mkdir()
        (self.root / "restored" / "Archive (2)" / "mine.txt").write_bytes(b"mine")
        restored = self.restore(encrypted)
        self.assertEqual(restored.outputs[0].name, "Archive (3)")
        self.assertEqual((self.root / "restored" / "Archive").read_bytes(), b"a file called Archive")
        self.assertEqual((self.root / "restored" / "Archive (2)" / "mine.txt").read_bytes(), b"mine")

    def test_a_folder_that_appears_while_restoring_is_kept(self):
        encrypted = self.made_archive()
        real_extract = archive.extract

        def someone_else_meanwhile(path, folder, stop):
            count = real_extract(path, folder, stop)
            (self.root / "restored" / "Archive").mkdir()  # Made by another program after the name was chosen.
            return count

        with patch("mindyourownbytes.core.archive.extract", side_effect=someone_else_meanwhile):
            restored = self.restore(encrypted)
        self.assertEqual(restored.outputs[0].name, "Archive (2)")
        self.assertEqual(list((self.root / "restored" / "Archive").iterdir()), [])

    def test_restoring_one_archive_twice_at_once_gives_two_whole_folders(self):
        encrypted = self.made_archive({f"{n}.bin": os.urandom(50_000) for n in range(6)})
        results = []

        def run(_):
            results.append(self.restore(encrypted))

        threads = [threading.Thread(target=run, args=(n,)) for n in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        names = sorted(result.outputs[0].name for result in results)
        self.assertEqual(names, ["Archive", "Archive (2)"], self.progress)
        first, second = (self.root / "restored" / name for name in names)
        self.assertEqual(sorted(p.name for p in (first / "Taxes").iterdir()),
                         sorted(p.name for p in (second / "Taxes").iterdir()))
        self.assertEqual(self.notes(), [])


class EveryEndingTidiesUpTests(RestoreCase):
    def test_a_wrong_passphrase(self):
        result = self.restore(self.made_archive(), passphrases=["not it"])
        self.assertEqual(result.failed, 1)
        self.assert_nothing_readable_left()

    def test_a_damaged_file(self):
        encrypted = self.encrypt(self.write("a.txt", b"x" * 5000))
        data = bytearray(encrypted.read_bytes())
        data[len(data) // 2] ^= 0xFF
        encrypted.write_bytes(bytes(data))
        result = self.restore(encrypted)
        self.assertRegex(self.progress[-1][2], "damaged|altered")
        self.assertEqual(result.failed, 1)
        self.assert_nothing_readable_left()

    def test_a_corrupted_zip_inside_a_valid_encryption(self):
        plain = self.root / "made.zip"
        with zipfile.ZipFile(plain, "w", compression=zipfile.ZIP_STORED) as made:
            made.writestr("a.txt", b"A" * 4000)
            made.comment = archive.MARKER
        data = bytearray(plain.read_bytes())
        data[data.index(b"A" * 100) + 50] = ord("B")  # Breaks the CRC of the only file.
        plain.write_bytes(bytes(data))
        encrypted = self.root / "Archive.zip.gpg"
        self.run_gpg("--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--symmetric", "--output",
                     str(encrypted), str(plain))
        result = self.restore(encrypted)
        self.assertEqual(result.failed, 1)
        self.assertIn("damaged inside", self.progress[-1][2])
        self.assert_nothing_readable_left()

    def test_cancelling_while_unpacking(self):
        real_extract = archive.extract

        def cancel_then_extract(path, folder, stop):
            self.cancel.set()
            return real_extract(path, folder, stop)

        with patch("mindyourownbytes.core.archive.extract", side_effect=cancel_then_extract):
            result = self.restore(self.made_archive())
        self.assertTrue(result.cancelled)
        self.assert_nothing_readable_left()

    def test_an_unexpected_error_halfway_through_unpacking(self):
        real_extract = archive.extract

        def fail_halfway(path, folder, stop):
            real_extract(path, folder, stop)
            raise RuntimeError("something nobody expected")

        with patch("mindyourownbytes.core.archive.extract", side_effect=fail_halfway):
            result = self.restore(self.made_archive())
        self.assertEqual(result.failed, 1)
        self.assertIn("nobody expected", self.progress[-1][2])
        self.assert_nothing_readable_left()

    def test_a_full_disk_when_writing_the_result_out(self):
        encrypted = self.encrypt(self.write("a.txt"))
        with patch("mindyourownbytes.core.safefs.sync_file", side_effect=OSError(errno.ENOSPC, "No space left")):
            result = self.restore(encrypted)
        self.assertEqual(result.failed, 1)
        self.assertIn("No space", self.progress[-1][2])
        self.assert_nothing_readable_left()

    def test_permission_denied_when_publishing(self):
        encrypted = self.encrypt(self.write("a.txt"))
        with patch("mindyourownbytes.core.safefs.publish_file", side_effect=PermissionError(13, "Access denied")):
            result = self.restore(encrypted)
        self.assertEqual(result.failed, 1)
        self.assertIn("couldn't be saved as a.txt", self.progress[-1][2])
        self.assert_nothing_readable_left()

    def test_a_drive_that_cant_publish_safely_says_so(self):
        encrypted = self.made_archive()
        unsupported = safefs._unsupported(self.root / "restored" / "Archive", errno.EINVAL)
        with patch("mindyourownbytes.core.safefs.publish_directory", side_effect=unsupported):
            result = self.restore(encrypted)
        self.assertEqual(result.failed, 1)
        self.assertIn("Choose a folder on another drive", self.progress[-1][2])
        self.assert_nothing_readable_left()

    def test_a_workspace_that_cant_be_deleted_is_reported_and_stays_noted(self):
        encrypted = self.encrypt(self.write("a.txt"))
        with patch("mindyourownbytes.workspace.shutil.rmtree", side_effect=PermissionError(13, "in use")):
            result = self.restore(encrypted)
        self.assertEqual(result.succeeded, 1, "the restore itself worked")
        self.assertEqual(len(result.leftovers), 1)
        self.assertTrue(workspace.NAME.fullmatch(result.leftovers[0].name))
        self.assertEqual(len(self.notes()), 1, "so the next start can offer to delete it")


class InterruptedRestoreTests(RestoreCase):
    def test_a_restore_killed_halfway_is_found_and_cleaned_up_next_time(self):
        encrypted = self.encrypt(self.write("secret.txt", b"readable secret"))
        script = textwrap.dedent(f"""
            import os, sys, threading
            from pathlib import Path
            sys.path.insert(0, {str(REPOSITORY)!r})
            from mindyourownbytes import core, safefs, workspace
            safefs.sync_file = lambda path: os._exit(9)  # Dies just as the decrypted file is complete.
            journal = workspace.Journal(Path({str(self.journal.directory)!r}))
            item = core.SourceItem(Path({str(encrypted)!r}), Path("secret.txt.gpg"), 1)
            core.process_items({self.gpg!r}, [item], Path({str(self.root / "restored")!r}), "restore", "password",
                               None, threading.Event(), lambda *a: None, passphrases=[{PASSPHRASE!r}],
                               journal=journal)
        """)
        child = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=120, check=False)
        self.assertEqual(child.returncode, 9, child.stderr[-500:])
        restored = self.root / "restored"
        (left,) = list(restored.iterdir())
        self.assertTrue(workspace.NAME.fullmatch(left.name))
        self.assertIn(b"readable secret", [p.read_bytes() for p in left.rglob("*") if p.is_file()],
                      "the crash really left plaintext behind, so this test means something")
        self.assertFalse((restored / "secret.txt").exists(), "no final name for an unfinished restore")
        # The next start of the app:
        found = self.journal.leftovers()
        self.assertEqual([leftover.path for leftover in found], [left])
        self.assertEqual(self.journal.clean(found), ([], []))
        self.assert_nothing_readable_left()
