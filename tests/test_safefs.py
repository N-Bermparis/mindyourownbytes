"""Publishing without replacing anything, on the real file system wherever possible.

The failures these guard against were real: on Linux and macOS, os.rename replaced an existing empty
folder when an archive was restored, and a drive without hard links got a partial file under its final
name while it was being copied. Mocks appear only where a failure can't be produced for real.
"""

import errno
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes import safefs


def make_symlink(link: Path, target: Path) -> bool:
    """A link, which Windows only allows with Developer Mode or administrator rights."""
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        return False
    return True


def make_junction(link: Path, target: Path) -> bool:
    """A Windows directory junction, which needs no special rights."""
    if os.name != "nt":
        return False
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, check=False)
    return result.returncode == 0


def renames_without_replacing(folder: Path) -> bool:
    """Whether this file system can rename without replacing. WSL's view of Windows drives (9p) and NFS can't.

    There, publishing a folder fails with PublicationUnsupported, which is the point. The tests that
    need a supporting file system are skipped rather than failed.
    """
    probe = folder / ".probe-source"
    probe.mkdir()
    try:
        safefs.rename_no_replace(probe, folder / ".probe-target")
    except safefs.PublicationUnsupported:
        return False
    finally:
        for leftover in (probe, folder / ".probe-target"):
            if leftover.is_dir():
                leftover.rmdir()
    return True


class FileSystemCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="myobtest")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        if not renames_without_replacing(self.root):
            self.skipTest(f"the file system holding {self.root} can't rename without replacing")

    def staged_folder(self, name: str = ".myob-0123456789abcdef.partial", files: dict | None = None) -> Path:
        folder = self.root / name
        folder.mkdir()
        for relative, content in (files or {"restored.txt": b"from the archive"}).items():
            (folder / relative).parent.mkdir(parents=True, exist_ok=True)
            (folder / relative).write_bytes(content)
        return folder

    def staged_file(self, content: bytes = b"complete ciphertext",
                    name: str = ".myob-fedcba9876543210.partial") -> Path:
        path = self.root / name
        path.write_bytes(content)
        return path

    def tree(self, folder: Path) -> dict:
        return {p.relative_to(folder).as_posix(): p.read_bytes() for p in sorted(folder.rglob("*")) if p.is_file()}


class WhyThisExistsTests(FileSystemCase):
    """The root cause, shown with the operating system's own rename. These pass because the OS behaves so."""

    @unittest.skipIf(os.name == "nt", "Windows' rename refuses an existing destination")
    def test_plain_rename_replaces_an_empty_folder_on_this_system(self):
        staged = self.staged_folder()
        target = self.root / "Archive"
        target.mkdir()
        os.rename(staged, target)  # What archive.unpack used to do.
        self.assertEqual(self.tree(target), {"restored.txt": b"from the archive"}, "the empty folder was replaced")

    @unittest.skipUnless(os.name == "nt", "only Windows' rename refuses")
    def test_windows_rename_refuses_any_existing_destination(self):
        staged = self.staged_folder()
        (self.root / "Archive").mkdir()
        with self.assertRaises(FileExistsError):
            os.rename(staged, self.root / "Archive")


class DirectoryPublicationTests(FileSystemCase):
    def test_a_new_name_is_published_with_everything_in_it(self):
        staged = self.staged_folder(files={"a.txt": b"a", "inner/b.txt": b"b"})
        target = self.root / "Archive"
        safefs.publish_directory(staged, target)
        self.assertEqual(self.tree(target), {"a.txt": b"a", "inner/b.txt": b"b"})
        self.assertFalse(staged.exists())

    def assert_refused_and_untouched(self, make_existing) -> None:
        staged = self.staged_folder()
        target = self.root / "Archive"
        make_existing(target)
        before = os.lstat(target)
        with self.assertRaises(FileExistsError):
            safefs.publish_directory(staged, target)
        after = os.lstat(target)
        self.assertEqual((before.st_ino, before.st_mode), (after.st_ino, after.st_mode), "it was replaced")
        self.assertEqual(self.tree(staged), {"restored.txt": b"from the archive"}, "the staged folder is still whole")

    def test_an_existing_empty_folder_is_kept(self):
        self.assert_refused_and_untouched(lambda target: target.mkdir())
        self.assertEqual(list((self.root / "Archive").iterdir()), [])

    def test_an_existing_folder_with_files_is_kept(self):
        def populated(target):
            target.mkdir()
            (target / "mine.txt").write_bytes(b"mine")
        self.assert_refused_and_untouched(populated)
        self.assertEqual(self.tree(self.root / "Archive"), {"mine.txt": b"mine"})

    def test_an_existing_file_is_kept(self):
        self.assert_refused_and_untouched(lambda target: target.write_bytes(b"a file of the same name"))
        self.assertEqual((self.root / "Archive").read_bytes(), b"a file of the same name")

    def test_a_link_to_nothing_is_kept(self):
        target = self.root / "Archive"
        if not make_symlink(target, self.root / "nowhere"):
            self.skipTest("this account can't make symbolic links")
        staged = self.staged_folder()
        with self.assertRaises(FileExistsError):
            safefs.publish_directory(staged, target)
        self.assertTrue(target.is_symlink())
        self.assertFalse((self.root / "nowhere").exists(), "nothing was written through the link")

    def test_a_junction_is_kept(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        target = self.root / "Archive"
        if not make_junction(target, elsewhere):
            self.skipTest("junctions are a Windows feature")
        staged = self.staged_folder()
        with self.assertRaises(FileExistsError):
            safefs.publish_directory(staged, target)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_a_failed_publication_shows_nothing_under_the_final_name(self):
        staged = self.staged_folder()
        target = self.root / "Archive"
        with patch("mindyourownbytes.safefs.rename_no_replace", side_effect=OSError(errno.EACCES, "denied")), \
                self.assertRaises(PermissionError):
            safefs.publish_directory(staged, target)
        self.assertFalse(os.path.lexists(target))
        self.assertTrue(staged.is_dir())


class FilePublicationTests(FileSystemCase):
    def test_a_new_name_is_published_whole(self):
        staged = self.staged_file(b"x" * 300_000)
        target = self.root / "report.pdf.gpg"
        safefs.publish_file(staged, target)
        self.assertEqual(target.read_bytes(), b"x" * 300_000)

    def test_existing_things_are_kept(self):
        for name, make in (("file", lambda p: p.write_bytes(b"older backup")),
                           ("empty folder", lambda p: p.mkdir()),
                           ("folder", lambda p: (p.mkdir(), (p / "x").write_bytes(b"x")))):
            with self.subTest(name):
                target = self.root / f"{name}.gpg"
                make(target)
                staged = self.staged_file()
                before = os.lstat(target)
                with self.assertRaises(FileExistsError):
                    safefs.publish_file(staged, target)
                self.assertEqual(os.lstat(target).st_ino, before.st_ino)
                staged.unlink()
        self.assertEqual((self.root / "file.gpg").read_bytes(), b"older backup")

    def test_a_link_to_nothing_is_kept(self):
        target = self.root / "report.pdf.gpg"
        if not make_symlink(target, self.root / "nowhere"):
            self.skipTest("this account can't make symbolic links")
        with self.assertRaises(FileExistsError):
            safefs.publish_file(self.staged_file(), target)
        self.assertTrue(target.is_symlink())
        self.assertFalse((self.root / "nowhere").exists(), "nothing was written through the link")

    def test_without_hard_links_a_rename_that_never_replaces_is_used(self):
        staged = self.staged_file()
        target = self.root / "report.pdf.gpg"
        with patch("mindyourownbytes.safefs.os.link", side_effect=OSError(errno.EPERM, "no hard links")):
            safefs.publish_file(staged, target)
        self.assertEqual(target.read_bytes(), b"complete ciphertext")
        (self.root / "taken.gpg").write_bytes(b"older backup")
        with patch("mindyourownbytes.safefs.os.link", side_effect=OSError(errno.EPERM, "no hard links")), \
                self.assertRaises(FileExistsError):
            safefs.publish_file(self.staged_file(name=".myob-1111111111111111.partial"), self.root / "taken.gpg")
        self.assertEqual((self.root / "taken.gpg").read_bytes(), b"older backup")

    def test_a_drive_with_neither_way_fails_clearly_and_never_copies(self):
        staged = self.staged_file()
        target = self.root / "report.pdf.gpg"
        unsupported = safefs._unsupported(target, errno.EINVAL)  # What the system call's EINVAL becomes.
        with patch("mindyourownbytes.safefs.os.link", side_effect=OSError(errno.EPERM, "no hard links")), \
                patch("mindyourownbytes.safefs.rename_no_replace", side_effect=unsupported), \
                patch("shutil.copyfileobj", side_effect=AssertionError("copied into the final name")), \
                self.assertRaises(safefs.PublicationUnsupported) as raised:
            safefs.publish_file(staged, target)
        self.assertFalse(os.path.lexists(target), "nothing may appear under the final name")
        self.assertEqual(staged.read_bytes(), b"complete ciphertext")
        self.assertIn("Choose a folder on another drive", str(raised.exception))

    def test_permission_denied_leaves_nothing(self):
        staged = self.staged_file()
        target = self.root / "report.pdf.gpg"
        denied = OSError(errno.EACCES, "Permission denied")
        with patch("mindyourownbytes.safefs.os.link", side_effect=denied), \
                patch("mindyourownbytes.safefs.rename_no_replace", side_effect=denied), \
                self.assertRaises(PermissionError):
            safefs.publish_file(staged, target)
        self.assertFalse(os.path.lexists(target))

    def test_an_interruption_during_publication_leaves_nothing(self):
        staged = self.staged_file()
        target = self.root / "report.pdf.gpg"
        with patch("mindyourownbytes.safefs.os.link", side_effect=KeyboardInterrupt), \
                patch("mindyourownbytes.safefs.rename_no_replace", side_effect=KeyboardInterrupt), \
                self.assertRaises(KeyboardInterrupt):
            safefs.publish_file(staged, target)
        self.assertFalse(os.path.lexists(target))


class FreeNameTests(FileSystemCase):
    def test_a_name_taken_by_another_program_meanwhile_is_skipped_not_replaced(self):
        staged = self.staged_folder()
        preferred = self.root / "Archive"
        real = safefs.publish_directory
        raced = []

        def someone_else_first(source, destination):
            if not raced:
                destination.mkdir()  # Another program creates it, empty, after the name was chosen.
                raced.append(destination)
            return real(source, destination)

        published = safefs.publish_under_free_name(staged, preferred, someone_else_first)
        self.assertEqual(published.name, "Archive (2)")
        self.assertEqual(list(preferred.iterdir()), [], "the other program's folder is untouched")
        self.assertEqual(self.tree(published), {"restored.txt": b"from the archive"})

    def test_concurrent_publishers_never_share_a_name(self):
        count = 12
        staged = [self.staged_folder(f".myob-{n:016x}.partial", {"who.txt": str(n).encode()}) for n in range(count)]
        preferred = self.root / "Archive"
        (self.root / "Archive").mkdir()  # The user's own, empty folder, which must survive.
        start = threading.Barrier(count)
        published, errors = {}, []

        def publish(n):
            start.wait()
            try:
                published[n] = safefs.publish_under_free_name(staged[n], preferred, safefs.publish_directory)
            except Exception as exc:  # Reported below.
                errors.append(exc)

        threads = [threading.Thread(target=publish, args=(n,)) for n in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(set(published.values())), count, "two publishers got the same name")
        self.assertNotIn(preferred, published.values())
        self.assertEqual(list(preferred.iterdir()), [])
        for n, folder in published.items():
            self.assertEqual(self.tree(folder), {"who.txt": str(n).encode()})

    def test_concurrent_file_publishers_never_share_a_name(self):
        count = 12
        staged = [self.staged_file(str(n).encode(), f".myob-{n:016x}.partial") for n in range(count)]
        preferred = self.root / "report.pdf.gpg"
        start = threading.Barrier(count)
        published = {}

        def publish(n):
            start.wait()
            published[n] = safefs.publish_under_free_name(staged[n], preferred, safefs.publish_file)

        threads = [threading.Thread(target=publish, args=(n,)) for n in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(set(published.values())), count)
        for n, path in published.items():
            self.assertEqual(path.read_bytes(), str(n).encode())

    def test_gives_up_with_a_clear_message_rather_than_looping_forever(self):
        def always_taken(source, destination):
            raise FileExistsError(errno.EEXIST, "taken")

        with self.assertRaisesRegex(safefs.PublishFailed, "kept taking every free name"):
            safefs.publish_under_free_name(self.staged_file(), self.root / "a.gpg", always_taken)


class UnsupportedFileSystemTests(unittest.TestCase):
    """On a file system that can't refuse a taken name, publishing a folder fails clearly. Runs where one exists."""

    def test_a_folder_is_never_published_by_a_rename_that_could_replace(self):
        temp = tempfile.TemporaryDirectory(prefix="myobtest")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        if renames_without_replacing(root):
            self.skipTest("this file system renames without replacing, so the clear failure can't happen here")
        staged, target = root / "staged", root / "Archive"
        staged.mkdir()
        with self.assertRaises(safefs.PublicationUnsupported):
            safefs.publish_directory(staged, target)
        self.assertFalse(os.path.lexists(target))
        self.assertTrue(staged.is_dir())


class PlatformCallTests(unittest.TestCase):
    """How each system's answer is read, without needing that system. The real calls run in the tests above."""

    def rename_with(self, system: str, code: int):
        target = "_linux_rename_noreplace" if system == "linux" else "_macos_rename_excl"
        staged, final = Path("staged"), Path("final")
        with patch("mindyourownbytes.safefs._system", return_value=system), \
                patch(f"mindyourownbytes.safefs.{target}", return_value=code) as called:
            safefs.rename_no_replace(staged, final)
        return called

    def test_each_system_gets_its_own_call(self):
        self.assertEqual(self.rename_with("linux", 0).call_count, 1)
        self.assertEqual(self.rename_with("macos", 0).call_count, 1)

    def test_errors_become_the_right_exceptions(self):
        for system in ("linux", "macos"):
            with self.subTest(system):
                with self.assertRaises(FileExistsError):
                    self.rename_with(system, errno.EEXIST)
                with self.assertRaises(PermissionError):
                    self.rename_with(system, errno.EACCES)
                for unsupported in (errno.EINVAL, errno.ENOSYS, errno.ENOTSUP):
                    with self.assertRaises(safefs.PublicationUnsupported):
                        self.rename_with(system, unsupported)

    def test_other_systems_fail_clearly_instead_of_guessing(self):
        with patch("mindyourownbytes.safefs._system", return_value="none"), \
                self.assertRaises(safefs.PublicationUnsupported):
            safefs.rename_no_replace(Path("staged"), Path("final"))

    def test_linux_without_hard_links_or_renameat2_never_copies(self):
        # As on a network share that refuses both: an error, never a partial file under the final name.
        with patch("mindyourownbytes.safefs._system", return_value="linux"), \
                patch("mindyourownbytes.safefs._linux_rename_noreplace", return_value=errno.EINVAL), \
                patch("mindyourownbytes.safefs.os.link", side_effect=OSError(errno.EPERM, "no hard links")), \
                self.assertRaises(safefs.PublicationUnsupported):
            safefs.publish_file(Path("staged"), Path("final"))

    def test_linux_uses_a_hard_link_where_renameat2_is_missing(self):
        # Such as NFS, whose server refuses a taken name for a hard link, atomically.
        with patch("mindyourownbytes.safefs._system", return_value="linux"), \
                patch("mindyourownbytes.safefs._linux_rename_noreplace", return_value=errno.EINVAL), \
                patch("mindyourownbytes.safefs.os.link") as link:
            safefs.publish_file(Path("staged"), Path("final"))
        link.assert_called_once_with(Path("staged"), Path("final"))

    @unittest.skipUnless(sys.platform.startswith("linux"), "the real renameat2 call")
    def test_linux_really_refuses_with_renameat2(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "staged").mkdir()
            (root / "taken").mkdir()
            code = safefs._linux_rename_noreplace(os.fsencode(root / "staged"), os.fsencode(root / "taken"))
            self.assertIn(code, (errno.EEXIST, errno.EINVAL))  # EINVAL only on a file system without it.
            self.assertTrue((root / "staged").is_dir())


class SyncTests(FileSystemCase):
    def test_a_file_can_be_synced_and_a_folder_asked_to(self):
        path = self.staged_file()
        safefs.sync_file(path)
        safefs.sync_directory(self.root)
        self.assertEqual(path.read_bytes(), b"complete ciphertext")

    def test_a_write_error_is_reported_so_the_file_is_not_published(self):
        path = self.staged_file()
        with patch("mindyourownbytes.safefs._full_sync", side_effect=OSError(errno.EIO, "I/O error")), \
                self.assertRaises(OSError):
            safefs.sync_file(path)
        with patch("mindyourownbytes.safefs._full_sync", side_effect=OSError(errno.ENOSPC, "No space")), \
                self.assertRaises(OSError):
            safefs.sync_file(path)

    def test_a_drive_that_cant_sync_is_not_an_error(self):
        path = self.staged_file()
        with patch("mindyourownbytes.safefs._full_sync", side_effect=OSError(errno.EINVAL, "not supported")):
            safefs.sync_file(path)
        with patch("mindyourownbytes.safefs._full_sync", side_effect=OSError(errno.EIO, "I/O error")):
            safefs.sync_directory(self.root)  # The name was given already, so this never fails a job.


if __name__ == "__main__":
    unittest.main()
