"""Path handling, naming, and failure logic. Uses no real gpg, so it runs anywhere."""

import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes.core import (
    SourceItem,
    bundled_gpg,
    collect_files,
    encode_passphrase,
    find_gpg,
    find_kleopatra,
    gpg_version,
    is_link_or_junction,
    looks_cloud_synced,
    output_relative,
    process_items,
    stop_bundled_gnupg,
    unique_target,
)
from tests.support import stderr_with_statuses

ENCRYPTED_OK = stderr_with_statuses("BEGIN_ENCRYPTION 2 9", "END_ENCRYPTION")
DECRYPTED_OK = stderr_with_statuses("BEGIN_DECRYPTION", "DECRYPTION_OKAY", "GOODMDC", "END_DECRYPTION")


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="myobtest")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "Research"
        (self.source / "QKD").mkdir(parents=True)
        (self.source / "QKD" / "report.pdf").write_bytes(b"Important research data")
        (self.source / "QKD" / "code.cpp").write_text("int main() { return 0; }")
        self.output = self.root / "encrypted"


class FileLayoutTests(TempDirCase):
    def test_folder_layout(self):
        result = collect_files([self.source], self.output, "encrypt")
        self.assertEqual((len(result.items), result.skipped, result.unreadable), (2, 0, ()))
        names = {str(output_relative(item, "encrypt")) for item in result.items}
        self.assertEqual(names, {
            str(Path("Research/QKD/report.pdf.gpg")),
            str(Path("Research/QKD/code.cpp.gpg")),
        })

    def test_rejects_output_inside_input(self):
        with self.assertRaisesRegex(ValueError, "inside"):
            collect_files([self.source], self.source / "subdirectory", "encrypt")

    def test_restore_requires_encrypted_extension(self):
        item = SourceItem(self.source / "QKD" / "report.pdf", Path("report.pdf"), 1)
        with self.assertRaises(ValueError):
            output_relative(item, "restore")

    def test_restore_mode_skips_non_encrypted_files(self):
        (self.source / "a.txt.gpg").write_bytes(b"x")
        result = collect_files([self.source], self.output, "restore")
        self.assertEqual([item.source.name for item in result.items], ["a.txt.gpg"])
        self.assertEqual(result.skipped, 2)

    def test_parent_directory_input_cannot_escape_output(self):
        # Path("..").name is "..", which used to become part of the output path.
        os.chdir(self.source / "QKD")
        self.addCleanup(os.chdir, self.root.parent)
        result = collect_files([".."], self.output, "encrypt")
        target = (self.output / output_relative(result.items[0], "encrypt")).resolve()
        self.assertIn(self.output.resolve(), target.parents)

    def test_skips_symlink(self):
        link = self.source / "link.txt"
        try:
            link.symlink_to(self.source / "QKD" / "report.pdf")
        except OSError:
            self.skipTest("Cannot create symlinks")
        result = collect_files([self.source], self.output, "encrypt")
        self.assertEqual(len(result.items), 2)
        self.assertGreaterEqual(result.skipped, 1)

    @unittest.skipUnless(os.name == "nt", "Windows junctions")
    def test_never_follows_junction_out_of_the_selection(self):
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "not-selected.txt").write_text("private")
        junction = self.source / "jump"
        subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
                       check=True, capture_output=True)
        self.assertTrue(is_link_or_junction(junction))
        result = collect_files([self.source], self.output, "encrypt")
        self.assertNotIn("not-selected.txt", [item.source.name for item in result.items])
        self.assertGreaterEqual(result.skipped, 1)

    def test_unreadable_folder_is_reported_not_silently_dropped(self):
        real_walk = os.walk

        def walk_hitting_denied_folder(top, **kwargs):
            kwargs["onerror"](PermissionError(13, "denied", str(Path(top) / "locked")))
            yield from real_walk(top, **kwargs)

        with patch("mindyourownbytes.core.os.walk", walk_hitting_denied_folder):
            result = collect_files([self.source], self.output, "encrypt")
        self.assertEqual([path.name for path in result.unreadable], ["locked"])
        self.assertEqual(len(result.items), 2)


class NamingTests(TempDirCase):
    def test_collision_keeps_the_restored_extension(self):
        self.output.mkdir()
        (self.output / "report.pdf.gpg").write_bytes(b"existing ciphertext")
        second = unique_target(self.output / "report.pdf.gpg")
        self.assertEqual(second.name, "report (2).pdf.gpg")
        self.assertEqual(second.with_suffix("").name, "report (2).pdf")

    def test_collision_for_restored_file_and_dotfile(self):
        self.output.mkdir()
        (self.output / "report.pdf").write_bytes(b"x")
        (self.output / ".env.gpg").write_bytes(b"x")
        self.assertEqual(unique_target(self.output / "report.pdf").name, "report (2).pdf")
        self.assertEqual(unique_target(self.output / ".env.gpg").name, ".env (2).gpg")

    def test_free_name_is_unchanged(self):
        self.assertEqual(unique_target(self.output / "a.gpg"), self.output / "a.gpg")


class PassphraseEncodingTests(unittest.TestCase):
    def test_rejects_what_gpg_would_silently_truncate(self):
        for bad in ("first\nsecond", "first\rsecond", "nul\0byte", ""):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                encode_passphrase(bad)

    def test_keeps_spaces_and_unicode(self):
        self.assertEqual(encode_passphrase(" κωδικός ✓ "), " κωδικός ✓ ".encode())


class GpgDiscoveryTests(TempDirCase):
    def test_never_runs_a_gpg_planted_in_the_current_directory(self):
        planted = self.root / ("gpg.exe" if os.name == "nt" else "gpg")
        planted.write_bytes(b"not really gpg")
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.root.parent)
        environment = {"PATH": f"{os.pathsep}.{os.pathsep}relative", "ProgramFiles": "", "ProgramW6432": "",
                       "ProgramFiles(x86)": "", "LOCALAPPDATA": ""}
        with patch.dict(os.environ, environment):
            os.environ.pop("NoDefaultCurrentDirectoryInExePath", None)
            self.assertIsNone(find_gpg())

    def test_never_runs_a_kleopatra_planted_in_the_current_directory(self):
        planted = self.root / ("kleopatra.exe" if os.name == "nt" else "kleopatra")
        planted.write_bytes(b"not really kleopatra")
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.root.parent)
        environment = {"PATH": f"{os.pathsep}.{os.pathsep}relative", "ProgramFiles": "", "ProgramW6432": "",
                       "ProgramFiles(x86)": "", "LOCALAPPDATA": ""}
        with patch.dict(os.environ, environment):
            self.assertIsNone(find_kleopatra())

    def test_skips_git_for_windows_bundled_gpg(self):
        bundled = self.root / "Git" / "usr" / "bin"
        bundled.mkdir(parents=True)
        (bundled / ("gpg.exe" if os.name == "nt" else "gpg")).write_bytes(b"x")
        environment = {"PATH": str(bundled), "ProgramFiles": "", "ProgramW6432": "",
                       "ProgramFiles(x86)": "", "LOCALAPPDATA": ""}
        with patch.dict(os.environ, environment):
            self.assertIsNone(find_gpg())

    def _download_folder(self) -> Path:
        """Lay out what the Windows download holds, and pretend to be running from it."""
        folder = self.root / "app"
        (folder / "gnupg" / "bin").mkdir(parents=True)
        (folder / "gnupg" / "bin" / "gpg.exe").write_bytes(b"x")
        for name, value in (("frozen", True), ("executable", str(folder / "mindyourownbytes.exe"))):
            patcher = patch.object(sys, name, value, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)
        return folder

    def test_source_checkouts_have_no_included_gnupg(self):
        self.assertIsNone(bundled_gpg())

    def test_included_gnupg_can_be_missing_from_the_download(self):
        folder = self._download_folder()
        self.assertEqual(bundled_gpg(), str(folder / "gnupg" / "bin" / "gpg.exe"))
        (folder / "gnupg" / "bin" / "gpg.exe").unlink()
        self.assertIsNone(bundled_gpg())

    @unittest.skipUnless(os.name == "nt", "only the Windows download includes GnuPG")
    def test_download_uses_its_own_gnupg_ahead_of_path(self):
        folder = self._download_folder()
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "gpg.exe").write_bytes(b"x")
        environment = {"PATH": str(elsewhere), "ProgramFiles": "", "ProgramW6432": "",
                       "ProgramFiles(x86)": "", "LOCALAPPDATA": ""}
        with patch.dict(os.environ, environment):
            self.assertEqual(find_gpg(), str(folder / "gnupg" / "bin" / "gpg.exe"))

    @unittest.skipUnless(os.name == "nt", "only the Windows download includes GnuPG")
    def test_download_prefers_a_gnupg_the_user_installed(self):
        self._download_folder()
        installed = self.root / "Program Files" / "GnuPG" / "bin"
        installed.mkdir(parents=True)
        (installed / "gpg.exe").write_bytes(b"x")
        environment = {"PATH": "", "ProgramFiles": str(self.root / "Program Files"), "ProgramW6432": "",
                       "ProgramFiles(x86)": "", "LOCALAPPDATA": ""}
        with patch.dict(os.environ, environment), patch("mindyourownbytes.core.is_valid_gpg", return_value=True):
            self.assertEqual(find_gpg(), str(installed / "gpg.exe"))

    @unittest.skipUnless(os.name == "nt", "only the Windows download includes GnuPG")
    def test_an_unusable_installed_gnupg_does_not_hide_the_included_one(self):
        folder = self._download_folder()
        installed = self.root / "Program Files" / "GnuPG" / "bin"
        installed.mkdir(parents=True)
        (installed / "gpg.exe").write_bytes(b"x")
        environment = {"PATH": "", "ProgramFiles": str(self.root / "Program Files"), "ProgramW6432": "",
                       "ProgramFiles(x86)": "", "LOCALAPPDATA": ""}
        with patch.dict(os.environ, environment), patch("mindyourownbytes.core.is_valid_gpg", return_value=False):
            self.assertEqual(find_gpg(), str(folder / "gnupg" / "bin" / "gpg.exe"))

    @unittest.skipUnless(os.name == "nt", "the standard install locations are only searched on Windows")
    def test_without_a_download_an_unusable_gnupg_is_still_found_and_reported(self):
        installed = self.root / "Program Files" / "GnuPG" / "bin"
        installed.mkdir(parents=True)
        (installed / "gpg.exe").write_bytes(b"x")
        environment = {"PATH": "", "ProgramFiles": str(self.root / "Program Files"), "ProgramW6432": "",
                       "ProgramFiles(x86)": "", "LOCALAPPDATA": ""}
        with patch.dict(os.environ, environment), patch("mindyourownbytes.core.is_valid_gpg", return_value=False):
            self.assertEqual(find_gpg(), str(installed / "gpg.exe"))

    def test_closing_stops_only_the_included_gnupg(self):
        folder = self._download_folder()
        bin_folder = folder / "gnupg" / "bin"
        with patch("mindyourownbytes.core.subprocess.run") as run:
            stop_bundled_gnupg(str(self.root / "Program Files" / "GnuPG" / "bin" / "gpg.exe"))
            stop_bundled_gnupg("")
            run.assert_not_called()
            stop_bundled_gnupg(str(bin_folder / "gpg.exe"))
        self.assertEqual(run.call_args.args[0], [str(bin_folder / "gpgconf.exe"), "--kill", "all"])

    def test_source_checkouts_never_stop_anyones_gnupg(self):
        with patch("mindyourownbytes.core.subprocess.run") as run:
            stop_bundled_gnupg("gpg")
            stop_bundled_gnupg("")
        run.assert_not_called()

    def test_failing_to_stop_gnupg_does_not_interrupt_closing(self):
        folder = self._download_folder()
        included = str(folder / "gnupg" / "bin" / "gpg.exe")
        for failure in (OSError("gone"), subprocess.TimeoutExpired("gpgconf", 15)):
            with patch("mindyourownbytes.core.subprocess.run", side_effect=failure):
                stop_bundled_gnupg(included)

    def test_relative_binary_is_never_executed(self):
        with patch("mindyourownbytes.core.subprocess.run") as run:
            self.assertIsNone(gpg_version("gpg"))
            run.assert_not_called()

    def test_program_that_merely_mentions_gpg_is_rejected(self):
        fake = subprocess.CompletedProcess([], 0, stdout="not-really-gpg 2.4.0\n")
        with patch("mindyourownbytes.core.subprocess.run", return_value=fake):
            self.assertIsNone(gpg_version(str(self.root / "x")))

    def test_parses_real_and_vendor_version_strings(self):
        for line, expected in (("gpg (GnuPG) 2.5.18", (2, 5, 18)), ("gpg (GnuPG/MacGPG2) 2.2.41", (2, 2, 41))):
            fake = subprocess.CompletedProcess([], 0, stdout=f"{line}\nlibgcrypt 1.12\n")
            with self.subTest(line=line), patch("mindyourownbytes.core.subprocess.run", return_value=fake):
                self.assertEqual(gpg_version(str(self.root / "x")), expected)


class CloudSyncDetectionTests(unittest.TestCase):
    def test_detects_common_sync_folders(self):
        for path in (r"C:\Users\me\OneDrive\Desktop", r"C:\Users\me\OneDrive - Contoso\x",
                     "/home/me/Dropbox/a", "/home/me/Nextcloud/a",
                     "/Users/me/Library/Mobile Documents/x", "/Users/me/Library/CloudStorage/y"):
            with self.subTest(path=path):
                normalized = path if os.name == "nt" or not path.startswith("C:") else path.replace("\\", "/")
                self.assertIsNotNone(looks_cloud_synced(normalized))

    def test_no_false_positive_on_a_similar_word(self):
        # The original check matched the substring "sync", so this was flagged.
        with patch.dict(os.environ, {"OneDrive": "", "OneDriveConsumer": "", "OneDriveCommercial": ""}):
            self.assertIsNone(looks_cloud_synced("/home/me/async-project/box-plots"))

    def test_honours_custom_onedrive_location_from_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "Personal files"
            with patch.dict(os.environ, {"OneDrive": str(root)}):
                self.assertEqual(looks_cloud_synced(root / "a" / "b"), "Personal files")


class ProcessItemsTests(TempDirCase):
    """gpg itself is mocked here; tests/test_gpg_integration.py runs the real thing."""

    def run_job(self, items, operation, fake, method="password", fingerprint=None, **kwargs):
        progress = []
        with patch("mindyourownbytes.core.is_valid_gpg", return_value=True), patch(
            "mindyourownbytes.core.run_gpg", side_effect=fake
        ):
            job = process_items("mock-gpg", items, self.output, operation, method, fingerprint,
                                threading.Event(), lambda *args: progress.append(args), **kwargs)
        return job, progress

    def item(self):
        original = self.source / "QKD" / "report.pdf"
        return SourceItem(original, Path("Research/QKD/report.pdf"), original.stat().st_size)

    def test_failed_operation_removes_partial_outputs(self):
        def fail_after_writing(argv, cancel, secret=None):
            Path(argv[argv.index("--output") + 1]).write_bytes(b"partial")
            return 2, "gpg: simulated failure\n"

        job, progress = self.run_job([self.item()], "encrypt", fail_after_writing)
        self.assertEqual((job.succeeded, job.failed), (0, 1))
        self.assertEqual([p for p in self.output.rglob("*") if p.is_file()], [])
        self.assertIn("simulated failure", progress[0][2])

    def test_success_publishes_only_the_final_name(self):
        def fake_encrypt(argv, cancel, secret=None):
            self.assertIn("--symmetric", argv)
            Path(argv[argv.index("--output") + 1]).write_bytes(b"dummy ciphertext")
            return 0, ENCRYPTED_OK

        job, _ = self.run_job([self.item()], "encrypt", fake_encrypt)
        self.assertEqual(job.outputs[0].relative_to(self.output), Path("Research/QKD/report.pdf.gpg"))
        self.assertEqual(job.outputs[0].read_bytes(), b"dummy ciphertext")
        self.assertFalse(list(self.output.rglob("*.partial")))

    def test_exit_code_zero_without_encryption_status_is_a_failure(self):
        def silent(argv, cancel, secret=None):
            Path(argv[argv.index("--output") + 1]).write_bytes(b"who knows what this is")
            return 0, ""

        job, _ = self.run_job([self.item()], "encrypt", silent)
        self.assertEqual((job.succeeded, job.failed), (0, 1))
        self.assertEqual([p for p in self.output.rglob("*") if p.is_file()], [])

    def test_passphrase_goes_over_the_pipe_and_never_into_argv(self):
        seen = {}

        def capture(argv, cancel, secret=None):
            seen.update(argv=argv, secret=secret)
            Path(argv[argv.index("--output") + 1]).write_bytes(b"c")
            return 0, ENCRYPTED_OK

        self.run_job([self.item()], "encrypt", capture, passphrases=["hunter2 hunter2"])
        self.assertEqual(seen["secret"], b"hunter2 hunter2")
        self.assertNotIn("hunter2", " ".join(seen["argv"]))
        self.assertIn("--passphrase-fd", seen["argv"])

    def test_kdf_is_pinned_rather_than_left_to_defaults(self):
        seen = {}

        def capture(argv, cancel, secret=None):
            seen["argv"] = argv
            Path(argv[argv.index("--output") + 1]).write_bytes(b"c")
            return 0, ENCRYPTED_OK

        self.run_job([self.item()], "encrypt", capture)
        argv = seen["argv"]
        self.assertEqual(argv[argv.index("--s2k-count") + 1], "65011712")
        self.assertEqual(argv[argv.index("--s2k-digest-algo") + 1], "SHA512")
        self.assertEqual(argv[argv.index("--cipher-algo") + 1], "AES256")
        self.assertIn("--no-symkey-cache", argv)

    def test_failed_encryption_is_not_described_as_a_damaged_file(self):
        def disk_full(argv, cancel, secret=None):
            return 2, stderr_with_statuses("NEED_PASSPHRASE_SYM 9 3 8") + "gpg: write error: disk full\n"

        _, progress = self.run_job([self.item()], "encrypt", disk_full)
        self.assertIn("disk full", progress[0][2])
        self.assertNotIn("damaged", progress[0][2])

    def test_staging_name_stays_short_for_long_filenames(self):
        # Regression: it embedded the original name and overflowed the limit.
        seen = {}
        long_item = SourceItem(self.source / "QKD" / "report.pdf", Path("L" * 230 + ".pdf"), 1)

        def capture(argv, cancel, secret=None):
            seen["staged"] = Path(argv[argv.index("--output") + 1])
            return 2, "gpg: stop here\n"

        self.run_job([long_item], "encrypt", capture)
        self.assertLess(len(seen["staged"].name), 40)
        self.assertNotIn("L" * 10, seen["staged"].name)

    def test_cleanup_failure_does_not_abort_the_batch(self):
        first, second = self.item(), SourceItem(self.source / "QKD" / "code.cpp", Path("code.cpp"), 1)

        def fail(argv, cancel, secret=None):
            return 2, "gpg: nope\n"

        with patch("pathlib.Path.unlink", side_effect=OSError(123, "invalid name")):
            job, progress = self.run_job([first, second], "encrypt", fail)
        self.assertEqual((job.failed, len(progress)), (2, 2))
        self.assertEqual(len(job.leftovers), 2)

    def test_rejects_invalid_requests(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self.run_job([self.item()], "encrypt", None, passphrases=["a", "b"])
        with self.assertRaisesRegex(ValueError, "recipient"):
            self.run_job([self.item()], "encrypt", None, method="public-key", fingerprint="abc")
        with self.assertRaisesRegex(ValueError, "does not use"):
            self.run_job([self.item()], "encrypt", None, method="public-key",
                         fingerprint="A" * 40, passphrases=["a"])


if __name__ == "__main__":
    unittest.main()
