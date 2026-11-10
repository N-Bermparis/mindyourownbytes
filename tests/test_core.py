"""Path handling, naming, and failure logic. Uses no real gpg, so it runs anywhere."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes.core import (
    CHECKED,
    CIPHERS,
    DEFAULT_CIPHER,
    READY,
    Cancelled,
    GpgFailure,
    SourceItem,
    add_post_quantum_subkey,
    available_ciphers,
    bundled_gpg,
    collect_files,
    create_post_quantum_key,
    encode_passphrase,
    find_gpg,
    find_kleopatra,
    gpg_version,
    is_link_or_junction,
    list_public_keys,
    looks_cloud_synced,
    output_relative,
    process_items,
    run_gpg_hashed,
    stop_bundled_gnupg,
    supports_post_quantum,
    unique_target,
    user_id,
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

        self.run_job([self.item()], "encrypt", capture, passphrases=["hunter2 hunter2"], verify=False)
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

    def capture_commands(self, seen):
        def capture(argv, cancel, secret=None):
            seen.append(argv)
            Path(argv[argv.index("--output") + 1]).write_bytes(b"c")
            return 0, DECRYPTED_OK if "--decrypt" in argv else ENCRYPTED_OK

        return capture

    def test_aes_256_is_the_default_choice(self):
        self.assertEqual(DEFAULT_CIPHER, "AES256")
        self.assertEqual(CIPHERS[0].name, DEFAULT_CIPHER)

    def test_each_algorithm_reaches_gnupg_with_the_same_strong_settings(self):
        for cipher in CIPHERS:
            with self.subTest(cipher.label):
                seen = []
                self.run_job([self.item()], "encrypt", self.capture_commands(seen), cipher=cipher.name)
                argv = seen[0]
                self.assertEqual(argv[argv.index("--cipher-algo") + 1], cipher.name)
                self.assertEqual(argv[argv.index("--s2k-mode") + 1], "3")
                self.assertEqual(argv[argv.index("--s2k-digest-algo") + 1], "SHA512")
                self.assertEqual(argv[argv.index("--s2k-count") + 1], "65011712")

    def test_an_algorithm_this_app_does_not_offer_is_refused_before_any_work(self):
        def never(argv, cancel, secret=None):
            self.fail("gpg should not have run")

        for cipher in ("CAST5", "3DES", "IDEA", "BLOWFISH", "AES", "aes256", "", "AES256 --s2k-count 1024"):
            with self.subTest(cipher), self.assertRaises(ValueError):
                self.run_job([self.item()], "encrypt", never, cipher=cipher)
        self.assertFalse(self.output.exists())

    def test_only_passphrase_encryption_takes_an_algorithm(self):
        seen = []
        original = self.source / "QKD" / "report.pdf"
        self.run_job([self.item()], "encrypt", self.capture_commands(seen), "public-key", "A" * 40, cipher="TWOFISH")
        self.run_job([SourceItem(original, Path("a.pdf.gpg"), 1)], "restore", self.capture_commands(seen),
                     cipher="TWOFISH")
        self.assertEqual(len(seen), 2)
        for argv in seen:
            self.assertNotIn("--cipher-algo", argv)

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


class CheckAfterEncryptingTests(TempDirCase):
    """The decisions around the check, with gpg mocked. tests/test_gpg_integration.py runs the real thing."""

    CONTENT = b"Important research data"

    def item(self, name="report.pdf"):
        original = self.source / "QKD" / name
        return SourceItem(original, Path(name), original.stat().st_size)

    def encrypting(self, seen=None):
        def fake(argv, cancel, secret=None):
            if seen is not None:
                seen.append(("encrypt", argv, secret))
            Path(argv[argv.index("--output") + 1]).write_bytes(b"dummy ciphertext")
            return 0, ENCRYPTED_OK

        return fake

    def run_job(self, check, items=None, encrypt=None, method="password", fingerprint=None, operation="encrypt",
                cancel=None, **kwargs):
        progress = []
        if operation == "encrypt" and method == "password":
            kwargs.setdefault("passphrases", ["hunter2 hunter2"])
        with patch("mindyourownbytes.core.is_valid_gpg", return_value=True), patch(
            "mindyourownbytes.core.run_gpg", side_effect=encrypt or self.encrypting()
        ), patch("mindyourownbytes.core.run_gpg_hashed", side_effect=check) as checker:
            job = process_items("mock-gpg", items or [self.item()], self.output, operation, method, fingerprint,
                                cancel or threading.Event(), lambda *args: progress.append(args), **kwargs)
        return job, progress, checker

    def answering(self, code=0, stderr=DECRYPTED_OK, content=None):
        digest = hashlib.sha256(self.CONTENT if content is None else content).digest()
        return lambda argv, cancel, secret: (code, stderr, digest)

    def assert_nothing_kept(self, job, progress, message):
        self.assertEqual((job.succeeded, job.failed, job.checked, job.outputs), (0, 1, 0, ()))
        self.assertRegex(progress[0][2], message)
        self.assertEqual([p for p in self.output.rglob("*") if p.is_file()], [])

    def test_a_matching_copy_is_published_and_counted_as_checked(self):
        job, progress, checker = self.run_job(self.answering())
        self.assertEqual((job.succeeded, job.failed, job.checked), (1, 0, 1))
        self.assertEqual(progress[0][1:3], (True, CHECKED))
        self.assertEqual(checker.call_count, 1)
        self.assertEqual([p.name for p in self.output.rglob("*") if p.is_file()], ["report.pdf.gpg"])

    def test_the_check_happens_before_the_file_gets_its_final_name(self):
        seen = {}

        def check(argv, cancel, secret):
            staged = Path(argv[-1])
            seen.update(staged=staged.name, staged_exists=staged.is_file(),
                        published=[p.name for p in self.output.rglob("*.gpg")])
            return 0, DECRYPTED_OK, hashlib.sha256(self.CONTENT).digest()

        self.run_job(check)
        self.assertRegex(seen["staged"], r"^\.myob-[0-9a-f]{16}\.partial$")
        self.assertTrue(seen["staged_exists"])
        self.assertEqual(seen["published"], [])

    def test_the_check_decrypts_to_a_pipe_with_the_passphrase_kept_out_of_the_command(self):
        seen = {}

        def check(argv, cancel, secret):
            seen.update(argv=argv, secret=secret)
            return 0, DECRYPTED_OK, hashlib.sha256(self.CONTENT).digest()

        self.run_job(check)
        argv = seen["argv"]
        self.assertEqual(seen["secret"], b"hunter2 hunter2")
        self.assertNotIn("hunter2", " ".join(argv))
        self.assertEqual(argv[argv.index("--output") + 1], "-")
        self.assertEqual(argv[argv.index("--pinentry-mode") + 1], "loopback")
        self.assertEqual(argv[argv.index("--passphrase-fd") + 1], "0")
        self.assertEqual(argv[-3:-1], ["--decrypt", "--"])
        for option in ("--batch", "--no-tty", "--no-symkey-cache", "--no-auto-key-retrieve"):
            self.assertIn(option, argv)

    def test_a_copy_with_other_content_is_not_published(self):
        job, progress, _ = self.run_job(self.answering(content=b"something else"))
        self.assert_nothing_kept(job, progress, "didn't give back the original")

    def test_exit_code_zero_is_required_even_with_the_right_content(self):
        job, progress, _ = self.run_job(self.answering(code=2))
        self.assert_nothing_kept(job, progress, "^Check failed: GnuPG couldn't decrypt")

    def test_decryption_okay_is_required_even_with_the_right_content(self):
        for stderr in ("", stderr_with_statuses("BEGIN_DECRYPTION", "PLAINTEXT 62 0 x", "END_DECRYPTION"),
                       "gpg: DECRYPTION_OKAY\n"):
            with self.subTest(stderr):
                job, progress, _ = self.run_job(self.answering(stderr=stderr))
                self.assert_nothing_kept(job, progress, "isn't actually encrypted")

    def test_a_check_that_cannot_run_keeps_nothing(self):
        def broken(argv, cancel, secret):
            raise OSError(5, "simulated failure")

        job, progress, _ = self.run_job(broken)
        self.assert_nothing_kept(job, progress, "^Check failed: GnuPG couldn't be run again")

    def test_an_original_that_cannot_be_read_again_keeps_nothing(self):
        with patch("mindyourownbytes.core._hash_file", side_effect=PermissionError(13, "denied")):
            job, progress, _ = self.run_job(self.answering())
        self.assert_nothing_kept(job, progress, "^Check failed: the original couldn't be read again")

    def test_a_changed_original_is_named_as_the_reason(self):
        original = self.source / "QKD" / "report.pdf"

        def check(argv, cancel, secret):
            original.write_bytes(b"A newer version of the research data, saved meanwhile")
            return 0, DECRYPTED_OK, hashlib.sha256(self.CONTENT).digest()

        job, progress, _ = self.run_job(check)
        self.assert_nothing_kept(job, progress, "^The original changed")

    def test_nothing_is_checked_without_a_passphrase_in_hand(self):
        for label, options in (
            ("GnuPG's own prompt", {"passphrases": []}),
            ("a key", {"method": "public-key", "fingerprint": "A" * 40}),
            ("turned off", {"verify": False}),
        ):
            with self.subTest(label):
                seen = []
                job, progress, checker = self.run_job(self.answering(), on_checking=seen.append, **options)
                self.assertEqual((job.succeeded, job.checked, seen), (1, 0, []))
                self.assertEqual(progress[0][1:3], (True, READY))
                checker.assert_not_called()
                shutil.rmtree(self.output)

    def test_a_restore_is_not_checked_this_way(self):
        def restoring(argv, cancel, secret=None):
            Path(argv[argv.index("--output") + 1]).write_bytes(b"plain")
            return 0, DECRYPTED_OK

        original = self.source / "QKD" / "report.pdf"
        job, _, checker = self.run_job(self.answering(), [SourceItem(original, Path("a.pdf.gpg"), 1)],
                                       encrypt=restoring, operation="restore", passphrases=["hunter2 hunter2"])
        self.assertEqual((job.succeeded, job.checked), (1, 0))
        checker.assert_not_called()

    def test_each_check_is_announced_with_its_position_before_it_runs(self):
        order = []

        def check(argv, cancel, secret):
            order.append("check")
            return 0, DECRYPTED_OK, hashlib.sha256(Path(self.sources[len(order) // 2 - 1]).read_bytes()).digest()

        self.sources = [self.source / "QKD" / "report.pdf", self.source / "QKD" / "code.cpp"]
        job, _, _ = self.run_job(check, [self.item(), self.item("code.cpp")],
                                 on_checking=lambda index: order.append(index))
        self.assertEqual(order, [0, "check", 1, "check"])
        self.assertEqual((job.succeeded, job.checked), (2, 2))

    def test_a_refused_file_does_not_stop_the_next_one(self):
        answers = iter([b"something else", (self.source / "QKD" / "code.cpp").read_bytes()])

        def check(argv, cancel, secret):
            return 0, DECRYPTED_OK, hashlib.sha256(next(answers)).digest()

        job, progress, _ = self.run_job(check, [self.item(), self.item("code.cpp")])
        self.assertEqual((job.succeeded, job.failed, job.checked), (1, 1, 1))
        self.assertEqual([entry[1] for entry in progress], [False, True])
        self.assertEqual([p.name for p in self.output.rglob("*") if p.is_file()], ["code.cpp.gpg"])

    def test_cancelling_after_encrypting_skips_the_check_and_keeps_nothing(self):
        cancel = threading.Event()

        def encrypt_then_cancel(argv, cancel_event, secret=None):
            Path(argv[argv.index("--output") + 1]).write_bytes(b"dummy ciphertext")
            cancel.set()
            return 0, ENCRYPTED_OK

        job, progress, checker = self.run_job(self.answering(), encrypt=encrypt_then_cancel, cancel=cancel)
        self.assertEqual((job.succeeded, job.failed, job.cancelled), (0, 0, True))
        self.assertEqual(progress[0][2], "Cancelled")
        checker.assert_not_called()
        self.assertEqual([p for p in self.output.rglob("*") if p.is_file()], [])


#: Stands in for gpg: reads the passphrase line, fills both pipes well past what they hold, then exits with 3.
_ECHOING = ("import sys; secret = sys.stdin.buffer.readline().strip(); sys.stderr.buffer.write(b'e' * 300000); "
            "sys.stderr.flush(); sys.stdout.buffer.write(secret + b'x' * 5000000); sys.exit(3)")


class RunGpgHashedTests(unittest.TestCase):
    """The pipe handling itself, with a small program standing in for gpg."""

    def test_hashes_everything_written_without_filling_a_pipe(self):
        code, stderr, digest = run_gpg_hashed([sys.executable, "-c", _ECHOING], threading.Event(), b"open sesame")
        self.assertEqual(code, 3)
        self.assertEqual(stderr, "e" * 300000)
        self.assertEqual(digest, hashlib.sha256(b"open sesame" + b"x" * 5000000).digest())

    def test_nothing_written_gives_the_hash_of_nothing(self):
        code, _, digest = run_gpg_hashed([sys.executable, "-c", "pass"], threading.Event(), b"unread")
        self.assertEqual((code, digest), (0, hashlib.sha256(b"").digest()))

    def test_cancel_stops_a_program_that_is_still_working(self):
        cancel = threading.Event()
        timer = threading.Timer(0.5, cancel.set)
        timer.start()
        self.addCleanup(timer.cancel)
        started = time.monotonic()
        with self.assertRaises(Cancelled):
            run_gpg_hashed([sys.executable, "-c", "import time; print('partial', flush=True); time.sleep(120)"],
                           cancel, b"secret")
        self.assertLess(time.monotonic() - started, 10)

    def test_a_problem_reading_the_output_is_an_error_not_a_hash_of_part_of_it(self):
        class Failing:
            def update(self, piece):
                raise OSError(5, "simulated read problem")

        # Once while the program is still writing, and once when it has already finished.
        for program in (_ECHOING, "print('short')"):
            with self.subTest(program), patch("mindyourownbytes.core.hashlib.sha256", return_value=Failing()), \
                    self.assertRaises(OSError):
                run_gpg_hashed([sys.executable, "-c", program], threading.Event(), b"secret")


class PostQuantumTests(unittest.TestCase):
    """Deciding what GnuPG can do, and reading what it says, with GnuPG stood in for."""

    GPG = str(Path(tempfile.gettempdir()).resolve() / "gpg")

    def supports(self, listing, version=(2, 5, 18), **mock):
        answer = subprocess.CompletedProcess([], 0, stdout=listing, stderr="")
        with patch("mindyourownbytes.core.gpg_version", return_value=version), patch(
            "mindyourownbytes.core.subprocess.run", return_value=answer, **mock
        ):
            return supports_post_quantum(self.GPG)

    def test_needs_gnupg_25_and_kyber(self):
        self.assertTrue(self.supports("cfg:pubkeyname:RSA;Kyber;ELG;DSA;ECDH;ECDSA;EDDSA\n"))
        self.assertTrue(self.supports("cfg:pubkeyname:RSA;KYBER\n"))
        self.assertFalse(self.supports("cfg:pubkeyname:RSA;ELG;DSA;ECDH;ECDSA;EDDSA\n"))
        self.assertFalse(self.supports("cfg:pubkeyname:RSA;Kyber\n", version=(2, 4, 7)))
        self.assertFalse(self.supports("cfg:pubkeyname:RSA;Kyber\n", version=None))
        self.assertFalse(self.supports(""))
        self.assertFalse(self.supports("", side_effect=OSError))
        self.assertFalse(self.supports("", side_effect=subprocess.TimeoutExpired("gpg", 8)))

    def test_user_ids_are_a_name_and_an_optional_email(self):
        self.assertEqual(user_id("  Alex Example ", ""), "Alex Example")
        self.assertEqual(user_id("Alex", " alex@example.invalid "), "Alex <alex@example.invalid>")
        self.assertEqual(user_id("Νίκος", ""), "Νίκος")
        for name, email in (("", ""), (" ", "a@b.c"), ("A <b>", ""), ("Line\nbreak", ""), ("x" * 101, ""),
                            ("Alex", "not an email"), ("Alex", "a@b"), ("Alex", "a b@c.d"), ("Alex", "<a@b.c>")):
            with self.subTest(name=name, email=email), self.assertRaises(ValueError):
                user_id(name, email)

    def make(self, returncode, stderr, call=None):
        answer = subprocess.CompletedProcess([], returncode, stdout=b"", stderr=stderr.encode())
        with patch("mindyourownbytes.core.supports_post_quantum", return_value=True), patch(
            "mindyourownbytes.core.subprocess.run", return_value=answer
        ) as run:
            result = (call or (lambda: create_post_quantum_key(self.GPG, "Alex <alex@example.invalid>")))()
        return result, run.call_args.args[0]

    def test_gnupg_asks_for_the_passphrase_itself_and_the_fingerprint_comes_back(self):
        fingerprint, argv = self.make(0, stderr_with_statuses("PINENTRY_LAUNCHED 1 1", f"KEY_CREATED B {'A' * 40}"))
        self.assertEqual(fingerprint, "A" * 40)
        self.assertEqual(argv[argv.index("--pinentry-mode") + 1], "ask")
        self.assertNotIn("--passphrase", argv)
        self.assertEqual(argv[-5:], ["--quick-generate-key", "Alex <alex@example.invalid>", "pqc", "default", "3y"])

    def test_adding_a_part_names_the_key_and_says_what_for(self):
        part, argv = self.make(0, stderr_with_statuses(f"KEY_CREATED S {'B' * 64}"),
                               lambda: add_post_quantum_subkey(self.GPG, "C" * 40))
        self.assertEqual(part, "B" * 64)
        self.assertEqual(argv[-5:], ["--quick-add-key", "C" * 40, "pqc", "encr", "3y"])

    def test_a_cancelled_prompt_is_named_as_such(self):
        with self.assertRaisesRegex(GpgFailure, "cancelled, so no key was made"):
            self.make(2, stderr_with_statuses("ERROR key_generate 83886179", "KEY_NOT_CREATED"))

    def test_any_other_failure_says_what_gnupg_said(self):
        with self.assertRaisesRegex(GpgFailure, "couldn't make the key: gpg: something went wrong"):
            self.make(2, "gpg: something went wrong\n" + stderr_with_statuses("FAILURE gpg-exit 33554433"))
        with self.assertRaisesRegex(GpgFailure, "couldn't make the key"):
            self.make(0, "")  # Success without a new key is no success.

    def test_nothing_runs_without_support_or_with_a_bad_fingerprint(self):
        with patch("mindyourownbytes.core.supports_post_quantum", return_value=False), patch(
            "mindyourownbytes.core.subprocess.run"
        ) as run:
            with self.assertRaisesRegex(GpgFailure, "GnuPG 2.5 or later"):
                create_post_quantum_key(self.GPG, "Alex")
            with self.assertRaises(ValueError):
                add_post_quantum_subkey(self.GPG, "not a fingerprint; rm -rf")
        run.assert_not_called()


class AvailableCiphersTests(unittest.TestCase):
    """A build of GnuPG, or someone's gpg.conf, can rule out an algorithm."""

    GPG = str(Path(tempfile.gettempdir()).resolve() / "gpg")

    def offered(self, stdout="", **mock):
        answer = subprocess.CompletedProcess([], 0, stdout=stdout, stderr="")
        with patch("mindyourownbytes.core.subprocess.run", return_value=answer, **mock):
            return [cipher.name for cipher in available_ciphers(self.GPG)]

    def test_lists_the_strong_ones_in_this_apps_order_and_never_the_old_ones(self):
        listing = "cfg:ciphername:IDEA;3DES;CAST5;BLOWFISH;AES;AES192;CAMELLIA256;TWOFISH;AES256;CAMELLIA128\n"
        self.assertEqual(self.offered(listing), ["AES256", "TWOFISH", "CAMELLIA256"])

    def test_leaves_out_what_this_gnupg_cannot_use(self):
        self.assertEqual(self.offered("cfg:ciphername:AES;AES256;TWOFISH\n"), ["AES256", "TWOFISH"])
        self.assertEqual(self.offered("cfg:ciphername:TWOFISH;CAMELLIA256\n"), ["TWOFISH", "CAMELLIA256"])

    def test_offers_only_the_default_if_gnupg_cannot_say(self):
        for listing in ("", "cfg:pubkey:1;2;3\n", "cfg:ciphername\n", "cfg:ciphername:IDEA;CAST5\n", "nonsense"):
            with self.subTest(listing):
                self.assertEqual(self.offered(listing), ["AES256"])
        self.assertEqual(self.offered(side_effect=OSError), ["AES256"])
        self.assertEqual(self.offered(side_effect=subprocess.TimeoutExpired("gpg", 8)), ["AES256"])

    def test_never_runs_a_relative_path(self):
        # The same rule as everywhere else: a planted gpg in this folder must never run.
        with patch("mindyourownbytes.core.subprocess.run") as run:
            self.assertEqual([cipher.name for cipher in available_ciphers("gpg")], ["AES256"])
        run.assert_not_called()


def key_record(kind, algorithm, bits="", *, created="1700000000", capabilities="e", validity="u", curve=""):
    """A pub or sub line from gpg --with-colons, with only the fields that matter here filled in."""
    fields = [""] * 21
    fields[:6] = [kind, validity, bits, algorithm, "0123456789ABCDEF", created]
    fields[11] = capabilities
    fields[16] = curve
    return ":".join(fields)


class KeyTypeTests(unittest.TestCase):
    """The key list has to name the key that GnuPG will really use."""

    PRIMARY = key_record("pub", "22", "255", capabilities="scE", curve="ed25519")

    def described(self, primary, *subkeys):
        details = [f"fpr{':' * 9}{'A' * 40}:", f"uid:u{':' * 8}Test <test@example.invalid>:"]
        listing = "\n".join([primary, *details, *subkeys])
        with patch("mindyourownbytes.core._list_keys",
                   side_effect=lambda binary, command: listing if command == "--list-keys" else ""):
            keys = list_public_keys("gpg")
        self.assertEqual(len(keys), 1)
        return keys[0].algorithm

    def test_names_each_kind_of_key(self):
        for expected, subkey in (
            ("RSA-3072", key_record("sub", "1", "3072")),
            ("ElGamal-2048", key_record("sub", "16", "2048")),
            ("Curve25519", key_record("sub", "18", "255", curve="cv25519")),
            ("Curve448", key_record("sub", "18", "448", curve="cv448")),
            ("NIST P-256", key_record("sub", "18", "256", curve="nistp256")),
            ("Brainpool P-384", key_record("sub", "18", "384", curve="brainpoolP384r1")),
            ("Kyber-768 (post-quantum)", key_record("sub", "8", "768", curve="ky768_bp256")),
            ("Kyber-1024 (post-quantum)", key_record("sub", "8", "1024", curve="ky1024_bp384")),
            ("secp256k1", key_record("sub", "18", "256", curve="secp256k1")),
            ("", key_record("sub", "99", "256")),
        ):
            with self.subTest(expected):
                self.assertEqual(self.described(self.PRIMARY, subkey), expected)

    def test_describes_the_newest_encryption_subkey(self):
        old = key_record("sub", "18", "255", created="1700000000", curve="cv25519")
        new = key_record("sub", "8", "768", created="1800000000", curve="ky768_bp256")
        self.assertEqual(self.described(self.PRIMARY, old, new), "Kyber-768 (post-quantum)")
        self.assertEqual(self.described(self.PRIMARY, new, old), "Kyber-768 (post-quantum)")

    def test_keeps_the_first_of_a_tie_as_gnupg_does(self):
        first = key_record("sub", "18", "255", curve="cv25519")
        second = key_record("sub", "1", "3072")
        self.assertEqual(self.described(self.PRIMARY, first, second), "Curve25519")

    def test_skips_a_newer_subkey_that_no_longer_works(self):
        works = key_record("sub", "18", "255", curve="cv25519")
        for validity in "erdni":
            with self.subTest(validity):
                dead = key_record("sub", "8", "768", created="1800000000", validity=validity)
                self.assertEqual(self.described(self.PRIMARY, works, dead), "Curve25519")

    def test_skips_a_newer_subkey_that_cannot_encrypt(self):
        works = key_record("sub", "1", "3072")
        signing = key_record("sub", "22", "255", created="1800000000", capabilities="s", curve="ed25519")
        self.assertEqual(self.described(self.PRIMARY, works, signing), "RSA-3072")

    def test_the_primary_key_only_counts_without_an_encryption_subkey(self):
        primary = key_record("pub", "1", "4096", created="1800000000", capabilities="scaeSCAE")
        self.assertEqual(self.described(primary), "RSA-4096")
        self.assertEqual(self.described(primary, key_record("sub", "18", "255", curve="cv25519")), "Curve25519")

    def test_each_key_gets_its_own_description(self):
        second_primary = key_record("pub", "22", "255", created="1600000000", capabilities="scE", curve="ed25519")
        listing = "\n".join([
            self.PRIMARY, f"fpr{':' * 9}{'A' * 40}:", f"uid:u{':' * 8}First <first@example.invalid>:",
            key_record("sub", "8", "768", created="1800000000", curve="ky768_bp256"),
            second_primary, f"fpr{':' * 9}{'B' * 40}:", f"uid:u{':' * 8}Second <second@example.invalid>:",
            key_record("sub", "18", "255", created="1600000000", curve="cv25519"),
        ])
        with patch("mindyourownbytes.core._list_keys",
                   side_effect=lambda binary, command: listing if command == "--list-keys" else ""):
            keys = list_public_keys("gpg")
        self.assertEqual({key.uid.split()[0]: key.algorithm for key in keys},
                         {"First": "Kyber-768 (post-quantum)", "Second": "Curve25519"})

    def test_a_missing_date_does_not_stop_the_list(self):
        self.assertEqual(self.described(self.PRIMARY, key_record("sub", "1", "2048", created="")), "RSA-2048")


if __name__ == "__main__":
    unittest.main()
