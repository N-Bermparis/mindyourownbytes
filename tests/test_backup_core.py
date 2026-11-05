from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from backup_core import (
    SourceItem, collect_files, list_public_keys, output_relative,
    process_items, unique_target,
)


class FileLayoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "Research"
        (self.source / "QKD").mkdir(parents=True)
        (self.source / "QKD" / "report.pdf").write_bytes(b"Important research data")
        (self.source / "QKD" / "code.cpp").write_text("int main() { return 0; }")
        self.output = self.root / "encrypted"

    def test_folder_layout(self):
        files, skipped = collect_files([self.source], self.output, "encrypt")
        self.assertEqual((len(files), skipped), (2, 0))
        names = {str(output_relative(item, "encrypt")) for item in files}
        self.assertEqual(names, {
            str(Path("Research/QKD/report.pdf.gpg")),
            str(Path("Research/QKD/code.cpp.gpg")),
        })

    def test_rejects_recursive_output(self):
        with self.assertRaisesRegex(ValueError, "inside"):
            collect_files([self.source], self.source / "subdirectory", "encrypt")

    def test_unique_backup_preserves_previous_copy(self):
        name = self.output / "report.pdf.gpg"
        self.output.mkdir()
        name.write_bytes(b"existing ciphertext")
        self.assertEqual(unique_target(name).name, "report.pdf (2).gpg")

    def test_restore_requires_encrypted_extension(self):
        item = SourceItem(self.source / "QKD" / "report.pdf", Path("report.pdf"), 1)
        with self.assertRaises(ValueError):
            output_relative(item, "restore")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks not available")
    def test_skips_symlink(self):
        link = self.source / "link.txt"
        try:
            link.symlink_to(self.source / "QKD" / "report.pdf")
        except OSError:
            self.skipTest("Cannot create symlinks")
        files, skipped = collect_files([self.source], self.output, "encrypt")
        self.assertEqual(len(files), 2)
        self.assertGreaterEqual(skipped, 1)

    def test_failed_operation_removes_partial_outputs(self):
        item = SourceItem(self.source / "QKD" / "report.pdf", Path("report.pdf"), 20)

        def fail_and_leave_partially_written_data(argv, cancel):
            Path(argv[argv.index("--output") + 1]).write_bytes(b"partial")
            return 2, "simulated GnuPG failure"

        with patch("backup_core.is_valid_gpg", return_value=True), patch(
            "backup_core._run_gpg", side_effect=fail_and_leave_partially_written_data
        ):
            results = []
            job = process_items("mock-gpg", [item], self.output, "encrypt", "password",
                                None, threading.Event(), lambda *args: results.append(args))
        self.assertEqual((job.succeeded, job.failed), (0, 1))
        self.assertEqual(list(self.output.rglob("*")), [])

    def test_successful_publication_and_restore_paths(self):
        original = self.source / "QKD" / "report.pdf"
        input_item = SourceItem(original, Path("Research/QKD/report.pdf"), original.stat().st_size)

        def fake_encrypt(argv, cancel):
            self.assertIn("--symmetric", argv)
            self.assertIn("AES256", argv)
            Path(argv[argv.index("--output") + 1]).write_bytes(b"dummy encrypted bytes")
            return 0, ""

        with patch("backup_core.is_valid_gpg", return_value=True), patch(
            "backup_core._run_gpg", side_effect=fake_encrypt
        ):
            job = process_items("mock-gpg", [input_item], self.output, "encrypt", "password",
                                None, threading.Event(), lambda *args: None)
        self.assertEqual((job.succeeded, job.failed), (1, 0))
        self.assertEqual(job.outputs[0].relative_to(self.output), Path("Research/QKD/report.pdf.gpg"))
        self.assertEqual(job.outputs[0].read_bytes(), b"dummy encrypted bytes")
        self.assertFalse(any(self.output.rglob("*.partial")))

        def fake_decrypt(argv, cancel):
            self.assertIn("--decrypt", argv)
            Path(argv[argv.index("--output") + 1]).write_bytes(original.read_bytes())
            return 0, ""

        restore_item = SourceItem(job.outputs[0], Path("Research/QKD/report.pdf.gpg"),
                                  job.outputs[0].stat().st_size)
        with patch("backup_core.is_valid_gpg", return_value=True), patch(
            "backup_core._run_gpg", side_effect=fake_decrypt
        ):
            restored = process_items("mock-gpg", [restore_item], self.root / "restored", "restore",
                                     "password", None, threading.Event(), lambda *args: None)
        self.assertEqual((restored.succeeded, restored.failed), (1, 0))
        self.assertEqual(restored.outputs[0].read_bytes(), original.read_bytes())


@unittest.skipUnless(shutil.which("gpg"), "GnuPG not installed")
class GpgRoundTripTests(unittest.TestCase):
    def test_public_key_encrypt_restore_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gnupg = root / "gnupg"
            gnupg.mkdir(mode=0o700)
            original = root / "document.pdf"
            original.write_bytes(b"%PDF-1.4\nMYOB private test bytes\n")
            env = dict(os.environ, GNUPGHOME=str(gnupg))
            generated = subprocess.run([
                shutil.which("gpg"), "--batch", "--yes", "--pinentry-mode", "loopback",
                "--passphrase", "", "--quick-generate-key",
                "MYOB Unit Test <test@example.invalid>", "default", "default", "1d",
            ], env=env, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=40)
            if generated.returncode != 0:
                self.skipTest("GnuPG agent cannot generate an isolated test key in this environment")

            with patch.dict(os.environ, {"GNUPGHOME": str(gnupg)}):
                keys = list_public_keys(shutil.which("gpg"))
                self.assertEqual(len(keys), 1)
                fingerprint, _ = keys[0]
                report = [SourceItem(original, Path(original.name), original.stat().st_size)]
                events = []
                encrypted = process_items(
                    shutil.which("gpg"), report, root / "backups", "encrypt", "public-key",
                    fingerprint, threading.Event(), lambda *args: events.append(args),
                )
                self.assertEqual((encrypted.succeeded, encrypted.failed), (1, 0))
                self.assertTrue(encrypted.outputs[0].exists())
                self.assertNotIn(b"private test bytes", encrypted.outputs[0].read_bytes())

                restored_item = SourceItem(encrypted.outputs[0], Path(encrypted.outputs[0].name),
                                           encrypted.outputs[0].stat().st_size)
                first = process_items(
                    shutil.which("gpg"), [restored_item], root / "restored", "restore",
                    "public-key", None, threading.Event(), lambda *args: None,
                )
                second = process_items(
                    shutil.which("gpg"), [restored_item], root / "restored", "restore",
                    "public-key", None, threading.Event(), lambda *args: None,
                )
                self.assertEqual((first.succeeded, second.succeeded), (1, 1))
                self.assertNotEqual(first.outputs[0], second.outputs[0])
                self.assertEqual(first.outputs[0].read_bytes(), original.read_bytes())
                self.assertEqual(second.outputs[0].read_bytes(), original.read_bytes())


if __name__ == "__main__":
    unittest.main()
