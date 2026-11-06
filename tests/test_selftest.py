"""The check the release workflow runs on the finished download must be able to fail."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.support import require_gpg

ROOT = Path(__file__).resolve().parent.parent


class SelfTestTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="myobtest", ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)

    def run_self_test(self, **environment) -> tuple[int, dict]:
        result = subprocess.run(
            [sys.executable, "-m", "mindyourownbytes", "--self-test", str(self.folder)],
            cwd=ROOT, env={**os.environ, "QT_QPA_PLATFORM": "offscreen", **environment},
            capture_output=True, timeout=300, check=False,
        )
        report = json.loads((self.folder / "self-test.json").read_text(encoding="utf-8"))
        return result.returncode, report

    def test_passes_with_a_working_gnupg(self):
        require_gpg()
        code, report = self.run_self_test()
        self.assertEqual([check for check in report["checks"] if not check["passed"]], [])
        self.assertEqual(code, 0)
        self.assertGreater((self.folder / "window.png").stat().st_size, 0)
        self.assertGreater((self.folder / "window-with-a-file.png").stat().st_size, 0)
        names = {check["name"] for check in report["checks"]}
        expected = {"Restores with a passphrase", "Restores with the key", "The window draws",
                    "Added files appear in the list", "Saved passphrases survive being locked",
                    "The window offers every algorithm", "AES-256 encrypts and restores",
                    "Twofish encrypts and restores", "Camellia-256 encrypts and restores"}
        self.assertLessEqual(expected, names)

    def test_fails_without_gnupg(self):
        code, report = self.run_self_test(PATH=str(self.folder), ProgramFiles="", ProgramW6432="",
                                          LOCALAPPDATA="", **{"ProgramFiles(x86)": ""})
        self.assertEqual(code, 1)
        self.assertFalse(report["passed"])
        self.assertIn({"name": "Finds a working GnuPG", "passed": False, "detail": "None"}, report["checks"])

    def test_does_not_touch_the_real_gnupg_home(self):
        require_gpg()
        real_home = self.folder / "real-home"
        real_home.mkdir()
        code, _report = self.run_self_test(GNUPGHOME=str(real_home))
        self.assertEqual(code, 0)
        self.assertEqual(list(real_home.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
