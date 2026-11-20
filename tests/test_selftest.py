"""The check the release workflow runs on the finished download must be able to fail."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes import selftest
from tests.support import require_gpg

ROOT = Path(__file__).resolve().parent.parent
#: ``python -m mindyourownbytes``, with none of the standard places to find GnuPG. Outside Windows, the
#: app looks in /usr/bin and the like whatever PATH says, so an empty PATH alone doesn't hide it there.
WITHOUT_STANDARD_GPG = (
    "import runpy\n"
    "from mindyourownbytes import core\n"
    "core.STANDARD_GPG = {'darwin': (), 'linux': ()}\n"
    "runpy.run_module('mindyourownbytes', run_name='__main__', alter_sys=True)\n"
)


class PostQuantumRequirementTests(unittest.TestCase):
    def outcome(self, gpg: str, bundled: str | None) -> bool:
        checks = selftest._Checks()
        with patch.object(selftest.core, "supports_post_quantum", return_value=False), \
                patch.object(selftest.core, "bundled_gpg", return_value=bundled):
            selftest._check_post_quantum(checks, gpg, Path("unused"), Path("unused"))
        return checks.results[-1]["passed"]

    def test_required_only_of_the_gnupg_the_windows_download_brings(self):
        # Linux and macOS downloads use the computer's own GnuPG, which is often 2.2 or 2.4.
        self.assertTrue(self.outcome("/usr/bin/gpg", None))
        self.assertTrue(self.outcome(r"C:\Program Files\GnuPG\bin\gpg.exe", r"C:\app\gnupg\bin\gpg.exe"))
        self.assertFalse(self.outcome(r"C:\app\gnupg\bin\gpg.exe", r"C:\app\gnupg\bin\gpg.exe"))


class SelfTestTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="myobtest", ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)

    def run_self_test(self, *, standard_gpg: bool = True, **environment) -> tuple[int, dict]:
        start = ["-m", "mindyourownbytes"] if standard_gpg else ["-c", WITHOUT_STANDARD_GPG]
        result = subprocess.run(
            [sys.executable, *start, "--self-test", str(self.folder)],
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
                    "Twofish encrypts and restores", "Camellia-256 encrypts and restores",
                    "Checks each file after encrypting it", "The check refuses a damaged copy, keeping nothing",
                    "The check refuses a copy of something else, keeping nothing",
                    "Generates passphrases from the word list", "Recognizes a download as the file made here",
                    "Notices a file under another name", "Packs a folder into one checked archive",
                    "The archive hides the names inside", "Restores an archive into the same folder",
                    "Post-quantum keys work, where this GnuPG has them"}
        self.assertLessEqual(expected, names)

    def test_fails_without_gnupg(self):
        code, report = self.run_self_test(standard_gpg=False, PATH=str(self.folder), ProgramFiles="",
                                          ProgramW6432="", LOCALAPPDATA="", **{"ProgramFiles(x86)": ""})
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
