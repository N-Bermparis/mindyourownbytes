"""Optional code signing of the downloads. No credentials exist here, so the signing tools are stood in for.

What can be checked without them: that nothing is signed unless fully set up, that half a setup fails
rather than building unsigned, the exact commands and their order, that every signature is verified
afterwards, and that the release workflow only offers signing to version tags.
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("signing", ROOT / "packaging" / "signing.py")
signing = importlib.util.module_from_spec(_spec)
sys.modules["signing"] = signing
_spec.loader.exec_module(signing)

THUMBPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
SIGNING_NAMES = ("MYOB_SIGN_CERT_SHA1", "MYOB_SIGN_TIMESTAMP_URL", "MYOB_MAC_SIGN_IDENTITY", "MYOB_NOTARY_KEY_PATH",
                 "MYOB_NOTARY_KEY_ID", "MYOB_NOTARY_ISSUER")


def environment(**values):
    return patch.dict(os.environ, {**dict.fromkeys(SIGNING_NAMES, ""), **values})


def completed(stdout: str = "", code: int = 0):
    return subprocess.CompletedProcess([], code, stdout, "")


class SettingsTests(unittest.TestCase):
    def test_nothing_set_means_unsigned_and_says_so(self):
        with environment():
            self.assertIsNone(signing.windows_signing())
            self.assertIsNone(signing.mac_signing())
        with patch.object(signing.sys, "platform", "win32"):
            self.assertIn("UNSIGNED", signing.describe())
        with patch.object(signing.sys, "platform", "darwin"):
            self.assertIn("UNSIGNED", signing.describe())

    def test_half_a_setup_fails_instead_of_building_unsigned(self):
        with environment(MYOB_SIGN_CERT_SHA1=THUMBPRINT), self.assertRaisesRegex(signing.SigningError, "half"):
            signing.windows_signing()
        with environment(MYOB_NOTARY_KEY_ID="ABC", MYOB_NOTARY_ISSUER="x", MYOB_NOTARY_KEY_PATH="k.p8"), \
                self.assertRaisesRegex(signing.SigningError, "signed app"):
            signing.mac_signing()

    def test_settings_are_checked(self):
        for thumbprint in ("not hex", THUMBPRINT[:-1], THUMBPRINT + "0"):
            with environment(MYOB_SIGN_CERT_SHA1=thumbprint, MYOB_SIGN_TIMESTAMP_URL="http://ts.example"), \
                    self.subTest(thumbprint), self.assertRaises(signing.SigningError):
                signing.windows_signing()
        with environment(MYOB_SIGN_CERT_SHA1=THUMBPRINT, MYOB_SIGN_TIMESTAMP_URL="ts.example; rm -rf /"), \
                self.assertRaises(signing.SigningError):
            signing.windows_signing()
        with environment(MYOB_MAC_SIGN_IDENTITY="Apple Development: Someone"), self.assertRaises(signing.SigningError):
            signing.mac_signing()

    def test_a_full_setup_is_read(self):
        spaced = " ".join(THUMBPRINT[i:i + 2] for i in range(0, 40, 2)).lower()
        with environment(MYOB_SIGN_CERT_SHA1=spaced, MYOB_SIGN_TIMESTAMP_URL="http://ts.example/rfc3161"):
            self.assertEqual(signing.windows_signing(), signing.WindowsSigning(THUMBPRINT, "http://ts.example/rfc3161"))
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "key.p8"
            key.write_text("not a real key")
            with environment(MYOB_MAC_SIGN_IDENTITY="Developer ID Application: Someone (TEAM123456)",
                             MYOB_NOTARY_KEY_PATH=str(key), MYOB_NOTARY_KEY_ID="KEY", MYOB_NOTARY_ISSUER="ISSUER"):
                self.assertEqual(signing.mac_signing().notary, (key, "KEY", "ISSUER"))


class WindowsTests(unittest.TestCase):
    def test_signs_with_sha256_and_a_timestamp_then_verifies_each_file(self):
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if command[0] == "powershell":
                self.assertNotIn(str(kwargs["env"]["MYOB_FILE"]), " ".join(command), "paths go by environment")
                return completed(f"Valid|{THUMBPRINT}|True")
            return completed()

        files = [Path("dist/app.exe"), Path("dist/setup.exe")]
        with patch.object(signing, "find_signtool", return_value=Path("signtool.exe")), \
                patch.object(signing.subprocess, "run", side_effect=run):
            signing.sign_windows(files, signing.WindowsSigning(THUMBPRINT, "http://ts.example"))
        sign = calls[0]
        self.assertEqual(sign[:2], ["signtool.exe", "sign"])
        expected = (("/sha1", THUMBPRINT), ("/fd", "SHA256"), ("/tr", "http://ts.example"), ("/td", "SHA256"))
        for option, value in expected:
            self.assertEqual(sign[sign.index(option) + 1], value)
        self.assertEqual(sign[-2:], [str(file) for file in files])
        self.assertEqual(sum(command[0] == "powershell" for command in calls), 2, "every file is checked")

    def test_a_signature_that_doesnt_check_out_fails_the_build(self):
        for answer in ("NotSigned||False", f"HashMismatch|{THUMBPRINT}|True", "Valid|" + "F" * 40 + "|True",
                       f"Valid|{THUMBPRINT}|False"):
            with self.subTest(answer), patch.object(signing.subprocess, "run", return_value=completed(answer)), \
                    self.assertRaises(signing.SigningError):
                signing.verify_windows(Path("app.exe"), THUMBPRINT)


class MacTests(unittest.TestCase):
    IDENTITY = "Developer ID Application: Someone (TEAM123456)"

    def app(self, folder: Path) -> Path:
        app = folder / "mindyourownbytes.app"
        (app / "Contents" / "MacOS").mkdir(parents=True)
        (app / "Contents" / "Frameworks" / "QtCore.framework").mkdir(parents=True)
        (app / "Contents" / "MacOS" / "mindyourownbytes").write_bytes(b"\xcf\xfa\xed\xfe main")
        (app / "Contents" / "Frameworks" / "QtCore.framework" / "QtCore").write_bytes(b"\xcf\xfa\xed\xfe lib")
        (app / "Contents" / "Frameworks" / "libpython.dylib").write_bytes(b"\xca\xfe\xba\xbe fat")
        (app / "Contents" / "Info.plist").write_bytes(b"<plist/>")
        return app

    def test_every_executable_part_is_signed_deepest_first_then_the_app_then_checked(self):
        calls = []
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(signing.subprocess, "run", side_effect=lambda c, **k: calls.append(c) or completed()):
            app = self.app(Path(folder))
            signing.sign_mac_app(app, signing.MacSigning(self.IDENTITY, None))
        signed = [Path(command[-1]).name for command in calls if command[:2] == ["codesign", "--force"]]
        self.assertEqual(signed, ["QtCore", "libpython.dylib", "mindyourownbytes.app"])
        for command in calls:
            if command[:2] == ["codesign", "--force"]:
                self.assertIn("runtime", command, "the hardened runtime, which notarization requires")
                self.assertIn("--timestamp", command)
        self.assertEqual(calls[-1][:3], ["codesign", "--verify", "--deep"])

    def test_notarizing_needs_apples_acceptance_and_a_stapled_ticket(self):
        calls = []

        def run(command, **kwargs):
            calls.append(command)
            if "notarytool" in command:
                return completed('{"id": "1", "status": "Accepted"}')
            return completed()

        notary = (Path("key.p8"), "KEY", "ISSUER")
        with patch.object(signing.subprocess, "run", side_effect=run):
            signing.sign_mac_image(Path("app.dmg"), signing.MacSigning(self.IDENTITY, notary))
        tools = [command[1] if command[0] == "xcrun" else command[0] for command in calls]
        self.assertEqual(tools, ["codesign", "notarytool", "stapler", "stapler", "spctl"])
        submit = calls[1]
        self.assertEqual(submit[submit.index("--key") + 1], "key.p8", "the key goes by path, never by content")
        with patch.object(signing.subprocess, "run",
                          side_effect=lambda c, **k: completed('{"status": "Invalid"}') if "notarytool" in c
                          else completed()), self.assertRaisesRegex(signing.SigningError, "didn't accept"):
            signing.sign_mac_image(Path("app.dmg"), signing.MacSigning(self.IDENTITY, notary))

    def test_a_failing_tool_stops_the_build(self):
        with patch.object(signing.subprocess, "run", return_value=completed(code=1)), \
                self.assertRaises(signing.SigningError):
            signing.sign_mac_image(Path("app.dmg"), signing.MacSigning(self.IDENTITY, None))


class WorkflowTests(unittest.TestCase):
    """The release workflow only reaches for signing settings on a version tag, and signs nothing otherwise."""

    def setUp(self):
        self.text = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    def test_signing_settings_reach_only_tag_builds(self):
        for name in ("WINDOWS_SIGN_CERT_SHA1", "WINDOWS_SIGN_TIMESTAMP_URL", "MAC_SIGN_IDENTITY", "MAC_NOTARY_KEY_ID",
                     "MAC_NOTARY_ISSUER"):
            for line in (line for line in self.text.splitlines() if f"vars.{name}" in line and "MYOB_" in line):
                with self.subTest(line.strip()):
                    self.assertIn("github.ref_type == 'tag'", line)

    def test_secrets_are_used_only_in_jobs_or_steps_that_run_for_tags(self):
        lines = self.text.splitlines()
        for number, line in enumerate(lines):
            if "secrets." in line:
                # From the start of the job the secret is in, which is where its condition would be.
                start = max(index for index in range(number) if lines[index].startswith("  ")
                            and not lines[index].startswith("   ") and lines[index].rstrip().endswith(":"))
                condition = r"if: \$\{\{ (always\(\) && )?github\.ref_type == 'tag'"
                with self.subTest(line.strip()):
                    self.assertRegex("\n".join(lines[start:number]), condition)

    def test_the_checksum_signature_job_can_not_write(self):
        job = self.text.split("  sign-checksums:")[1].split("\n  publish:")[0]
        self.assertIn("contents: read", job)
        self.assertNotRegex(job, r":\s*write")
        self.assertIn("VALIDSIG", job, "the signature is checked with only the public key")


if __name__ == "__main__":
    unittest.main()
