"""Optional code signing of the downloads. No credentials exist here, so the signing tools are stood in for.

What can be checked without them: that nothing is signed unless fully set up, that half a setup fails
rather than building unsigned, the exact commands and their order, that every signature is verified
afterwards, and that the release workflow only offers signing to version tags.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.support import GpgTestCase

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
        self.assertNotRegex(job, r":\s*write\b")
        self.assertIn("VALIDSIG", job, "the signature is checked with only the public key")
        # The same check finds a job that can write, so that it can't pass by never matching anything.
        self.assertRegex(self.text.split("\n  publish:")[1], r":\s*write\b")

    def test_a_release_waits_for_the_tag_check_which_runs_nothing_from_the_repository(self):
        job = self.text.split("\n  tag:")[1].split("\n  collect:")[0]
        self.assertIn("vars.TAG_SIGNING_FINGERPRINTS", job)
        self.assertNotIn("secrets.", job)
        self.assertNotRegex(job, r":\s*write")
        self.assertNotRegex(job, r"python|\.py\b|\./", "only reads the keys file")
        collect = self.text.split("\n  collect:")[1].split("\n  sign-checksums:")[0]
        self.assertIn("needs: [tag, ", collect)


def step_script(workflow: str, name: str) -> str:
    """A step's shell script from a workflow file, exactly as the runner gets it."""
    lines = workflow.splitlines()
    start = lines.index(f"      - name: {name}")
    run = next(index for index in range(start, len(lines)) if lines[index].strip() == "run: |")
    body = []
    for line in lines[run + 1:]:
        if line.strip() and not line.startswith(" " * 10):
            break
        body.append(line[10:])
    return "\n".join(body) + "\n"


def posix_shell() -> str | None:
    """bash, but never WSL's on Windows: Git for Windows' own, which comes with GnuPG."""
    if os.name != "nt":
        return shutil.which("bash")
    git = shutil.which("git")
    for parent in Path(git).resolve().parents if git else ():
        if (parent / "bin" / "bash.exe").is_file():
            return str(parent / "bin" / "bash.exe")
    return None


class TagCheckTests(GpgTestCase):
    """The release workflow's check of who signed a tag, run as written, with real git and GnuPG."""

    def setUp(self):
        super().setUp()
        self.bash = posix_shell()
        if self.bash is None or shutil.which("git") is None:
            self.skipTest("needs git and bash")
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.script = self.root / "check.sh"
        self.script.write_text(step_script(workflow, "Check who signed the tag"), encoding="utf-8", newline="\n")
        # Nothing from this computer's own git settings, such as signing every tag with an SSH key. And the
        # GnuPG the tests use: on Windows, git would otherwise pick Git's own, which can't find a home that
        # Git Bash names as /tmp/... once git has turned it into a Windows path.
        empty = self.root / "gitconfig"
        empty.write_text("", encoding="utf-8")
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": str(empty), "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "gpg.program", "GIT_CONFIG_VALUE_0": self.gpg}
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        (self.repo / "README").write_text("release\n", encoding="utf-8")
        self.git("add", "README")
        self.git("commit", "-q", "-m", "release")
        self.maintainer = self.generate_key("Maintainer <maintainer@example.invalid>")
        self.other = self.generate_key("Someone Else <someone@example.invalid>")

    def git(self, *args: str) -> subprocess.CompletedProcess:
        command = ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                   "-c", f"gpg.program={self.gpg}", *args]
        result = subprocess.run(command, cwd=self.repo, env=self.env, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def publish_keys(self, *fingerprints: str) -> None:
        (self.repo / "packaging").mkdir(exist_ok=True)
        exported = self.run_gpg("--armor", "--export", *fingerprints).stdout
        (self.repo / "packaging" / "release-keys.asc").write_bytes(exported)

    def check(self, tag: str, expected: str) -> tuple[int, str, str]:
        output, summary = self.root / "output", self.root / "summary"
        output.write_text("", encoding="utf-8")
        summary.write_text("", encoding="utf-8")
        env = {**self.env, "TAG": tag, "EXPECTED": expected, "GITHUB_OUTPUT": output.as_posix(),
               "GITHUB_STEP_SUMMARY": summary.as_posix()}
        result = subprocess.run([self.bash, self.script.as_posix()], cwd=self.repo, env=env, capture_output=True,
                                text=True, check=False, timeout=120)
        return result.returncode, result.stdout + result.stderr, output.read_text(encoding="utf-8")

    def test_a_tag_signed_by_an_expected_key_passes_and_names_it(self):
        self.publish_keys(self.maintainer, self.other)
        self.git("tag", "-s", "-u", self.maintainer, "-m", "v1.0.0", "v1.0.0")
        code, said, output = self.check("v1.0.0", f"{self.other.lower()}\n{self.maintainer.lower()}")
        self.assertEqual(code, 0, said)
        self.assertEqual(output.strip(), f"signer={self.maintainer}")

    def test_nothing_set_up_means_a_warning_not_a_check(self):
        self.git("tag", "v1.0.0")
        code, said, output = self.check("v1.0.0", " \n")
        self.assertEqual(code, 0, said)
        self.assertIn("::warning title=Tag signature not checked::", said)
        self.assertEqual(output, "")

    def test_every_other_tag_stops_the_release(self):
        self.publish_keys(self.maintainer, self.other)
        self.git("tag", "light")
        self.git("tag", "-a", "-m", "unsigned", "unsigned")
        self.git("tag", "-s", "-u", self.other, "-m", "other", "other")
        cases = {"light": "lightweight", "unsigned": "no good signature", "other": "isn't in TAG_SIGNING_FINGERPRINTS"}
        for tag, reason in cases.items():
            with self.subTest(tag):
                code, said, output = self.check(tag, self.maintainer)
                self.assertEqual(code, 1, said)
                self.assertIn(reason, said)
                self.assertEqual(output, "")

    def test_a_key_that_isnt_published_or_a_missing_keys_file_stops_it(self):
        self.git("tag", "-s", "-u", self.maintainer, "-m", "v1.0.0", "v1.0.0")
        code, said, _output = self.check("v1.0.0", self.maintainer)
        self.assertEqual(code, 1, said)
        self.assertIn("release-keys.asc", said)
        self.publish_keys(self.other)
        code, said, _output = self.check("v1.0.0", self.maintainer)
        self.assertEqual(code, 1, said)
        self.assertIn("no good signature", said)


if __name__ == "__main__":
    unittest.main()
