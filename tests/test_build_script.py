"""The parts of the Windows packaging that can be checked without building anything."""

from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import mindyourownbytes

ROOT = Path(__file__).resolve().parent.parent
PACKAGING = ROOT / "packaging"

_spec = importlib.util.spec_from_file_location("build_windows", PACKAGING / "build_windows.py")
build = importlib.util.module_from_spec(_spec)
sys.modules["build_windows"] = build
_spec.loader.exec_module(build)


class PinTests(unittest.TestCase):
    def test_every_download_is_pinned_and_https(self):
        for download in (build.GNUPG, build.GNUPG_SOURCE, build.INNO_SETUP):
            self.assertTrue(download.url.startswith("https://"), download.url)
            self.assertRegex(download.sha256, r"^[0-9a-f]{64}$")

    def test_gnupg_version_matches_its_files(self):
        self.assertIn(f"gnupg-w32-{build.GNUPG_VERSION}_", build.GNUPG.name)
        self.assertIn(f"gnupg-w32-{build.GNUPG_VERSION}_", build.GNUPG_SOURCE.name)

    def test_build_requirements_are_hash_locked(self):
        text = (ROOT / "requirements-build.txt").read_text(encoding="utf-8")
        self.assertIn("pyinstaller==", text)
        self.assertIn("--hash=sha256:", text)


class NewestGnupgTests(unittest.TestCase):
    def test_compares_versions_as_numbers(self):
        listing = """
            <a href="gnupg-w32-2.5.9_20250710.exe">x</a> <a href="gnupg-w32-2.5.9_20250710.exe.sig">x</a>
            <a href="gnupg-w32-2.5.24_20260923.exe">x</a> <a href="gnupg-w32-2.5.24_20260923.wixlib">x</a>
            <a href="gnupg-w32-2.4.8_20250514.exe">x</a> <a href="gnupg-w32cli-1.4.23.exe">x</a>
        """
        self.assertEqual(build.newest_gnupg_build(listing), "gnupg-w32-2.5.24_20260923.exe")

    def test_a_rebuild_of_the_same_version_counts_as_newer(self):
        listing = '"gnupg-w32-2.5.24_20260923.exe" "gnupg-w32-2.5.24_20261001.exe"'
        self.assertEqual(build.newest_gnupg_build(listing), "gnupg-w32-2.5.24_20261001.exe")

    def test_an_unreadable_listing_fails_rather_than_passing(self):
        with self.assertRaises(SystemExit):
            build.newest_gnupg_build("<html>This page has moved</html>")

    def test_out_of_date_gnupg_fails_and_says_what_to_do(self):
        with patch.object(build, "newest_gnupg_build", return_value="gnupg-w32-9.9.9_20990101.exe"), patch.object(
            build, "read_gnupg_listing", return_value=""
        ), self.assertRaises(SystemExit) as stopped:
            build.check_gnupg_is_current()
        self.assertIn("docs/RELEASE_CHECKLIST.md", str(stopped.exception))

    def test_current_gnupg_passes(self):
        with patch.object(build, "newest_gnupg_build", return_value=build.GNUPG.name), patch.object(
            build, "read_gnupg_listing", return_value=""
        ), patch("builtins.print"):
            build.check_gnupg_is_current()


class VersionTests(unittest.TestCase):
    def test_reads_the_same_version_as_the_app(self):
        self.assertEqual(build.app_version(), mindyourownbytes.__version__)

    def test_changelog_has_a_section_for_this_version(self):
        section = build.changelog_section(mindyourownbytes.__version__)
        self.assertIn("### Added", section)
        self.assertNotRegex(section, r"(?m)^## \[")

    def test_a_version_without_a_changelog_section_stops_the_build(self):
        with self.assertRaises(SystemExit):
            build.changelog_section("99.0.0")


class RecipesAgreeTests(unittest.TestCase):
    """Each of these names is written in several places, and a mismatch fails silently."""

    def setUp(self):
        self.installer = (PACKAGING / "installer.iss").read_text(encoding="utf-8")
        self.check = (PACKAGING / "check_windows_download.py").read_text(encoding="utf-8")
        self.window = (ROOT / "mindyourownbytes" / "gui" / "main_window.py").read_text(encoding="utf-8")

    def test_running_marker(self):
        name = re.search(r"AppMutex=(\S+)", self.installer).group(1)
        self.assertIn(f'CreateMutexW(None, False, "{name}")', self.window)
        self.assertIn(f'RUNNING_MUTEX = "{name}"', self.check)

    def test_taskbar_identity(self):
        name = re.search(r'AppUserModelID: "([^"]+)"', self.installer).group(1)
        self.assertIn(f'SetCurrentProcessExplicitAppUserModelID("{name}")', self.window)

    def test_install_identity(self):
        app_id = re.search(r"AppId=\{(\{[0-9A-F-]{36}\})", self.installer).group(1)
        self.assertIn(f"Uninstall\\{app_id}_is1", self.check)

    def test_the_uninstaller_never_touches_peoples_data(self):
        self.assertNotIn("[UninstallDelete]", self.installer)
        self.assertNotIn("{userappdata}", self.installer)
        self.assertNotIn("{userdocs}", self.installer)


if __name__ == "__main__":
    unittest.main()
