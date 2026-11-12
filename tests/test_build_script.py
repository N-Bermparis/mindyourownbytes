"""The parts of the Windows packaging that can be checked without building anything."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile
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


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, PACKAGING / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# build_unix uses build_windows, which is loaded above under the name it imports.
unix = _load("build_unix")
collect = _load("collect_release")


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
        self.handover = (ROOT / "mindyourownbytes" / "gui" / "handover.py").read_text(encoding="utf-8")

    def test_running_marker(self):
        name = re.search(r"AppMutex=(\S+)", self.installer).group(1)
        self.assertIn(f'RUNNING_MUTEX = "{name}"', self.handover)
        self.assertIn("CreateMutexW(None, False, RUNNING_MUTEX)", self.handover)
        self.assertIn(f'RUNNING_MUTEX = "{name}"', self.check)

    def right_click_entries(self) -> list[str]:
        return [line for line in self.installer.splitlines() if "\\shell\\mindyourownbytes" in line]

    def test_right_click_entries_are_for_this_account_and_go_with_the_app(self):
        entries = self.right_click_entries()
        self.assertEqual(len(entries), 8)
        for line in entries:
            self.assertTrue(line.startswith("Root: HKCU;"), line)
        for kind in ("*", "Directory"):
            top = [line for line in entries if f'Subkey: "Software\\Classes\\{kind}\\shell\\mindyourownbytes";' in line
                   and "Tasks: rightclick" in line and "ValueName" not in line]
            self.assertEqual(len(top), 1, kind)
            self.assertIn("uninsdeletekey", top[0])

    def test_right_click_passes_only_the_path(self):
        commands = [line for line in self.right_click_entries() if "\\command" in line]
        self.assertEqual(len(commands), 2)
        for line in commands:
            self.assertIn('ValueData: """{app}\\mindyourownbytes.exe"" ""%1"""', line)
        self.assertIn('"Encrypt with mindyourownbytes"', self.check)
        self.assertIn('"%1"', self.check)

    def test_right_click_entry_can_be_left_out(self):
        self.assertIn('Name: "rightclick"', self.installer)
        removals = [line for line in self.right_click_entries() if "Tasks: not rightclick" in line]
        self.assertEqual(len(removals), 2)
        for line in removals:
            self.assertIn("deletekey", line)

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


class UnixDownloadTests(unittest.TestCase):
    def test_names_say_the_system_and_the_processor_as_download_pages_do(self):
        cases = (("linux", "x86_64", "linux-x86_64"), ("linux", "AMD64", "linux-x86_64"),
                 ("darwin", "arm64", "macos-arm64"), ("linux", "aarch64", "linux-arm64"))
        for platform_name, machine, expected in cases:
            with self.subTest(system=platform_name, machine=machine):
                self.assertEqual(unix.base_name("1.2.3", platform_name, machine), f"mindyourownbytes-1.2.3-{expected}")

    def test_the_release_notes_name_the_files_each_build_makes(self):
        # The Windows build writes the notes, so it must name the Linux and Mac downloads as build_unix does.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "dist").mkdir()
            (root / "CHANGELOG.md").write_text("## [9.8.7] - Unreleased\n\nNew things.\n", encoding="utf-8")
            checksums = root / "SHA256SUMS.txt"
            checksums.write_text("abc  x\n", encoding="utf-8")
            with patch.object(build, "ROOT", root):
                notes = build.write_release_notes("9.8.7", Path("a-setup.exe"), Path("a-portable.zip"),
                                                  checksums).read_text(encoding="utf-8")
        self.assertIn(f"{unix.base_name('9.8.7', 'linux', 'x86_64')}.tar.gz", notes)
        self.assertIn(f"{unix.base_name('9.8.7', 'darwin', 'arm64')}.dmg", notes)
        self.assertEqual(notes.count("```text"), 1, "one list of checksums, for collect_release.py to replace")
        self.assertIn("New things.", notes)

    def test_the_notices_name_what_each_download_holds(self):
        notices = (PACKAGING / "THIRD-PARTY-NOTICES-unix.txt").read_text(encoding="utf-8")
        filled = notices.format(version="1.2.3", libraries="_internal", qt="6.12.0", qt_series="6.12",
                                python="3.14.3", pyinstaller="6.22.3")
        self.assertIn("isn't included here", filled)
        self.assertIn('"_internal/PySide6"', filled)


class AddToMenuTests(unittest.TestCase):
    SCRIPT = PACKAGING / "linux" / "add-to-menu.sh"

    def test_keeps_unix_line_endings_even_in_a_windows_checkout(self):
        self.assertNotIn(b"\r", self.SCRIPT.read_bytes())

    @unittest.skipIf(os.name == "nt" or shutil.which("sh") is None, "runs the script as Linux does")
    def test_adds_an_entry_that_starts_the_app_where_it_was_unpacked(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / "unpacked here"
            folder.mkdir()
            shutil.copy2(self.SCRIPT, folder / "add-to-menu.sh")
            (folder / "mindyourownbytes.png").write_bytes(b"png")
            data = Path(temporary) / "data"
            subprocess.run(["sh", str(folder / "add-to-menu.sh")], check=True, capture_output=True,
                           env={**os.environ, "XDG_DATA_HOME": str(data)})
            entry = (data / "applications" / "mindyourownbytes.desktop").read_text(encoding="utf-8")
            self.assertIn(f'Exec="{folder}/mindyourownbytes" %F', entry)
            self.assertTrue((data / "icons" / "hicolor" / "256x256" / "apps" / "mindyourownbytes.png").is_file())


class CollectReleaseTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.artifacts = self.root / "downloads"
        windows = self.artifacts / "windows-download"
        (windows / "release").mkdir(parents=True)
        for name in ("app-setup.exe", "app-portable.zip", "gnupg-source.tar.xz", "SHA256SUMS.txt"):
            (windows / "release" / name).write_bytes(name.encode())
        (windows / "release-notes.md").write_text("Notes\n\n```text\nonly windows\n```\n\nEnd\n", encoding="utf-8")
        # Uploaded as one folder, so their files sit at the top of the artifact.
        for part, name in (("linux-download", "app-linux.tar.gz"), ("macos-download", "app-macos.dmg")):
            (self.artifacts / part).mkdir()
            (self.artifacts / part / name).write_bytes(name.encode())
            (self.artifacts / part / "SHA256SUMS.txt").write_bytes(b"its own list")

    def test_one_folder_with_every_download_and_one_list_of_checksums(self):
        release = collect.collect(self.artifacts, self.root / "dist")
        names = sorted(path.name for path in release.iterdir())
        self.assertEqual(names, ["SHA256SUMS.txt", "app-linux.tar.gz", "app-macos.dmg", "app-portable.zip",
                                 "app-setup.exe", "gnupg-source.tar.xz"])
        checksums = (release / "SHA256SUMS.txt").read_text(encoding="utf-8")
        for name in names[1:]:
            self.assertIn(f"{hashlib.sha256(name.encode()).hexdigest()}  {name}\n", checksums)
        notes = (self.root / "dist" / "release-notes.md").read_text(encoding="utf-8")
        self.assertIn(checksums, notes)
        self.assertNotIn("only windows", notes)
        self.assertTrue(notes.endswith("End\n"))

    def test_a_missing_download_stops_the_release(self):
        shutil.rmtree(self.artifacts / "macos-download")
        with self.assertRaises(SystemExit) as stopped:
            collect.collect(self.artifacts, self.root / "dist")
        self.assertIn("macos-download", str(stopped.exception))

    def test_two_downloads_that_make_the_same_file_stop_the_release(self):
        (self.artifacts / "linux-download" / "app-macos.dmg").write_bytes(b"different")
        with self.assertRaises(SystemExit):
            collect.collect(self.artifacts, self.root / "dist")


if __name__ == "__main__":
    unittest.main()
