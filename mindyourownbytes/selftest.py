"""Prove that a built copy of the app really works, without touching anyone's data.

``mindyourownbytes.exe --self-test FOLDER`` opens the real window and does a real encrypt
and restore in a throwaway GnuPG home. The release workflow runs it on the finished
download. A windowed app has no console, so the results go to FOLDER/self-test.json, with
a picture of the window beside it, and the exit code says whether everything passed.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
import traceback
from pathlib import Path
from urllib.parse import unquote

from PySide6 import __version__ as pyside_version
from PySide6.QtCore import QSettings

from mindyourownbytes import __version__, core
from mindyourownbytes.gui import icons
from mindyourownbytes.gui.main_window import MainWindow, create_application

#: Not a secret: it only ever protects the test data below.
PASSPHRASE = "self-test passphrase, not a secret"  # noqa: S105
#: Not plain ASCII, because people's names and files aren't.
FILE_NAME = "Τεστ αρχείο résumé.txt"
CONTENT = bytes(range(256)) * 256


class _Checks:
    def __init__(self) -> None:
        self.results: list[dict[str, str | bool]] = []

    def record(self, name: str, passed: object, detail: object = "") -> bool:
        self.results.append({"name": name, "passed": bool(passed), "detail": str(detail)})
        return bool(passed)


def _check_interface(checks: _Checks, report: dict, folder: Path, scratch: Path) -> None:
    app = create_application()
    style = app.style().objectName()
    report.update(platform=app.platformName(), style=style)
    # Qt quietly falls back to its plain "windows" style if the native one failed to load.
    checks.record("A native style loaded", style.lower() in ("windows11", "fusion"), style)

    icon = icons.app_icon().pixmap(32, 32).toImage()
    checks.record("Icons draw", icon.pixelColor(16, 16).alpha() > 0)

    settings = QSettings(str(scratch / "settings.ini"), QSettings.Format.IniFormat)
    window = MainWindow(settings=settings, vault_path=scratch / "vault.gpg")
    window.show()
    app.processEvents()
    picture = window.grab()
    checks.record("The window draws", not picture.isNull() and picture.save(str(folder / "window.png")))
    checks.record("The window sees GnuPG", "ready" in window.gpg_status.text(), window.gpg_status.text())
    window.close()
    app.processEvents()


def _job(gpg: str, source: Path, output: Path, operation: core.Operation, method: core.Method,
         fingerprint: str | None = None, passphrases: tuple[str, ...] = ()) -> core.JobResult:
    items = core.collect_files([source], output, operation).items
    return core.process_items(gpg, items, output, operation, method, fingerprint, threading.Event(),
                              lambda *_: None, passphrases=passphrases)


def _is_restored(result: core.JobResult) -> bool:
    return result.succeeded == 1 and result.outputs[0].read_bytes() == CONTENT


def _check_passphrase_round_trip(checks: _Checks, gpg: str, source: Path, scratch: Path) -> None:
    encrypted = _job(gpg, source, scratch / "passphrase-encrypted", "encrypt", "password",
                     passphrases=(PASSPHRASE,))
    if not checks.record("Encrypts with a passphrase", encrypted.succeeded == 1):
        return
    output = encrypted.outputs[0]
    checks.record("The encrypted file doesn't contain the original",
                  CONTENT[:1024] not in output.read_bytes() and core.peek_protection(output) == "passphrase")
    wrong_folder = scratch / "passphrase-wrong"
    wrong = _job(gpg, output, wrong_folder, "restore", "password", passphrases=("not the passphrase",))
    checks.record("Refuses a wrong passphrase, writing nothing",
                  wrong.failed == 1 and not wrong.outputs
                  and not (wrong_folder.exists() and any(wrong_folder.iterdir())))
    restored = _job(gpg, output, scratch / "passphrase-restored", "restore", "password", passphrases=(PASSPHRASE,))
    checks.record("Restores with a passphrase", _is_restored(restored))


def _check_key_round_trip(checks: _Checks, gpg: str, source: Path, scratch: Path) -> None:
    """A private key is only ever handled by gpg-agent, so this also proves that it can start."""
    created = subprocess.run(
        [gpg, "--batch", "--no-tty", "--passphrase", "", "--pinentry-mode", "loopback",
         "--quick-generate-key", "Self test <self-test@example.invalid>", "default", "default", "1d"],
        capture_output=True, timeout=120, check=False, creationflags=core.windows_flags(),
    )
    if not checks.record("Creates a key", created.returncode == 0, created.stderr[-300:].decode(errors="replace")):
        return
    keys = core.list_public_keys(gpg)
    if not checks.record("Lists the key", len(keys) == 1 and keys[0].has_secret, keys):
        return
    encrypted = _job(gpg, source, scratch / "key-encrypted", "encrypt", "public-key", keys[0].fingerprint)
    if not checks.record("Encrypts to the key", encrypted.succeeded == 1):
        return
    restored = _job(gpg, encrypted.outputs[0], scratch / "key-restored", "restore", "public-key")
    checks.record("Restores with the key", _is_restored(restored))


def _check_passphrase_prompt(checks: _Checks, gpgconf: Path) -> None:
    """The window that asks for a passphrase can't be clicked from here, but it can be located."""
    components = subprocess.run(
        [str(gpgconf), "--list-components"], capture_output=True, timeout=60, check=False,
        creationflags=core.windows_flags(),
    ).stdout.decode(errors="replace")
    fields = next((line.split(":") for line in components.splitlines() if line.startswith("pinentry:")), [])
    program = unquote(fields[2]) if len(fields) > 2 else ""
    checks.record("GnuPG can find its passphrase window", program and Path(program).is_file(), program)


def _check_gnupg(checks: _Checks, report: dict, scratch: Path) -> None:
    gpg = core.find_gpg()
    included = gpg is not None and gpg == core.bundled_gpg()
    version = core.gpg_version(gpg) if gpg else None
    report.update(gnupg=gpg, gnupg_version=".".join(map(str, version or ())), gnupg_included=included)
    if not checks.record("Finds a working GnuPG", gpg and core.is_valid_gpg(gpg), gpg):
        return

    source = scratch / "originals" / FILE_NAME
    source.parent.mkdir()
    source.write_bytes(CONTENT)
    _check_passphrase_round_trip(checks, gpg, source, scratch)
    _check_key_round_trip(checks, gpg, source, scratch)
    if included:
        _check_passphrase_prompt(checks, _gpgconf(gpg))


def _gpgconf(gpg: str) -> Path:
    return Path(gpg).with_name("gpgconf.exe" if os.name == "nt" else "gpgconf")


def _stop_gnupg() -> None:
    """Whatever GnuPG started would otherwise keep its files open, and outlive this process."""
    gpg = core.find_gpg()
    if gpg:
        subprocess.run([str(_gpgconf(gpg)), "--kill", "all"], capture_output=True, timeout=60, check=False,
                       creationflags=core.windows_flags())


def run(folder: Path) -> int:
    """Returns the exit code for the process: 0 only if every check passed."""
    folder.mkdir(parents=True, exist_ok=True)
    checks = _Checks()
    report: dict = {
        "version": __version__,
        "python": platform.python_version(),
        "pyside": pyside_version,
        "frozen": bool(getattr(sys, "frozen", False)),
        "checks": checks.results,
    }
    try:
        with tempfile.TemporaryDirectory(prefix="myob-self-test-", ignore_cleanup_errors=True) as temporary:
            scratch = Path(temporary)
            # Set first, because the window looks for keys as soon as it opens.
            home = scratch / "gnupg-home"
            home.mkdir(mode=0o700)
            os.environ["GNUPGHOME"] = str(home)
            try:
                _check_interface(checks, report, folder, scratch)
                _check_gnupg(checks, report, scratch)
            finally:
                _stop_gnupg()
    except Exception:
        checks.record("Finishes without an unexpected error", False, traceback.format_exc())
    report["passed"] = all(check["passed"] for check in checks.results)
    (folder / "self-test.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0 if report["passed"] else 1
