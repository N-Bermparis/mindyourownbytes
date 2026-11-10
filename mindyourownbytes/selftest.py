"""Prove that a built copy of the app really works, without touching anyone's data.

``mindyourownbytes.exe --self-test FOLDER`` opens the real window and does a real encrypt
and restore in a throwaway GnuPG home. The release workflow runs it on the finished
download. A windowed app has no console, so the results go to FOLDER/self-test.json, with
pictures of the window beside it, and the exit code says whether everything passed.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import traceback
from collections.abc import Callable
from pathlib import Path

from PySide6 import __version__ as pyside_version
from PySide6.QtCore import QSettings

from mindyourownbytes import __version__, core, generator
from mindyourownbytes.gui import icons
from mindyourownbytes.gui.main_window import MainWindow, create_application
from mindyourownbytes.vault import Vault, WrongMasterPassphrase, generate_passphrase

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


def _check_interface(checks: _Checks, report: dict, folder: Path, scratch: Path, source: Path) -> None:
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
    offered = [window.algorithm_combo.itemData(row) for row in range(window.algorithm_combo.count())]
    checks.record("The window offers every algorithm", offered == [cipher.name for cipher in core.CIPHERS], offered)
    window.add_paths([str(source)])
    app.processEvents()
    checks.record("Added files appear in the list", [item.source.name for item in window.items] == [source.name])
    window.grab().save(str(folder / "window-with-a-file.png"))
    window.close()
    app.processEvents()


def _job(gpg: str, source: Path, output: Path, operation: core.Operation, method: core.Method,
         fingerprint: str | None = None, passphrases: tuple[str, ...] = (),
         cipher: str = core.DEFAULT_CIPHER) -> core.JobResult:
    items = core.collect_files([source], output, operation).items
    return core.process_items(gpg, items, output, operation, method, fingerprint, threading.Event(),
                              lambda *_: None, passphrases=passphrases, cipher=cipher)


def _is_restored(result: core.JobResult) -> bool:
    return result.succeeded == 1 and result.outputs[0].read_bytes() == CONTENT


def _check_passphrase_round_trip(checks: _Checks, gpg: str, source: Path, scratch: Path) -> None:
    encrypted = _job(gpg, source, scratch / "passphrase-encrypted", "encrypt", "password",
                     passphrases=(PASSPHRASE,))
    if not checks.record("Encrypts with a passphrase", encrypted.succeeded == 1):
        return
    checks.record("Checks each file after encrypting it", encrypted.checked == 1)
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


def _refuses(gpg: str, source: Path, folder: Path, spoil: Callable[[Path], None]) -> tuple[bool, str]:
    """Encrypt, but change the new file just before it's checked, as a failing disk could.

    Returns whether the check then refused the file and kept nothing, with what it said.
    """
    said: list[str] = []

    def spoil_the_new_file(_index: int) -> None:
        spoil(next(folder.glob(".myob-*.partial")))

    items = core.collect_files([source], folder, "encrypt").items
    result = core.process_items(gpg, items, folder, "encrypt", "password", None, threading.Event(),
                                lambda _index, _ok, message, _output: said.append(message),
                                passphrases=(PASSPHRASE,), on_checking=spoil_the_new_file)
    refused = result.failed == 1 and not result.outputs and said[-1].startswith("Check failed")
    return refused and not any(folder.iterdir()), said[-1]


def _check_the_check(checks: _Checks, gpg: str, source: Path, scratch: Path) -> None:
    """A check that can't fail proves nothing, so each of these gives it something wrong to find."""
    def damage(staged: Path) -> None:
        data = bytearray(staged.read_bytes())
        data[len(data) // 2] ^= 0xFF
        staged.write_bytes(bytes(data))

    checks.record("The check refuses a damaged copy, keeping nothing",
                  *_refuses(gpg, source, scratch / "damaged", damage))

    # Encrypted properly, with the same passphrase, but from other content. Only comparing can tell.
    name = "The check refuses a copy of something else, keeping nothing"
    decoy = scratch / "decoy.txt"
    decoy.write_bytes(b"not the original\n")
    other = _job(gpg, decoy, scratch / "decoy-encrypted", "encrypt", "password", passphrases=(PASSPHRASE,))
    if other.succeeded != 1:
        checks.record(name, False, "could not encrypt a second file to swap in")
        return

    def swap(staged: Path) -> None:
        shutil.copyfile(other.outputs[0], staged)

    checks.record(name, *_refuses(gpg, source, scratch / "swapped", swap))


def _check_every_algorithm(checks: _Checks, gpg: str, source: Path, scratch: Path) -> None:
    """Each one is separate code in GnuPG, so one could go missing without affecting the others."""
    for cipher in core.CIPHERS:
        name = f"{cipher.label} encrypts and restores"
        encrypted = _job(gpg, source, scratch / f"{cipher.name}-encrypted", "encrypt", "password",
                         passphrases=(PASSPHRASE,), cipher=cipher.name)
        if not encrypted.succeeded:
            checks.record(name, False, "could not encrypt")
            continue
        listing = subprocess.run(
            [gpg, "--batch", "--no-tty", "--pinentry-mode", "cancel", "--list-packets", str(encrypted.outputs[0])],
            capture_output=True, encoding="utf-8", errors="replace", timeout=60, check=False,
            creationflags=core.windows_flags(),
        ).stdout
        restored = _job(gpg, encrypted.outputs[0], scratch / f"{cipher.name}-restored", "restore", "password",
                        passphrases=(PASSPHRASE,))
        checks.record(name, f"cipher {cipher.packet_id}," in listing and _is_restored(restored), listing[:120])


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


def _check_generator(checks: _Checks) -> None:
    """The word list is a separate file, which the download has to bring along unchanged."""
    try:
        phrase = generator.word_passphrase()
        listed = set(generator.words())
        detail = ""
    except (OSError, RuntimeError) as exc:
        phrase, listed, detail = "", set(), str(exc)
    # Each word has at least three letters, so a whole passphrase has at least this many characters.
    checks.record("Generates passphrases from the word list",
                  len(listed) == generator.WORD_COUNT and len(phrase) >= generator.DEFAULT_WORDS * 4 - 1, detail)


def _check_vault(checks: _Checks, gpg: str, scratch: Path) -> None:
    """This also covers Python's random numbers and hashing, which the download's trimming could break."""
    path = scratch / "vault" / "vault.gpg"
    path.parent.mkdir()
    saved = generate_passphrase()
    vault = Vault(gpg, path)
    vault.create(PASSPHRASE)
    vault.add("Self test", saved)
    vault.lock()
    reopened = Vault(gpg, path)
    try:
        reopened.unlock("not the master passphrase")
        refused = False
    except WrongMasterPassphrase:
        refused = True
    checks.record("The vault refuses a wrong master passphrase", refused)
    reopened.unlock(PASSPHRASE)
    checks.record("Saved passphrases survive being locked", [entry.passphrase for entry in reopened.entries] == [saved])


def _check_gnupg(checks: _Checks, report: dict, source: Path, scratch: Path) -> None:
    gpg = core.find_gpg()
    included = gpg is not None and gpg == core.bundled_gpg()
    version = core.gpg_version(gpg) if gpg else None
    report.update(gnupg=gpg, gnupg_version=".".join(map(str, version or ())), gnupg_included=included)
    if not checks.record("Finds a working GnuPG", gpg and core.is_valid_gpg(gpg), gpg):
        return

    _check_passphrase_round_trip(checks, gpg, source, scratch)
    _check_the_check(checks, gpg, source, scratch)
    _check_every_algorithm(checks, gpg, source, scratch)
    _check_key_round_trip(checks, gpg, source, scratch)
    _check_generator(checks)
    _check_vault(checks, gpg, scratch)


def _stop_gnupg() -> None:
    """Whatever GnuPG started would otherwise keep its files open, and outlive this process."""
    gpg = core.find_gpg()
    if gpg:
        gpgconf = Path(gpg).with_name("gpgconf.exe" if os.name == "nt" else "gpgconf")
        subprocess.run([str(gpgconf), "--kill", "all"], capture_output=True, timeout=60, check=False,
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
            source = scratch / "originals" / FILE_NAME
            source.parent.mkdir()
            source.write_bytes(CONTENT)
            try:
                _check_interface(checks, report, folder, scratch, source)
                _check_gnupg(checks, report, source, scratch)
            finally:
                _stop_gnupg()
    except Exception:
        checks.record("Finishes without an unexpected error", False, traceback.format_exc())
    report["passed"] = all(check["passed"] for check in checks.results)
    (folder / "self-test.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return 0 if report["passed"] else 1
