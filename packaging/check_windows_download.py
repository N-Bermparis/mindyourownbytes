"""Test the finished Windows download the way people will use it.

    python packaging/check_windows_download.py

Run this after build_windows.py. It inspects what's inside, runs the portable copy, then
installs for real: it runs the self-test from where the app landed, upgrades over it, and
uninstalls. Everything lands in a temporary folder, but while it runs the app appears in
the Start menu and in Settings > Apps, and its window opens briefly. It refuses to run if
the app is already installed. Results and pictures go to dist/check/.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import winreg
import zipfile
from fnmatch import fnmatch
from pathlib import Path

from build_windows import GNUPG_VERSION, RELEASE, app_version, sha256

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "dist" / "mindyourownbytes"
RESULTS = ROOT / "dist" / "check"
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{7F3B9C52-6E1D-4A8F-B0C4-2D95E1A7C364}_is1"
RUNNING_MUTEX = "mindyourownbytes-running"

REQUIRED_FILES = (
    "LICENSE.txt",
    "THIRD-PARTY-NOTICES.txt",
    "licenses/Python.txt",
    "licenses/PyInstaller.txt",
    "mindyourownbytes.exe",
    "_internal/mindyourownbytes/styles.qss",
    "_internal/PySide6/plugins/platforms/qwindows.dll",
    "_internal/PySide6/plugins/styles/qmodernwindowsstyle.dll",
    "gnupg/README.txt",
    "gnupg/bin/gpg.exe",
    "gnupg/bin/gpg-agent.exe",
    "gnupg/bin/gpgconf.exe",
    "gnupg/bin/pinentry-basic.exe",
    "gnupg/share/gnupg/distsigkey.gpg",
)
#: The README and the threat model promise that the app has no way to use the network by
#: itself. This keeps that true of what actually ships.
FORBIDDEN_FILES = (
    "*/Qt6Network.dll",
    "*/QtNetwork.pyd",
    "*/_socket*.pyd",
    "*/_ssl*.pyd",
    "*/libssl*",
    "*/libcrypto*",
    "*/dirmngr*",
    "*/gpg-wks-client*",
    "*/libntbtls*",
    "*/opengl32sw.dll",
    "gnupg/share/locale/*",
    "*.tmp",
)


def ensure(condition: object, message: str) -> None:
    if not condition:
        sys.exit(f"FAILED: {message}")
    print(f"ok: {message}", flush=True)


def check_contents() -> None:
    files = [path.relative_to(APP).as_posix() for path in APP.rglob("*") if path.is_file()]
    missing = [name for name in REQUIRED_FILES if name not in files]
    ensure(not missing, f"every required file is present {missing or ''}")
    unwanted = [name for name in files if any(fnmatch(name, pattern) for pattern in FORBIDDEN_FILES)]
    ensure(not unwanted, f"nothing that should be left out is included {unwanted or ''}")


def check_gnupg_is_official() -> None:
    """Each GnuPG file must still carry its publisher's signature, so it can't have been altered."""
    script = (
        "Get-ChildItem -LiteralPath $env:MYOB_FOLDER | Where-Object Extension -in '.exe','.dll' | ForEach-Object {"
        " $s = Get-AuthenticodeSignature -LiteralPath $_.FullName;"
        " '{0}|{1}|{2}' -f $_.Name, $s.Status, $s.SignerCertificate.Subject }"
    )
    output = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        env={**os.environ, "MYOB_FOLDER": str(APP / "gnupg" / "bin")},
        capture_output=True, text=True, timeout=120, check=True,
    ).stdout
    results = [line.split("|", 2) for line in output.splitlines() if line.strip()]
    wrong = [line for line in results if line[1] != "Valid" or "CN=g10 Code GmbH" not in line[2]]
    ensure(len(results) > 10 and not wrong, f"all {len(results)} GnuPG files are signed by g10 Code {wrong or ''}")


def check_gnupg_tools_start(environment: dict[str, str]) -> None:
    """A DLL that was left out by mistake would stop a tool from loading at all."""
    tools = sorted((APP / "gnupg" / "bin").glob("*.exe"))
    for tool in tools:
        result = subprocess.run([str(tool), "--version"], env=environment, capture_output=True, timeout=60, check=False)
        ensure(result.returncode == 0, f"{tool.name} starts")
    version = subprocess.run([str(APP / "gnupg" / "bin" / "gpg.exe"), "--version"], env=environment,
                             capture_output=True, text=True, timeout=60, check=True).stdout
    ensure(f"gpg (GnuPG) {GNUPG_VERSION}\n" in version, f"the included GnuPG is {GNUPG_VERSION}")


def check_checksums() -> None:
    lines = (RELEASE / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    listed = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in lines}
    actual = {path.name: sha256(path) for path in RELEASE.iterdir() if path.name != "SHA256SUMS.txt"}
    ensure(listed == actual and len(listed) == 3, "SHA256SUMS.txt lists every file, correctly")


def self_test(executable: Path, environment: dict[str, str], label: str, version: str) -> dict:
    folder = RESULTS / label
    shutil.rmtree(folder, ignore_errors=True)
    code = subprocess.run([str(executable), "--self-test", str(folder)], env=environment,
                          timeout=300, check=False).returncode
    report_file = folder / "self-test.json"
    ensure(report_file.is_file(), f"{label}: the self-test finished")
    report = json.loads(report_file.read_text(encoding="utf-8"))
    failed = [check for check in report["checks"] if not check["passed"]]
    ensure(code == 0 and not failed, f"{label}: all {len(report['checks'])} self-test checks pass {failed or ''}")
    ensure(report["frozen"] and report["version"] == version, f"{label}: it reports version {version}")
    ensure(report["platform"] == "windows", f"{label}: it ran with a real window")
    gnupg = Path(report["gnupg"])
    ensure(report["gnupg_included"] and gnupg.is_relative_to(executable.parent),
           f"{label}: it uses the included GnuPG, not {gnupg}")
    return report


def check_portable(archive: Path, scratch: Path, environment: dict[str, str], version: str) -> None:
    target = scratch / "Portable Τεστ"
    with zipfile.ZipFile(archive) as contents:
        contents.extractall(target)  # noqa: S202 - our own archive, just built
    self_test(target / "mindyourownbytes" / "mindyourownbytes.exe", environment, "portable", version)


def install(setup: Path, target: Path, environment: dict[str, str], log: Path) -> None:
    code = subprocess.run(
        [str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", f"/DIR={target}", f"/LOG={log}"],
        env=environment, timeout=300, check=False,
    ).returncode
    ensure(code == 0, f"the installer succeeds (exit code {code})")


def uninstall(target: Path, environment: dict[str, str], log: Path) -> bool:
    """Returns whether the app was removed. The real work happens in a temporary copy of the
    uninstaller that outlives the process started here, so this waits for its log to finish."""
    log.unlink(missing_ok=True)
    subprocess.run([str(target / "unins000.exe"), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", f"/LOG={log}"],
                   env=environment, timeout=300, check=False)
    deadline = time.monotonic() + 120
    while not (log.is_file() and "Log closed." in log.read_text(encoding="utf-8", errors="replace")):
        if time.monotonic() > deadline:
            sys.exit("FAILED: the uninstaller didn't finish")
        time.sleep(0.25)
    # Windows can take a moment to let go of the uninstaller's own file and folder.
    for _attempt in range(40):
        if not target.exists():
            return True
        time.sleep(0.25)
    return False


def is_in_use(path: Path) -> bool:
    try:
        with path.open("r+b"):
            return False
    except PermissionError:
        return True


def start_included_agent(target: Path, environment: dict[str, str]) -> Path:
    agent = target / "gnupg" / "bin" / "gpg-agent.exe"
    subprocess.run([str(target / "gnupg" / "bin" / "gpgconf.exe"), "--launch", "gpg-agent"],
                   env=environment, timeout=60, check=True)
    ensure(is_in_use(agent), "the included gpg-agent is running in the background")
    return agent


def app_is_open() -> bool:
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenMutexW(0x00100000, False, RUNNING_MUTEX)  # SYNCHRONIZE
    if handle:
        kernel32.CloseHandle(handle)
    return bool(handle)


def installed_entry() -> dict[str, str] | None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as key:
            return {name: winreg.QueryValueEx(key, name)[0]
                    for name in ("DisplayName", "DisplayVersion", "InstallLocation", "Publisher")}
    except FileNotFoundError:
        return None


def check_opening_and_closing(target: Path, environment: dict[str, str], log: Path) -> None:
    """Open the app the normal way. The uninstaller must then refuse to pull it from under itself."""
    window = subprocess.Popen([str(target / "mindyourownbytes.exe")], env=environment)
    try:
        for _attempt in range(120):
            if app_is_open():
                break
            time.sleep(0.25)
        ensure(app_is_open(), "the app opens normally")
        time.sleep(3)
        ensure(window.poll() is None, "the app is still open a few seconds later")
        removed = uninstall(target, environment, log)
        ensure(not removed and (target / "mindyourownbytes.exe").is_file() and installed_entry(),
               "the uninstaller won't remove the app while it's open")
    finally:
        window.kill()
        window.wait(timeout=30)


def check_installer(setup: Path, scratch: Path, environment: dict[str, str], version: str) -> None:
    # Spaces and non-ASCII letters, as in many people's user names.
    target = scratch / "Τα προγράμματά μου" / "mindyourownbytes"
    log = scratch / "setup.log"
    uninstall_log = scratch / "uninstall.log"
    roaming = Path(os.environ["APPDATA"])
    shortcut = roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "mindyourownbytes.lnk"

    # Whatever is here must survive. Created only if there is nothing to overwrite.
    vault = roaming / "mindyourownbytes" / "vault.gpg"
    created_vault = not vault.exists()
    if created_vault:
        vault.parent.mkdir(parents=True, exist_ok=True)
        vault.write_bytes(b"stand-in for someone's vault")
    vault_before = vault.read_bytes()
    try:
        install(setup, target, environment, log)
        entry = installed_entry()
        ensure(entry and entry["DisplayVersion"] == version, f"Settings > Apps lists version {version}")
        ensure(Path(entry["InstallLocation"].rstrip("\\")) == target, "it installed into the chosen folder")
        ensure(shortcut.is_file(), "the Start menu has a shortcut")
        self_test(target / "mindyourownbytes.exe", environment, "installed", version)

        # Installing over the top, with the included GnuPG still running from its folder.
        agent = start_included_agent(target, environment)
        install(setup, target, environment, log)
        ensure(not is_in_use(agent), "upgrading stops the included GnuPG first")
        self_test(target / "mindyourownbytes.exe", environment, "upgraded", version)

        check_opening_and_closing(target, environment, uninstall_log)

        start_included_agent(target, environment)
        ensure(uninstall(target, environment, uninstall_log), "uninstalling removes the whole folder")
        ensure(installed_entry() is None, "Settings > Apps no longer lists it")
        ensure(not shortcut.exists(), "the Start menu shortcut is gone")
        ensure(vault.is_file() and vault.read_bytes() == vault_before,
               "uninstalling leaves the saved passphrases alone")
    finally:
        if (target / "unins000.exe").is_file():
            uninstall(target, environment, uninstall_log)
        if created_vault:
            vault.unlink(missing_ok=True)
            if not any(vault.parent.iterdir()):
                vault.parent.rmdir()


def main() -> None:
    if installed_entry():
        sys.exit("mindyourownbytes is installed on this computer, and this test would replace it. Uninstall it first.")
    version = app_version()
    RESULTS.mkdir(parents=True, exist_ok=True)
    check_contents()
    check_gnupg_is_official()
    check_checksums()
    base_name = f"mindyourownbytes-{version}-windows-x64"
    with tempfile.TemporaryDirectory(prefix="myob-check-", ignore_cleanup_errors=True) as temporary:
        scratch = Path(temporary).resolve()
        # Looks like a computer without Gpg4win, and keeps GnuPG away from any real keys on this one.
        (scratch / "gnupg-home").mkdir()
        (scratch / "no-programs").mkdir()
        environment = {
            **os.environ,
            "GNUPGHOME": str(scratch / "gnupg-home"),
            "ProgramFiles": str(scratch / "no-programs"),
            "ProgramW6432": str(scratch / "no-programs"),
            "ProgramFiles(x86)": str(scratch / "no-programs"),
        }
        check_gnupg_tools_start(environment)
        check_portable(RELEASE / f"{base_name}-portable.zip", scratch, environment, version)
        check_installer(RELEASE / f"{base_name}-setup.exe", scratch, environment, version)
    print("Everything passed.", flush=True)


if __name__ == "__main__":
    main()
