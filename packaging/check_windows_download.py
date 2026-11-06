"""Test the finished Windows download the way people will use it.

    python packaging/check_windows_download.py

Run this after build_windows.py. It only looks at dist/release/, the files people actually
get. It inspects the zip's contents, runs that portable copy, then installs for real: it
runs the self-test from where the app landed, upgrades over it, and uninstalls.

Almost everything lands in a temporary folder, but for a moment the app also installs into
its usual folder, and appears in the Start menu and in Settings > Apps, and its windows open
briefly. It refuses to run if the app is already installed. Your GnuPG keys aren't touched.
Results and pictures go to dist/check/.
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
from ctypes import wintypes
from fnmatch import fnmatch
from pathlib import Path

from build_windows import GNUPG_VERSION, RELEASE, app_version, sha256

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "dist" / "check"
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{7F3B9C52-6E1D-4A8F-B0C4-2D95E1A7C364}_is1"
RUNNING_MUTEX = "mindyourownbytes-running"
#: Not a secret: it only ever protects test data. Long enough that GnuPG doesn't query its quality.
PASSPHRASE = "correct horse battery staple 1729 !"  # noqa: S105

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
#: The README and the threat model promise that the download holds no network code of its
#: own. This keeps that true of what actually ships.
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

user32 = ctypes.WinDLL("user32")
kernel32 = ctypes.WinDLL("kernel32")
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.OpenMutexW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
kernel32.OpenMutexW.restype = wintypes.HANDLE
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
]
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPCWSTR]
user32.SendMessageW.restype = ctypes.c_ssize_t
_ENUM_WINDOWS = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
_SYNCHRONIZE = 0x00100000
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_WM_CLOSE = 0x0010
_WM_SETTEXT = 0x000C
_BM_CLICK = 0x00F5


def ensure(condition: object, message: str) -> None:
    if not condition:
        sys.exit(f"FAILED: {message}")
    print(f"ok: {message}", flush=True)


def check_checksums() -> None:
    lines = (RELEASE / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    listed = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in lines}
    actual = {path.name: sha256(path) for path in RELEASE.iterdir() if path.name != "SHA256SUMS.txt"}
    ensure(listed == actual and len(listed) == 3, "SHA256SUMS.txt lists every file, correctly")


def check_contents(app: Path) -> None:
    files = [path.relative_to(app).as_posix() for path in app.rglob("*") if path.is_file()]
    missing = [name for name in REQUIRED_FILES if name not in files]
    ensure(not missing, f"every required file is present {missing or ''}")
    unwanted = [name for name in files if any(fnmatch(name, pattern) for pattern in FORBIDDEN_FILES)]
    ensure(not unwanted, f"nothing that should be left out is included {unwanted or ''}")


def check_gnupg_is_official(app: Path) -> None:
    """Each GnuPG file must still carry its publisher's signature, so it can't have been altered."""
    script = (
        "$ErrorActionPreference = 'Stop';"
        "Get-ChildItem -LiteralPath $env:MYOB_FOLDER | Where-Object Extension -in '.exe','.dll' | ForEach-Object {"
        " $s = Get-AuthenticodeSignature -LiteralPath $_.FullName;"
        " '{0}|{1}|{2}' -f $_.Name, $s.Status, $s.SignerCertificate.Subject }"
    )
    # When started from PowerShell 7, as on CI, this variable points Windows PowerShell at
    # modules it can't load, and the signature command then isn't available.
    environment = {name: value for name, value in os.environ.items() if name.upper() != "PSMODULEPATH"}
    environment["MYOB_FOLDER"] = str(app / "gnupg" / "bin")
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        env=environment, capture_output=True, text=True, timeout=120, check=False,
    )
    ensure(result.returncode == 0, f"signatures can be read {result.stderr[-600:]}")
    results = [line.split("|", 2) for line in result.stdout.splitlines() if line.strip()]
    wrong = [line for line in results if line[1] != "Valid" or "CN=g10 Code GmbH" not in line[2]]
    ensure(len(results) > 10 and not wrong, f"all {len(results)} GnuPG files are signed by g10 Code {wrong or ''}")


def check_gnupg_tools_start(app: Path, environment: dict[str, str]) -> None:
    """A DLL that was left out by mistake would stop a tool from loading at all."""
    tools = sorted((app / "gnupg" / "bin").glob("*.exe"))
    for tool in tools:
        result = subprocess.run([str(tool), "--version"], env=environment, capture_output=True, timeout=60, check=False)
        ensure(result.returncode == 0, f"{tool.name} starts")
    version = subprocess.run([str(app / "gnupg" / "bin" / "gpg.exe"), "--version"], env=environment,
                             capture_output=True, text=True, timeout=60, check=True).stdout
    ensure(f"gpg (GnuPG) {GNUPG_VERSION}\n" in version, f"the included GnuPG is {GNUPG_VERSION}")


def _controls(window: int) -> list[tuple[int, str, str]]:
    found = []

    @_ENUM_WINDOWS
    def visit(control, _parameter):
        kind = ctypes.create_unicode_buffer(80)
        text = ctypes.create_unicode_buffer(300)
        user32.GetClassNameW(control, kind, len(kind))
        user32.GetWindowTextW(control, text, len(text))
        found.append((control, kind.value, text.value.replace("&", "")))
        return True

    user32.EnumChildWindows(window, visit, 0)
    return found


def _visible_windows() -> list[int]:
    found = []

    @_ENUM_WINDOWS
    def visit(window, _parameter):
        if user32.IsWindowVisible(window):
            found.append(window)
        return True

    user32.EnumWindows(visit, 0)
    return found


def _process_id(window: int) -> int:
    process_id = wintypes.DWORD()
    user32.GetWindowThreadProcessId(window, ctypes.byref(process_id))
    return process_id.value


def _process_path(window: int) -> str:
    process = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, _process_id(window))
    if not process:
        return ""
    path = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(path))
    kernel32.QueryFullProcessImageNameW(process, 0, path, ctypes.byref(size))
    kernel32.CloseHandle(process)
    return path.value


def _passphrase_windows(program: Path) -> list[int]:
    """Only this exact copy's windows, so that nothing else on the computer gets touched."""
    return [window for window in _visible_windows()
            if os.path.normcase(_process_path(window)) == os.path.normcase(program)]


def _run_answering_prompts(command: list[str], program: Path, environment: dict[str, str],
                           button: str) -> tuple[int, int]:
    """Run gpg, and answer its passphrase windows as a person would. Returns its exit code and the prompt count."""
    process = subprocess.Popen(command, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    prompts = 0
    deadline = time.monotonic() + 90
    while process.poll() is None:
        if time.monotonic() > deadline:
            process.kill()
            sys.exit(f"FAILED: gpg was still waiting after {prompts} passphrase windows")
        for window in _passphrase_windows(program):
            controls = {(kind.lower(), text): control for control, kind, text in _controls(window)}
            field = next((control for (kind, _text), control in controls.items() if kind == "edit"), None)
            press = controls.get(("button", button))
            if field and press:
                user32.SendMessageW(field, _WM_SETTEXT, 0, PASSPHRASE)
                user32.SendMessageW(press, _BM_CLICK, 0, None)
                prompts += 1
                while window in _passphrase_windows(program) and time.monotonic() < deadline:
                    time.sleep(0.05)
        time.sleep(0.05)
    return process.returncode, prompts


def check_passphrase_window(app: Path, scratch: Path, environment: dict[str, str]) -> None:
    """Tools > Let GnuPG ask for each passphrase depends on this window, which only the included GnuPG provides."""
    gnupg = app / "gnupg" / "bin"
    program = gnupg / "pinentry-basic.exe"
    folder = scratch / "passphrase-window"
    folder.mkdir()
    original = folder / "original.txt"
    original.write_bytes(b"passphrase window test\n" * 100)
    encrypted = folder / "encrypted.gpg"
    restored = folder / "restored.txt"
    gpg = [str(gnupg / "gpg.exe"), "--batch", "--no-tty", "--no-symkey-cache", "--pinentry-mode", "ask"]
    encrypt = [*gpg, "--symmetric", "--cipher-algo", "AES256", "--output", str(encrypted), str(original)]
    try:
        code, prompts = _run_answering_prompts(encrypt, program, environment, "OK")
        ensure(code == 0 and prompts == 2 and encrypted.is_file(),
               f"GnuPG's own window asks twice to encrypt (exit code {code}, {prompts} windows)")
        restore = [*gpg, "--output", str(restored), "--decrypt", str(encrypted)]
        code, prompts = _run_answering_prompts(restore, program, environment, "OK")
        ensure(code == 0 and prompts == 1 and restored.read_bytes() == original.read_bytes(),
               f"GnuPG's own window asks once to restore (exit code {code}, {prompts} windows)")
        cancelled = folder / "cancelled.txt"
        cancel = [*gpg, "--output", str(cancelled), "--decrypt", str(encrypted)]
        code, prompts = _run_answering_prompts(cancel, program, environment, "Cancel")
        ensure(code != 0 and prompts == 1 and not cancelled.exists(), "cancelling GnuPG's own window stops cleanly")
    finally:
        subprocess.run([str(gnupg / "gpgconf.exe"), "--kill", "all"], env=environment, timeout=60, check=False,
                       creationflags=subprocess.CREATE_NO_WINDOW)


def self_test(executable: Path, environment: dict[str, str], label: str, version: str) -> dict:
    folder = RESULTS / label
    shutil.rmtree(folder, ignore_errors=True)
    code = subprocess.run([str(executable), "--self-test", str(folder)], env=environment,
                          timeout=180, check=False).returncode
    report_file = folder / "self-test.json"
    ensure(report_file.is_file(), f"{label}: the self-test finished")
    report = json.loads(report_file.read_text(encoding="utf-8"))
    failed = [check for check in report["checks"] if not check["passed"]]
    ensure(code == 0 and not failed, f"{label}: all {len(report['checks'])} self-test checks pass {failed or ''}")
    ensure(report["frozen"] and report["version"] == version, f"{label}: it reports version {version}")
    ensure(report["platform"] == "windows", f"{label}: it ran with a real window, in the {report['style']} style")
    gnupg = Path(report["gnupg"])
    ensure(report["gnupg_included"] and gnupg.is_relative_to(executable.parent),
           f"{label}: it uses the included GnuPG, not {gnupg}")
    return report


def install(setup: Path, target: Path | None, environment: dict[str, str], log: Path) -> None:
    command = [str(setup), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", f"/LOG={log}"]
    if target:
        command.append(f"/DIR={target}")
    code = subprocess.run(command, env=environment, timeout=300, check=False).returncode
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


def stops_being_used(path: Path) -> bool:
    for _attempt in range(40):
        if not is_in_use(path):
            return True
        time.sleep(0.25)
    return False


def start_included_agent(target: Path, environment: dict[str, str]) -> Path:
    agent = target / "gnupg" / "bin" / "gpg-agent.exe"
    subprocess.run([str(target / "gnupg" / "bin" / "gpgconf.exe"), "--launch", "gpg-agent"],
                   env=environment, timeout=60, check=True)
    ensure(is_in_use(agent), "the included gpg-agent is running in the background")
    return agent


def app_is_open() -> bool:
    handle = kernel32.OpenMutexW(_SYNCHRONIZE, False, RUNNING_MUTEX)
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


def installed_folder() -> Path | None:
    entry = installed_entry()
    return Path(entry["InstallLocation"].rstrip("\\")) if entry else None


def file_hashes(folder: Path) -> dict[str, str]:
    return {path.relative_to(folder).as_posix(): sha256(path) for path in folder.rglob("*") if path.is_file()}


def check_usual_folder(setup: Path, environment: dict[str, str], log: Path, uninstall_log: Path) -> None:
    """Everyone using the wizard gets this folder, without administrator rights."""
    usual = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "mindyourownbytes"
    try:
        install(setup, None, environment, log)
        ensure(installed_folder() == usual, r"by default it installs into %LOCALAPPDATA%\Programs")
        ensure((usual / "mindyourownbytes.exe").is_file(), "the app is in that folder")
        ensure(uninstall(usual, environment, uninstall_log), "the default installation uninstalls")
    finally:
        # Wherever it really landed, if the checks above stopped this early.
        folder = installed_folder()
        if folder and (folder / "unins000.exe").is_file():
            uninstall(folder, environment, uninstall_log)


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

        agent = start_included_agent(target, environment)
        for visible in _visible_windows():
            if _process_id(visible) == window.pid:
                user32.PostMessageW(visible, _WM_CLOSE, 0, 0)
        ensure(window.wait(timeout=30) == 0, "the app closes cleanly")
        ensure(stops_being_used(agent), "closing the app stops the included GnuPG")
    finally:
        if window.poll() is None:
            window.kill()
            window.wait(timeout=30)


def check_installer(setup: Path, portable: Path, scratch: Path, environment: dict[str, str], version: str) -> None:
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
        check_usual_folder(setup, environment, log, uninstall_log)

        install(setup, target, environment, log)
        entry = installed_entry()
        ensure(entry and entry["DisplayVersion"] == version, f"Settings > Apps lists version {version}")
        ensure(installed_folder() == target, "it installed into the chosen folder")
        ensure(shortcut.is_file(), "the Start menu has a shortcut")
        installed = {name: value for name, value in file_hashes(target).items() if not name.startswith("unins000.")}
        ensure(installed == file_hashes(portable), "the installer and the zip hold exactly the same app")
        self_test(target / "mindyourownbytes.exe", environment, "installed", version)

        # Installing over the top, with the included GnuPG still running from its folder.
        agent = start_included_agent(target, environment)
        install(setup, target, environment, log)
        ensure(stops_being_used(agent), "upgrading stops the included GnuPG first")
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
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if installed_entry():
        sys.exit("mindyourownbytes is installed on this computer, and this test would replace it. Uninstall it first.")
    version = app_version()
    base_name = f"mindyourownbytes-{version}-windows-x64"
    RESULTS.mkdir(parents=True, exist_ok=True)
    check_checksums()
    with tempfile.TemporaryDirectory(prefix="myob-check-", ignore_cleanup_errors=True) as temporary:
        scratch = Path(temporary).resolve()
        # Looks like a computer without Gpg4win, and keeps GnuPG away from any real keys on this
        # one. PATH matters too: Windows would load a DLL missing from the download from there.
        (scratch / "gnupg-home").mkdir()
        (scratch / "no-programs").mkdir()
        windows = os.environ["SYSTEMROOT"]
        environment = {
            **os.environ,
            "GNUPGHOME": str(scratch / "gnupg-home"),
            "PATH": f"{windows}\\System32;{windows}",
            "ProgramFiles": str(scratch / "no-programs"),
            "ProgramW6432": str(scratch / "no-programs"),
            "ProgramFiles(x86)": str(scratch / "no-programs"),
        }
        unpacked = scratch / "Portable Τεστ"
        with zipfile.ZipFile(RELEASE / f"{base_name}-portable.zip") as contents:
            contents.extractall(unpacked)  # noqa: S202 - our own archive, just built
        portable = unpacked / "mindyourownbytes"
        check_contents(portable)
        check_gnupg_is_official(portable)
        check_gnupg_tools_start(portable, environment)
        check_passphrase_window(portable, scratch, environment)
        self_test(portable / "mindyourownbytes.exe", environment, "portable", version)
        check_installer(RELEASE / f"{base_name}-setup.exe", portable, scratch, environment, version)
    print("Everything passed.", flush=True)


if __name__ == "__main__":
    main()
