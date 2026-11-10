"""GnuPG engine for mindyourownbytes: find gpg, expand inputs, encrypt, restore.

Every cryptographic operation is delegated to an installed GnuPG executable.
This module implements no cipher, KDF, or file format of its own, and it makes
no network calls. Keeping it free of Qt lets the security-relevant logic be
tested without a display.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Literal, NamedTuple

Operation = Literal["encrypt", "restore"]
Method = Literal["password", "public-key"]

ENCRYPTED_SUFFIXES = (".gpg", ".pgp")

#: Needed for --no-symkey-cache (2.2.7) and hard failure on missing MDC (2.2.8).
MIN_GPG_VERSION = (2, 2, 8)

#: Applied to every gpg call. --no-symkey-cache stops gpg-agent keeping a
#: passphrase after use: without it, a restore right after encrypting succeeds
#: with no prompt at all. The two --no-auto-key options keep a "local only"
#: promise even if the user's gpg.conf enables keyserver lookups.
_BASE_ARGS = (
    "--batch", "--no-tty", "--status-fd", "2", "--no-symkey-cache",
    "--no-auto-key-retrieve", "--no-auto-key-locate",
)


class Cipher(NamedTuple):
    """An encryption algorithm people can choose for passphrase encryption."""

    #: What GnuPG calls it.
    name: str
    #: What people see.
    label: str
    #: Its number inside an OpenPGP file.
    packet_id: int


#: Every choice has a 256-bit key and 128-bit blocks. IDEA, 3DES, CAST5, and Blowfish
#: are left out because their 64-bit blocks are too small, and GnuPG 2.5 refuses to
#: encrypt with them. Smaller keys are left out because they bring no benefit.
#: AES-256 comes first, because it's the default: the one nearly every OpenPGP tool opens.
CIPHERS = (
    Cipher("AES256", "AES-256", 9),
    Cipher("TWOFISH", "Twofish", 10),
    Cipher("CAMELLIA256", "Camellia-256", 13),
)
DEFAULT_CIPHER = CIPHERS[0].name


def symmetric_args(cipher: str = DEFAULT_CIPHER) -> tuple[str, ...]:
    """Passphrase encryption settings, with nothing left to GnuPG's defaults.

    The implicit defaults are unsafe to rely on: they vary by GnuPG version and
    silently fall back to 65,536 iterations when gpg-agent cannot be reached. The
    iteration count and digest are the OpenPGP maximum. See docs/THREAT_MODEL.md.
    """
    if cipher not in {choice.name for choice in CIPHERS}:
        raise ValueError(f"This app doesn't offer the encryption algorithm {cipher!r}.")
    return (
        "--symmetric", "--cipher-algo", cipher, "--s2k-mode", "3",
        "--s2k-digest-algo", "SHA512", "--s2k-count", "65011712",
    )


#: Hands gpg the passphrase over stdin, in place of asking through Pinentry.
_PIPE_ARGS = ("--pinentry-mode", "loopback", "--passphrase-fd", "0")

#: What ``on_progress`` says about a file that worked, and about one that was also checked.
READY = "Ready"
CHECKED = "Checked"

#: How much of a file is in memory at a time while it is checked.
_CHECK_CHUNK = 1024 * 1024

#: Windows sync clients and macOS keep these exact folder names.
_SYNC_FOLDER_NAMES = {
    "box", "box sync", "cloudstorage", "dropbox", "google drive", "googledrive",
    "icedrive", "icloud drive", "iclouddrive", "internxt", "koofr", "mega",
    "megasync", "mobile documents", "my drive", "nextcloud", "owncloud",
    "pcloud", "pcloud drive", "proton drive", "protondrive", "seadrive",
    "seafile", "sync", "syncthing", "tresorit", "yandex.disk",
}
_GPG_ERR_BAD_PASSPHRASE = 11
_GPG_ERR_CANCELED = 99

#: Sync clients often append an account name, e.g. "OneDrive - Contoso".
_SYNC_FOLDER_PREFIXES = ("onedrive", "dropbox (", "nextcloud-", "google drive (")

#: In gpg's --with-colons output: expired, revoked, disabled, never valid, and invalid.
_UNUSABLE_VALIDITY = tuple("erdni")

#: Curves as gpg's --with-colons output names them, and as people know them.
_CURVE_NAMES = {
    "cv25519": "Curve25519",
    "cv448": "Curve448",
    "nistp256": "NIST P-256",
    "nistp384": "NIST P-384",
    "nistp521": "NIST P-521",
    "brainpoolp256r1": "Brainpool P-256",
    "brainpoolp384r1": "Brainpool P-384",
    "brainpoolp512r1": "Brainpool P-512",
}


@dataclass(frozen=True)
class SourceItem:
    source: Path
    relative: Path
    size: int


@dataclass(frozen=True)
class JobResult:
    succeeded: int
    failed: int
    cancelled: bool
    outputs: tuple[Path, ...]
    #: Staging files that could not be deleted. On restore these are plaintext.
    leftovers: tuple[Path, ...] = ()
    #: How many of the outputs were decrypted again and matched their originals.
    checked: int = 0


class PublicKey(NamedTuple):
    fingerprint: str
    uid: str
    #: False means the matching private key is not on this computer, so the user
    #: could not decrypt what they encrypt to this key.
    has_secret: bool
    #: The type of key that files get encrypted to, for people to read. Empty if unknown.
    algorithm: str = ""


class CollectResult(NamedTuple):
    items: list[SourceItem]
    #: Links, duplicates, and files of the wrong type: deliberately left out.
    skipped: int
    #: Paths that could not be read. Unlike ``skipped``, this means content the
    #: user asked for is missing, so it must be shown to them.
    unreadable: tuple[Path, ...]


class Cancelled(Exception):
    pass


class GpgFailure(Exception):
    """gpg ran but the operation failed. The message is safe to show the user.

    ``wrong_secret`` means the file looks fine and the passphrase did not open it.
    """

    def __init__(self, message: str, wrong_secret: bool = False) -> None:
        super().__init__(message)
        self.wrong_secret = wrong_secret


def windows_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _is_git_bundled(path: Path) -> bool:
    """Git for Windows ships its own gpg, with a keyring separate from Kleopatra's."""
    parts = [part.lower() for part in path.parts]
    return "git" in parts and "usr" in parts


def _absolute_path_entries() -> list[Path]:
    """PATH entries that are absolute.

    Empty and relative entries resolve against the current directory, which is
    how a planted gpg.exe in, say, Downloads would get executed.
    """
    entries = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        path = Path(entry.strip().strip('"'))
        if entry.strip() and path.is_absolute():
            entries.append(path)
    return entries


def bundled_gpg() -> str | None:
    """The copy of GnuPG inside the Windows download, when running from one."""
    if not getattr(sys, "frozen", False):
        return None
    candidate = Path(sys.executable).parent / "gnupg" / "bin" / "gpg.exe"
    return str(candidate) if candidate.is_file() else None


def find_gpg() -> str | None:
    """Locate GnuPG without ever searching the current directory.

    ``shutil.which`` is deliberately not used: on Windows it searches the
    current directory first, so a gpg.exe dropped next to the app would be
    executed at startup and would then see every file and passphrase. The
    standard install locations come first for the same reason, and because
    someone's keys and Kleopatra already work with the GnuPG they installed.
    After those comes the copy in the Windows download, ahead of PATH, so that a
    stray PATH entry can't replace it. An installed GnuPG that is broken or too old
    to use must not hide that working copy.
    """
    if os.name == "nt":
        bundled = bundled_gpg()
        roots = [os.environ.get(name, "") for name in
                 ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "LOCALAPPDATA")]
        subpaths = (
            "GnuPG/bin/gpg.exe", "Gpg4win/bin/gpg.exe", "GnuPG/gpg.exe",
            "Programs/GnuPG/bin/gpg.exe", "Programs/Gpg4win/bin/gpg.exe",
        )
        for root in filter(None, roots):
            for subpath in subpaths:
                candidate = Path(root) / subpath
                if candidate.is_file() and (bundled is None or is_valid_gpg(str(candidate))):
                    return str(candidate)
        if bundled:
            return bundled
    names = ("gpg.exe",) if os.name == "nt" else ("gpg",)
    for directory in _absolute_path_entries():
        for name in names:
            candidate = directory / name
            if candidate.is_file() and not _is_git_bundled(candidate):
                return str(candidate)
    return None


def stop_bundled_gnupg(binary: str) -> None:
    """Stop the background helpers of the copy of GnuPG inside the Windows download.

    They would otherwise outlive the app and keep its files locked, so a portable copy
    couldn't be deleted, or its USB stick ejected. A GnuPG installed separately is left
    alone, because other programs, such as Kleopatra, rely on it.
    """
    if binary != bundled_gpg():
        return
    # The app is closing, and a failure here isn't worth interrupting that for.
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run([str(Path(binary).with_name("gpgconf.exe")), "--kill", "all"], capture_output=True,
                       timeout=15, check=False, creationflags=windows_flags())


def find_kleopatra() -> str | None:
    """Kleopatra, if installed, with the same rules as GnuPG so a planted copy never runs."""
    if os.name == "nt":
        for name in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "LOCALAPPDATA"):
            root = os.environ.get(name, "")
            for subpath in ("Gpg4win/bin/kleopatra.exe", "Programs/Gpg4win/bin/kleopatra.exe"):
                if root and (Path(root) / subpath).is_file():
                    return str(Path(root) / subpath)
        return None
    for directory in _absolute_path_entries():
        if (directory / "kleopatra").is_file():
            return str(directory / "kleopatra")
    return None


def gpg_version(binary: str) -> tuple[int, ...] | None:
    """Return the version of a GnuPG executable, or None if it isn't GnuPG."""
    if not Path(binary).is_absolute():
        return None
    try:
        result = subprocess.run(
            [binary, "--version"], capture_output=True, encoding="utf-8",
            errors="replace", timeout=8, check=False, creationflags=windows_flags(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.match(r"gpg \(GnuPG[^)]*\) (\d+)\.(\d+)\.(\d+)", result.stdout)
    if result.returncode != 0 or not match:
        return None
    return tuple(int(part) for part in match.groups())


def is_valid_gpg(binary: str) -> bool:
    """Sanity check only. Running it does not prove a binary is trustworthy."""
    version = gpg_version(binary)
    return version is not None and version >= MIN_GPG_VERSION


def available_ciphers(binary: str) -> tuple[Cipher, ...]:
    """The choices this GnuPG can use, because a build or a gpg.conf can rule some out.

    If GnuPG can't say, this offers only the default, which is what would be used anyway.
    If it turns out not to work, GnuPG's refusal is reported like any other failure.
    """
    if not Path(binary).is_absolute():
        return CIPHERS[:1]
    try:
        result = subprocess.run(
            [binary, "--batch", "--with-colons", "--list-config", "ciphername"],
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=8, check=False, creationflags=windows_flags(),
        )
    except (OSError, subprocess.SubprocessError):
        return CIPHERS[:1]
    supported: set[str] = set()
    for line in result.stdout.splitlines():
        fields = line.split(":")
        if fields[:2] == ["cfg", "ciphername"] and len(fields) > 2:
            supported.update(name.strip().upper() for name in fields[2].split(";"))
    return tuple(cipher for cipher in CIPHERS if cipher.name in supported) or CIPHERS[:1]


def is_link_or_junction(path: Path) -> bool:
    """Detect links to elsewhere.

    OneDrive's cloud placeholders are also reparse points, but they are ordinary
    files that belong in a backup, and ``is_junction`` correctly leaves them alone.
    """
    return path.is_symlink() or path.is_junction()


def _unescape_colon_field(value: str) -> str:
    """Undo gpg's ``\\xHH`` escaping in --with-colons output."""
    raw = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)
    try:
        return raw.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return raw


def _list_keys(binary: str, command: str) -> str:
    result = subprocess.run(
        [binary, "--batch", "--with-colons", "--fingerprint", command],
        capture_output=True, encoding="utf-8", errors="replace",
        timeout=15, check=False, creationflags=windows_flags(),
    )
    return result.stdout if result.returncode == 0 else ""


def _secret_fingerprints(binary: str) -> set[str]:
    fingerprints: set[str] = set()
    expecting_primary = False
    for line in _list_keys(binary, "--list-secret-keys").splitlines():
        fields = line.split(":")
        if fields[0] == "sec":
            expecting_primary = True
        elif fields[0] == "fpr" and expecting_primary and len(fields) > 9:
            fingerprints.add(fields[9])
            expecting_primary = False
    return fingerprints


def _key_type(fields: list[str]) -> str:
    """Name the type of key in a ``pub`` or ``sub`` record, for people to read."""
    bits, algorithm = fields[2], fields[3]
    curve = fields[16] if len(fields) > 16 else ""
    if algorithm in ("1", "2"):
        return f"RSA-{bits}"
    if algorithm in ("16", "20"):
        return f"ElGamal-{bits}"
    if algorithm == "8":
        return f"Kyber-{bits} (post-quantum)"
    return _CURVE_NAMES.get(curve.lower(), curve)


def _encryption_key_type(records: list[list[str]]) -> str:
    """Describe the key GnuPG will really encrypt to.

    That's the newest usable encryption subkey, and the primary key only if there is
    none. A key can hold several, such as a post-quantum subkey added to an older key.
    """
    def usable(fields: list[str]) -> bool:
        return len(fields) > 11 and "e" in fields[11] and fields[1] not in _UNUSABLE_VALIDITY

    subkeys = [fields for fields in records if fields[0] == "sub" and usable(fields)]
    if subkeys:
        # max() keeps the first of a tie, as GnuPG does.
        return _key_type(max(subkeys, key=lambda fields: int(fields[5]) if fields[5].isdigit() else 0))
    primary = next((fields for fields in records if fields[0] == "pub" and usable(fields)), None)
    return _key_type(primary) if primary else ""


def list_public_keys(binary: str) -> list[PublicKey]:
    """List keys usable for encryption, with the user's own keys first.

    Field 12 of a ``pub`` record holds the capabilities. Uppercase letters mean
    usable right now for the key as a whole, so an expired or revoked key has no
    ``E``, and ``D`` marks a disabled key.
    """
    secret = _secret_fingerprints(binary)
    keys: list[PublicKey] = []
    current: dict[str, str] | None = None
    records: list[list[str]] = []

    def flush() -> None:
        if current and current["fingerprint"] and current["usable"]:
            keys.append(PublicKey(
                current["fingerprint"], current["uid"] or "Unknown identity",
                current["fingerprint"] in secret, _encryption_key_type(records),
            ))

    for line in _list_keys(binary, "--list-keys").splitlines():
        fields = line.split(":")
        record = fields[0]
        if record == "pub":
            flush()
            records = []
            capabilities = fields[11] if len(fields) > 11 else ""
            validity = fields[1] if len(fields) > 1 else ""
            usable = "E" in capabilities and "D" not in capabilities and validity not in _UNUSABLE_VALIDITY
            current = {"fingerprint": "", "uid": "", "usable": "yes" if usable else ""}
        elif current is not None and record == "fpr" and not current["fingerprint"]:
            current["fingerprint"] = fields[9] if len(fields) > 9 else ""
        elif current is not None and record == "uid" and not current["uid"]:
            current["uid"] = _unescape_colon_field(fields[9]) if len(fields) > 9 else ""
        if record in ("pub", "sub") and len(fields) > 5:
            records.append(fields)
    flush()
    return sorted(keys, key=lambda key: not key.has_secret)


def looks_cloud_synced(path: str | Path) -> str | None:
    """Return the folder name that suggests ``path`` is synced, or None.

    A best-effort heuristic used only for warnings. It cannot see every sync
    client, so the UI must not imply that a clean result means a folder is safe.
    """
    resolved = Path(path).expanduser().absolute()
    for variable in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        root = os.environ.get(variable)
        if root and Path(root) in (resolved, *resolved.parents):
            return Path(root).name
    for part in resolved.parts[1:]:
        lowered = part.lower()
        if lowered in _SYNC_FOLDER_NAMES or lowered.startswith(_SYNC_FOLDER_PREFIXES):
            return part
    return None


def _check_root(path: Path, output_directory: Path) -> None:
    if is_link_or_junction(path):
        raise ValueError(f"Links or junctions are not supported: {path.name}")
    if not path.exists():
        raise ValueError(f"This path no longer exists: {path}")
    if path.is_dir():
        source = path.resolve()
        destination = output_directory.resolve()
        if destination == source or source in destination.parents:
            raise ValueError("The output folder cannot be inside a selected input folder.")
    elif not path.is_file():
        raise ValueError(f"Not a regular file: {path}")


def collect_files(paths: Iterable[str | Path], output_directory: Path,
                  operation: Operation) -> CollectResult:
    """Expand dropped files and folders. Links are skipped, never followed."""
    collected: list[SourceItem] = []
    seen: set[Path] = set()
    unreadable: list[Path] = []
    skipped = 0

    def consider(path: Path, relative: Path) -> None:
        nonlocal skipped
        if is_link_or_junction(path) or not path.is_file():
            skipped += 1
            return
        if operation == "restore" and path.suffix.lower() not in ENCRYPTED_SUFFIXES:
            skipped += 1
            return
        try:
            resolved = path.resolve()
            size = path.stat().st_size
        except OSError:
            unreadable.append(path)
            return
        if resolved in seen:
            skipped += 1
            return
        seen.add(resolved)
        collected.append(SourceItem(resolved, relative, size))

    def on_walk_error(error: OSError) -> None:
        # os.walk ignores these by default, which would leave a subfolder out
        # of a backup without anyone being told.
        unreadable.append(Path(error.filename) if error.filename else Path("(unknown)"))

    for raw in paths:
        # abspath first: Path("..").name is "..", which would otherwise put
        # outputs outside the chosen folder.
        path = Path(os.path.abspath(Path(raw).expanduser()))
        _check_root(path, output_directory)
        if path.is_file():
            consider(path, Path(path.name))
            continue
        for root, dirs, files in os.walk(path, topdown=True, followlinks=False, onerror=on_walk_error):
            root_path = Path(root)
            kept = []
            for dirname in sorted(dirs):
                if is_link_or_junction(root_path / dirname):
                    skipped += 1
                else:
                    kept.append(dirname)
            dirs[:] = kept
            for filename in sorted(files):
                candidate = root_path / filename
                consider(candidate, Path(path.name) / candidate.relative_to(path))
    return CollectResult(collected, skipped, tuple(unreadable))


def peek_protection(path: Path) -> Literal["passphrase", "key"] | None:
    """Which kind of secret a file expects, judged from its first OpenPGP packet.

    Used only to pre-select an option, so a wrong answer costs one click and no
    security decision rests on it. Reads a single byte of the outer header.
    """
    try:
        with open(path, "rb") as file:
            first = file.read(1)
    except OSError:
        return None
    if not first or not first[0] & 0x80:
        return None
    tag = first[0] & 0x3F if first[0] & 0x40 else (first[0] & 0x3C) >> 2
    return {1: "key", 3: "passphrase"}.get(tag)


def output_relative(item: SourceItem, operation: Operation) -> Path:
    relative = item.relative
    if operation == "encrypt":
        return relative.with_name(relative.name + ".gpg")
    if relative.suffix.lower() not in ENCRYPTED_SUFFIXES:
        raise ValueError("The restore input must have a .gpg or .pgp extension")
    result = relative.with_suffix("")
    if not result.name or result.name in (".", ".."):
        raise ValueError("The encrypted file has no safe output filename")
    return result


def unique_target(path: Path) -> Path:
    """Pick a free name, so earlier backups and restores are never overwritten.

    The counter goes before the inner extension, so ``report.pdf.gpg`` becomes
    ``report (2).pdf.gpg`` and later restores as ``report (2).pdf``. Placing it
    last would produce ``report.pdf (2)``, which no application can open.
    """
    if not os.path.lexists(path):
        return path
    name = path.name
    outer = ""
    if name.lower().endswith(ENCRYPTED_SUFFIXES):
        name, outer = name[:-4], name[-4:]
    stem, inner = os.path.splitext(name)
    for number in range(2, 10001):
        candidate = path.with_name(f"{stem} ({number}){inner}{outer}")
        if not os.path.lexists(candidate):
            return candidate
    raise RuntimeError("Too many backups with the same filename")


def publish_no_overwrite(staged: Path, destination: Path) -> None:
    """Publish a complete file without overwriting a pre-existing destination."""
    try:
        os.link(staged, destination)
    except FileExistsError:
        raise
    except OSError:
        if os.name == "nt":
            # Windows rename fails when the target already exists and keeps
            # publication atomic, even on filesystems without hardlinks.
            os.rename(staged, destination)
            return
        # Non-NTFS drives may not permit hardlinks. Exclusive create prevents
        # replacement; a failure removes only the newly created destination.
        with destination.open("xb") as target:
            try:
                with staged.open("rb") as source:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
            except BaseException:
                target.close()
                destination.unlink(missing_ok=True)
                raise


def encode_passphrase(passphrase: str) -> bytes:
    """Encode a passphrase for --passphrase-fd, refusing what gpg would truncate.

    gpg reads a single line, so ``abc\\ndef`` would silently encrypt with
    ``abc``, and the user would be locked out when they later type the whole
    thing. Encoding matches what Pinentry sends, so a file encrypted either way
    can be opened the other way.
    """
    if not passphrase:
        raise ValueError("The passphrase is empty.")
    if any(character in passphrase for character in "\n\r\0"):
        raise ValueError("Passphrases cannot contain line breaks or NUL characters.")
    return passphrase.encode("utf-8")


def run_gpg_pipe(binary: str, args: Sequence[str], secret: bytes, data: bytes = b"",
                 timeout: float = 120) -> tuple[int, bytes, str]:
    """Run gpg with a passphrase, and optional data, over stdin. Nothing touches disk.

    The passphrase never goes in argv, where any local process could read it.
    Prefixing it to the data on one pipe is a supported gpg idiom: --passphrase-fd
    consumes exactly one line and leaves the rest for the message.
    """
    result = subprocess.run(
        [binary, *_BASE_ARGS, *_PIPE_ARGS, *args], input=secret + b"\n" + data,
        capture_output=True, timeout=timeout, check=False, creationflags=windows_flags(),
    )
    return result.returncode, result.stdout, result.stderr.decode("utf-8", errors="replace")


def run_gpg(argv: list[str], cancel: threading.Event, secret: bytes | None = None) -> tuple[int, str]:
    """Run gpg until it exits or ``cancel`` is set. Returns (exit code, stderr)."""
    process = subprocess.Popen(
        argv, stdin=subprocess.PIPE if secret is not None else subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, creationflags=windows_flags(),
    )
    pending = None if secret is None else secret + b"\n"
    try:
        while True:
            if cancel.is_set():
                process.terminate()
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                raise Cancelled()
            try:
                _, stderr = process.communicate(input=pending, timeout=0.25)
                return process.returncode, stderr.decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                # Retrying communicate() keeps any output read so far, but it
                # may only be given the input once.
                pending = None
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def run_gpg_hashed(argv: list[str], cancel: threading.Event, secret: bytes) -> tuple[int, str, bytes]:
    """Run gpg until it exits or ``cancel`` is set. Returns (exit code, stderr, SHA-256 of its stdout).

    The output is hashed as it arrives, a piece at a time, so a decrypted file is never written to
    disk and never held in memory whole. Each pipe gets its own thread, because gpg stops and waits
    whenever one of them is full, and this thread has to stay free to notice ``cancel``.
    """
    process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=windows_flags())
    digest = hashlib.sha256()
    diagnostics = bytearray()
    problems: list[Exception] = []

    def feed() -> None:
        # gpg can exit without reading this, if it rejects an option, say. Its exit code then says so.
        with contextlib.suppress(OSError), process.stdin:
            process.stdin.write(secret + b"\n")

    def hash_output() -> None:
        with process.stdout:
            while piece := process.stdout.read(_CHECK_CHUNK):
                digest.update(piece)

    def keep_diagnostics() -> None:
        with process.stderr:
            diagnostics.extend(process.stderr.read())

    def guarded(work: Callable[[], None]) -> None:
        try:
            work()
        except Exception as exc:  # Raised again below, by the thread that is waiting.
            problems.append(exc)

    pumps = [threading.Thread(target=guarded, args=(work,), daemon=True)
             for work in (feed, hash_output, keep_diagnostics)]
    try:
        for pump in pumps:
            pump.start()
        # Each one ends when gpg closes its side, which it does by exiting.
        for pump in pumps:
            while pump.is_alive():
                if cancel.is_set():
                    raise Cancelled()
                if problems:
                    raise problems[0]
                pump.join(timeout=0.25)
        while process.poll() is None:
            if cancel.is_set():
                raise Cancelled()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=0.25)
        if problems:
            # Without all of the output, the hash would say nothing about the file.
            raise problems[0]
        return process.returncode, diagnostics.decode("utf-8", errors="replace"), digest.digest()
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for pump in pumps:
            if pump.ident is not None:
                pump.join(timeout=3)


def _status_lines(stderr: str) -> list[list[str]]:
    return [line.split()[1:] for line in stderr.splitlines() if line.startswith("[GNUPG:] ")]


def _last_diagnostic(stderr: str) -> str:
    """The last human-readable line. gpg never echoes passphrases here."""
    lines = [line.strip() for line in stderr.splitlines()
             if line.strip() and not line.startswith("[GNUPG:] ")]
    return lines[-1][:300] if lines else "No details"


def describe_failure(stderr: str, operation: Operation = "restore") -> GpgFailure:
    """Turn gpg's machine-readable status lines into one clear explanation.

    The order matters, and it comes from measuring hundreds of corrupted files:
    the same damage can surface as BADMDC, a zlib error, NODATA, or a low-level
    filter message depending on where it falls. Status tokens are used because
    gpg's human-readable text is translated.
    """
    lines = _status_lines(stderr)
    statuses = {line[0] for line in lines if line}
    # The low 16 bits of a libgpg-error code identify the error.
    error_codes = {
        int(line[-1]) & 0xFFFF for line in lines
        if len(line) > 1 and line[0] in ("ERROR", "FAILURE") and line[-1].isdigit()
    }
    bad_passphrase = "BAD_PASSPHRASE" in statuses or _GPG_ERR_BAD_PASSPHRASE in error_codes
    damaged = "This file is damaged, or it is not a valid encrypted file. Nothing was restored."
    if _GPG_ERR_CANCELED in error_codes:
        return GpgFailure("The passphrase prompt was cancelled.")
    if "BADMDC" in statuses:
        return GpgFailure("Integrity check failed: this file is damaged or was altered. Nothing was restored.")
    if "BADSIG" in statuses:
        return GpgFailure("This file's signature is invalid, so it was altered or forged. Nothing was restored.")
    if "DECRYPTION_OKAY" in statuses and ("NO_PUBKEY" in statuses or "ERRSIG" in statuses):
        # Common with files from other tools, such as Kleopatra's sign-and-encrypt.
        # The file itself is fine, so saying "damaged" here would be false.
        return GpgFailure("This file decrypted, but it is signed by a key you don't have, so the signature "
                          "can't be checked. Import the signer's public key and try again.")
    if "INV_RECP" in statuses:
        return GpgFailure("GnuPG refused this key. It may be expired, revoked, or not yet certified in Kleopatra.")
    if operation == "encrypt":
        # A full disk, say. The rest of these only make sense when reading a file.
        return GpgFailure(f"GnuPG reported an error: {_last_diagnostic(stderr)}")
    if "PLAINTEXT" in statuses or "NODATA" in statuses:
        return GpgFailure(damaged)
    if "NO_SECKEY" in statuses and not bad_passphrase:
        # gpg also says NO_SECKEY after a mistyped passphrase. Telling someone
        # their key is missing when they only made a typo would cause real alarm.
        return GpgFailure("The private key for this file is not on this computer.")
    if "DECRYPTION_FAILED" in statuses or bad_passphrase:
        return GpgFailure("Wrong passphrase, or this file was encrypted with a different secret.", wrong_secret=True)
    if "BEGIN_DECRYPTION" in statuses or "NEED_PASSPHRASE_SYM" in statuses:
        # gpg got as far as the encrypted data and then found it malformed.
        return GpgFailure(damaged)
    return GpgFailure(f"GnuPG reported an error: {_last_diagnostic(stderr)}")


def _check_success(operation: Operation, code: int, stderr: str, staged: Path) -> None:
    """Decide success from gpg's status lines rather than its exit code alone.

    Exit code 0 is not enough. ``gpg --decrypt`` also "succeeds" on OpenPGP data
    that was never encrypted, with no key or passphrase needed, so whoever holds
    the storage could replace a backup with content of their choosing and it
    would restore as if nothing had happened. DECRYPTION_OKAY proves that
    decryption really took place.
    """
    if code != 0:
        raise describe_failure(stderr, operation)
    statuses = {line[0] for line in _status_lines(stderr) if line}
    if operation == "encrypt":
        if "END_ENCRYPTION" not in statuses:
            raise GpgFailure("GnuPG did not confirm that it encrypted this file.")
        if not staged.is_file() or staged.stat().st_size == 0:
            raise GpgFailure("GnuPG did not produce a valid output file.")
    else:
        if "DECRYPTION_OKAY" not in statuses:
            raise GpgFailure("This file is not actually encrypted, so it cannot be trusted as your "
                             "backup. It may have been replaced. Nothing was restored.")
        # Not checked for size: an encrypted empty file correctly restores empty.
        if not staged.is_file():
            raise GpgFailure("GnuPG did not produce an output file.")


def _build_command(binary: str, operation: Operation, method: Method, fingerprint: str | None,
                   staged: Path, source: Path, piped: bool, cipher: str) -> list[str]:
    command = [binary, *_BASE_ARGS]
    command += _PIPE_ARGS if piped else ("--pinentry-mode", "ask")
    command += ["--output", str(staged)]
    if operation == "restore":
        command.append("--decrypt")
    elif method == "password":
        command += symmetric_args(cipher)
    else:
        command += ["--encrypt", "--recipient", fingerprint or ""]
    command += ["--", str(source)]
    return command


def _remove_staged(staged: Path, leftovers: list[Path]) -> None:
    # A cleanup problem must not abort the rest of the batch, but it must not
    # stay hidden either: on restore this file holds plaintext.
    try:
        staged.unlink(missing_ok=True)
    except OSError:
        leftovers.append(staged)


def _file_state(path: Path) -> tuple[int, ...] | None:
    """Enough to notice, cheaply, that a file was written to or replaced. None if it can't be found."""
    try:
        status = os.stat(path)
    except OSError:
        return None
    return status.st_size, status.st_mtime_ns, status.st_ino, status.st_dev


def _hash_file(path: Path, cancel: threading.Event) -> bytes:
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        while piece := file.read(_CHECK_CHUNK):
            if cancel.is_set():
                raise Cancelled()
            digest.update(piece)
    return digest.digest()


def _check_copy(binary: str, staged: Path, source: Path, state_before: tuple[int, ...] | None,
                secret: bytes, cancel: threading.Event) -> None:
    """Prove that a newly encrypted file decrypts back to its original, or raise.

    People may delete an original once its copy is reported as encrypted, so that report has to be
    true. GnuPG decrypts the copy again, with the same passphrase over a pipe. What it writes is
    hashed as it arrives, then compared with a hash of the original, which is read last so that the
    answer is about the original as it is now.

    As for a restore, exit code 0 isn't enough. DECRYPTION_OKAY has to be there as well, or a copy
    that was never encrypted would pass by holding the right content.
    """
    command = [binary, *_BASE_ARGS, *_PIPE_ARGS, "--output", "-", "--decrypt", "--", str(staged)]
    try:
        code, stderr, decrypted = run_gpg_hashed(command, cancel, secret)
    except OSError as exc:
        raise GpgFailure("Check failed: GnuPG couldn't be run again to decrypt the new copy, so it wasn't "
                         f"kept. The reason given was: {exc}") from exc
    if code != 0:
        raise GpgFailure("Check failed: GnuPG couldn't decrypt the copy it had just made, so it wasn't kept. "
                         f"GnuPG said: {_last_diagnostic(stderr)}")
    if "DECRYPTION_OKAY" not in {line[0] for line in _status_lines(stderr) if line}:
        raise GpgFailure("Check failed: the copy GnuPG made isn't actually encrypted, so it wasn't kept.")
    try:
        original = _hash_file(source, cancel)
    except OSError as exc:
        if _file_state(source) is None:
            raise GpgFailure("The original is gone: it was moved or deleted while it was being encrypted, "
                             "so no encrypted copy was kept.") from exc
        raise GpgFailure("Check failed: the original couldn't be read again to compare it, so the "
                         f"encrypted copy wasn't kept. The reason given was: {exc}") from exc
    if decrypted != original:
        if _file_state(source) != state_before:
            # Not damage: the copy holds this file as it was a moment ago, or part old and part new.
            raise GpgFailure("The original changed: something wrote to this file while it was being "
                             "encrypted, so no encrypted copy was kept. Try again when nothing is changing it.")
        raise GpgFailure("Check failed: decrypting the new copy didn't give back the original, so the copy "
                         "wasn't kept. Your original hasn't been touched. Try again, and if another program "
                         "has this file open, close it first.")


def _process_one(binary: str, item: SourceItem, output_directory: Path, operation: Operation,
                 method: Method, fingerprint: str | None, cancel: threading.Event,
                 secrets: Sequence[bytes], leftovers: list[Path], cipher: str, verify: bool,
                 on_checking: Callable[[], None] | None) -> tuple[Path, bool]:
    """Returns where the result is, and whether it was checked against its original."""
    target = unique_target(output_directory / output_relative(item, operation))
    target.parent.mkdir(parents=True, exist_ok=True)
    failures: list[GpgFailure] = []
    for secret in secrets or (None,):
        # A short fixed-length name: embedding the original name pushed long,
        # perfectly valid filenames past the 255-character limit.
        staged = target.parent / f".myob-{uuid.uuid4().hex[:16]}.partial"
        # Only with a passphrase already in hand. A key, or GnuPG's own prompt, would mean asking again.
        checking = verify and operation == "encrypt" and method == "password" and secret is not None
        try:
            command = _build_command(binary, operation, method, fingerprint, staged,
                                     item.source, piped=secret is not None, cipher=cipher)
            state_before = _file_state(item.source) if checking else None
            code, stderr = run_gpg(command, cancel, secret)
            _check_success(operation, code, stderr, staged)
            if checking:
                if cancel.is_set():
                    raise Cancelled()
                if on_checking is not None:
                    on_checking()
                # Still under its temporary name, so a copy that fails never gets its final one.
                _check_copy(binary, staged, item.source, state_before, secret, cancel)
            publish_no_overwrite(staged, target)
            return target, checking
        except GpgFailure as exc:
            # Keep going even after what looks like damage. About 1 wrong
            # passphrase in 65,536 passes gpg's quick check and then fails like
            # a corrupt file, so stopping could wrongly report a good backup as
            # damaged when a later saved passphrase would have opened it.
            failures.append(exc)
        finally:
            _remove_staged(staged, leftovers)
    other = next((failure for failure in failures if not failure.wrong_secret), None)
    if other is not None:
        raise other
    if len(failures) > 1:
        raise GpgFailure("None of the saved passphrases opened this file.")
    raise failures[0]


def process_items(
    binary: str, items: list[SourceItem], output_directory: Path,
    operation: Operation, method: Method, fingerprint: str | None,
    cancel: threading.Event, on_progress: Callable[[int, bool, str, Path | None], None],
    *, passphrases: Sequence[str] = (), cipher: str = DEFAULT_CIPHER, verify: bool = True,
    on_checking: Callable[[int], None] | None = None, on_start: Callable[[int], None] | None = None,
) -> JobResult:
    """Process each item independently; failed jobs leave no partial exports.

    With no ``passphrases``, gpg-agent asks through Pinentry, once per file for
    passphrase encryption. Otherwise the passphrase goes to gpg over a pipe. A
    restore may pass several, which are tried in order.

    ``cipher`` only applies to passphrase encryption. A key decides its own, and a
    restore reads it from the file.

    ``verify`` decrypts each newly encrypted file again and compares it with its original,
    before the file gets its final name. That only happens when a passphrase was passed in,
    because anything else would make GnuPG ask again. ``on_checking`` hears when a file's
    check begins, and ``on_progress`` then says ``CHECKED`` rather than ``READY``.

    ``on_start`` hears as work on each item begins, before GnuPG sees it.
    """
    if not is_valid_gpg(binary):
        raise RuntimeError(
            "The selected GnuPG executable is not available, or is older than "
            f"{'.'.join(map(str, MIN_GPG_VERSION))}."
        )
    symmetric_args(cipher)  # Refuses an algorithm this app doesn't offer, before any work.
    if operation == "encrypt" and method == "public-key":
        if not fingerprint or not re.fullmatch(r"[0-9A-Fa-f]{40,64}", fingerprint):
            raise ValueError("Select a valid OpenPGP recipient key.")
        if passphrases:
            raise ValueError("Public-key encryption does not use a passphrase.")
    if operation == "encrypt" and len(passphrases) > 1:
        raise ValueError("Encryption uses exactly one passphrase.")
    secrets = [encode_passphrase(passphrase) for passphrase in passphrases]

    succeeded = failed = checked = 0
    outputs: list[Path] = []
    leftovers: list[Path] = []
    was_cancelled = False
    for index, item in enumerate(items):
        if cancel.is_set():
            was_cancelled = True
            break
        try:
            if on_start is not None:
                on_start(index)
            target, was_checked = _process_one(
                binary, item, output_directory, operation, method, fingerprint, cancel, secrets, leftovers,
                cipher, verify, partial(on_checking, index) if on_checking is not None else None,
            )
        except Cancelled:
            was_cancelled = True
            on_progress(index, False, "Cancelled", None)
            break
        except Exception as exc:  # Other files should still be processed.
            failed += 1
            on_progress(index, False, str(exc), None)
        else:
            outputs.append(target)
            succeeded += 1
            checked += was_checked
            on_progress(index, True, CHECKED if was_checked else READY, target)
    return JobResult(succeeded, failed, was_cancelled, tuple(outputs), tuple(leftovers), checked)
