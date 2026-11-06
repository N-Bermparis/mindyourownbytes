"""Local-only GnuPG file preparation and restoration for mindyourownbytes.

No cloud services, credentials, analytics, or network calls are used here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Literal
import os
import re
import shutil
import subprocess
import threading
import uuid


Operation = Literal["encrypt", "restore"]
Method = Literal["password", "public-key"]


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


class Cancelled(Exception):
    pass


def find_gpg() -> str | None:
    """Find the Gpg4win engine without assuming a particular version/path."""
    for name in ("gpg.exe", "gpg"):
        match = shutil.which(name)
        if match:
            return match

    candidate_roots = [
        os.environ.get("ProgramFiles", ""),
        os.environ.get("ProgramFiles(x86)", ""),
        os.environ.get("LOCALAPPDATA", ""),
    ]
    subpaths = (
        Path("GnuPG/bin/gpg.exe"),
        Path("Gpg4win/bin/gpg.exe"),
        Path("GnuPG/gpg.exe"),
    )
    for root in candidate_roots:
        if not root:
            continue
        for subpath in subpaths:
            path = Path(root) / subpath
            if path.is_file():
                return str(path)
    return None


def is_valid_gpg(binary: str) -> bool:
    try:
        result = subprocess.run(
            [binary, "--version"], capture_output=True, text=True,
            timeout=8, check=False, creationflags=_windows_flags(),
        )
        return result.returncode == 0 and "gpg" in result.stdout.lower()
    except (OSError, subprocess.TimeoutExpired):
        return False


def _windows_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _is_link_or_junction(path: Path) -> bool:
    """Reject symbolic links and Windows junctions (where supported)."""
    if path.is_symlink():
        return True
    check_junction = getattr(path, "is_junction", None)
    return bool(check_junction()) if callable(check_junction) else False


def list_public_keys(binary: str) -> list[tuple[str, str]]:
    """Return (fingerprint, visible UID) pairs for encryption-capable keys."""
    result = subprocess.run(
        [binary, "--batch", "--with-colons", "--fingerprint", "--list-keys"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=15, check=False, creationflags=_windows_flags(),
    )
    if result.returncode:
        return []
    output: list[tuple[str, str]] = []
    current: dict[str, str | bool] | None = None
    for line in result.stdout.splitlines():
        fields = line.split(":")
        record = fields[0]
        if record == "pub":
            if current and current.get("fingerprint") and current.get("can_encrypt"):
                output.append((str(current["fingerprint"]), str(current.get("uid") or "Unknown identity")))
            current = {
                "fingerprint": "", "uid": "",
                "can_encrypt": "e" in (fields[11].lower() if len(fields) > 11 else ""),
            }
        elif current is not None and record == "sub":
            usage = fields[11].lower() if len(fields) > 11 else ""
            if "e" in usage:
                current["can_encrypt"] = True
        elif current is not None and record == "fpr" and not current["fingerprint"]:
            current["fingerprint"] = fields[9] if len(fields) > 9 else ""
        elif current is not None and record == "uid" and not current["uid"]:
            current["uid"] = fields[9] if len(fields) > 9 else ""
    if current and current.get("fingerprint") and current.get("can_encrypt"):
        output.append((str(current["fingerprint"]), str(current.get("uid") or "Unknown identity")))
    return output


def _check_root(path: Path, output_directory: Path, operation: Operation) -> None:
    if _is_link_or_junction(path):
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
                  operation: Operation) -> tuple[list[SourceItem], int]:
    """Expand dropped files/folders. Skip symlinks, never follow link targets."""
    collected: list[SourceItem] = []
    seen: set[Path] = set()
    skipped = 0

    def consider(path: Path, relative: Path) -> None:
        nonlocal skipped
        if _is_link_or_junction(path) or not path.is_file():
            skipped += 1
            return
        if operation == "restore" and path.suffix.lower() not in (".gpg", ".pgp"):
            skipped += 1
            return
        resolved = path.resolve()
        if resolved in seen:
            skipped += 1
            return
        seen.add(resolved)
        collected.append(SourceItem(resolved, relative, path.stat().st_size))

    for raw in paths:
        path = Path(raw).expanduser()
        _check_root(path, output_directory, operation)
        if path.is_file():
            consider(path, Path(path.name))
            continue
        for root, dirs, files in os.walk(path, topdown=True, followlinks=False):
            root_path = Path(root)
            filtered_dirs = []
            for dirname in sorted(dirs):
                candidate = root_path / dirname
                if _is_link_or_junction(candidate):
                    skipped += 1
                else:
                    filtered_dirs.append(dirname)
            dirs[:] = filtered_dirs
            for filename in sorted(files):
                candidate = root_path / filename
                consider(candidate, Path(path.name) / candidate.relative_to(path))
    return collected, skipped


def output_relative(item: SourceItem, operation: Operation) -> Path:
    relative = item.relative
    if operation == "encrypt":
        return relative.with_name(relative.name + ".gpg")
    if relative.suffix.lower() not in (".gpg", ".pgp"):
        raise ValueError("The restore input must have a .gpg or .pgp extension")
    result = relative.with_suffix("")
    if not result.name or result.name in (".", ".."):
        raise ValueError("The encrypted file has no safe output filename")
    return result


def unique_target(path: Path) -> Path:
    """Avoid overwriting previous backups/restores, including duplicate names."""
    if not path.exists():
        return path
    for number in range(2, 10001):
        candidate = path.with_name(f"{path.stem} ({number}){path.suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError("Too many backups with the same filename")


def _publish_no_overwrite(staged: Path, destination: Path) -> None:
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


def _run_gpg(argv: list[str], cancel: threading.Event) -> tuple[int, str]:
    process = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, creationflags=_windows_flags(),
    )
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
                _, stderr = process.communicate(timeout=0.25)
                return process.returncode, stderr.decode("utf-8", errors="replace")[-1200:]
            except subprocess.TimeoutExpired:
                continue
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate()


def process_items(
    binary: str, items: list[SourceItem], output_directory: Path,
    operation: Operation, method: Method, fingerprint: str | None,
    cancel: threading.Event, on_progress: Callable[[int, bool, str, Path | None], None],
) -> JobResult:
    """Process each item independently; failed jobs leave no partial exports."""
    if not is_valid_gpg(binary):
        raise RuntimeError("The selected GnuPG executable is not available.")
    if operation == "encrypt" and method == "public-key":
        if not fingerprint or not re.fullmatch(r"[0-9A-Fa-f]{40,64}", fingerprint):
            raise ValueError("Select a valid OpenPGP recipient key.")

    succeeded = failed = 0
    outputs: list[Path] = []
    was_cancelled = False
    for index, item in enumerate(items):
        if cancel.is_set():
            was_cancelled = True
            break
        staged: Path | None = None
        try:
            relative = output_relative(item, operation)
            target = unique_target(output_directory / relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            staged = target.with_name(f".{target.name}.{uuid.uuid4().hex}.partial")
            command = [binary, "--no-tty", "--output", str(staged)]
            if operation == "restore":
                command += ["--decrypt"]
            elif method == "password":
                command += ["--symmetric", "--cipher-algo", "AES256"]
            else:
                command += ["--encrypt", "--recipient", fingerprint or ""]
            command += ["--", str(item.source)]
            code, diagnostic = _run_gpg(command, cancel)
            if code != 0:
                # Errors are displayed locally only. Never include passphrases.
                detail = diagnostic.strip().splitlines()[-1] if diagnostic.strip() else "No details"
                raise RuntimeError(f"GnuPG reported an error: {detail}")
            if not staged.is_file() or staged.stat().st_size == 0:
                raise RuntimeError("GnuPG did not produce a valid output file")
            _publish_no_overwrite(staged, target)
            outputs.append(target)
            succeeded += 1
            on_progress(index, True, "Ready", target)
        except Cancelled:
            was_cancelled = True
            on_progress(index, False, "Cancelled", None)
            break
        except Exception as exc:  # Other files should still be processed.
            failed += 1
            on_progress(index, False, str(exc), None)
        finally:
            if staged is not None:
                staged.unlink(missing_ok=True)
    return JobResult(succeeded, failed, was_cancelled, tuple(outputs))
