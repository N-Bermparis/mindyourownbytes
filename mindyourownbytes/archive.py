"""Archives: many files in one zip, so that GnuPG can encrypt them as one .gpg file.

Whoever stores an encrypted archive sees one file, its name, and roughly its size. The names,
folders, number, and sizes of the files inside are encrypted along with their contents.

This module only packs and unpacks ordinary zip files. GnuPG does all the encryption, and
``core.encrypt_archive`` connects the two. Packing writes the zip straight into GnuPG, so no
readable archive touches disk. Unpacking needs the decrypted zip on disk, because a zip keeps
its table of contents at the end. That copy keeps a temporary name until it's unpacked, and is
then deleted.

Nothing here depends on this app to open an archive later:
``gpg --output Archive.zip --decrypt Archive.zip.gpg``, then open Archive.zip.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import time
import uuid
import zipfile
import zlib
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import BinaryIO

#: Archives are named "<name>.zip.gpg", so that decrypting one by hand gives a file any computer opens.
SUFFIX = ".zip"
#: Written as the zip's comment. Only a zip that carries it is unpacked on restore. Any other zip,
#: encrypted as an ordinary file, is restored as the .zip it was.
MARKER = b"mindyourownbytes archive 1"
MAX_NAME = 100
_CHUNK = 1024 * 1024

#: Characters and names that Windows can't use in a file or folder name.
INVALID_NAME_CHARACTERS = frozenset('<>:"/\\|?*')
RESERVED_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
})


class ArchiveError(Exception):
    """An archive couldn't be made or unpacked. The message is safe to show the user."""


class OutputClosed(Exception):
    """What the archive was being written to stopped taking it. For GnuPG, that means it failed."""


def is_safe_name_part(part: str) -> bool:
    """Whether one file or folder name is safe to create on every system this app runs on."""
    return (
        bool(part) and part not in (".", "..") and len(part) <= 255
        and not any(character in INVALID_NAME_CHARACTERS or ord(character) < 32 for character in part)
        # Windows drops these from the end of a name, so two different names could become one.
        and not part.endswith((".", " "))
        and part.split(".")[0].strip().upper() not in RESERVED_NAMES
    )


def check_name(name: str) -> str:
    """Return a cleaned archive name, without its extensions, or say what's wrong with it."""
    cleaned = name.strip()
    lowered = cleaned.casefold()
    for ending in (f"{SUFFIX}.gpg", ".gpg", SUFFIX):
        if lowered.endswith(ending):
            cleaned = cleaned[:-len(ending)].strip()
            break
    if not cleaned:
        raise ValueError("The archive needs a name.")
    if len(cleaned) > MAX_NAME:
        raise ValueError(f"Archive names can be at most {MAX_NAME} characters.")
    if cleaned.startswith("."):
        raise ValueError("Archive names can't start with a dot.")
    if not is_safe_name_part(cleaned):
        raise ValueError('Archive names can\'t contain < > : " / \\ | ? *, end with a dot, or be a name '
                         "that Windows reserves, such as CON or NUL.")
    return cleaned


def member_names(relatives: Sequence[str]) -> list[str]:
    """Names inside the archive: each file's folders as listed, and never the same name twice.

    Two folders with the same name, from different places, can both be in one list. Windows can't
    tell names apart by case, so that counts as the same name too.
    """
    used: set[str] = set()
    names = []
    for relative in relatives:
        name = PurePosixPath(relative).as_posix()
        candidate, number = name, 2
        while candidate.casefold() in used:
            path = PurePosixPath(name)
            candidate = str(path.with_name(f"{path.stem} ({number}){path.suffix}"))
            number += 1
        used.add(candidate.casefold())
        names.append(candidate)
    return names


def file_state(path: Path) -> tuple[int, ...] | None:
    """Enough to notice, cheaply, that a file was written to or replaced. None if it can't be found."""
    try:
        status = os.stat(path)
    except OSError:
        return None
    return status.st_size, status.st_mtime_ns, status.st_ino, status.st_dev


class _Writer:
    """What zipfile writes to: hashed on the way, and checked for Cancel between writes."""

    def __init__(self, target: BinaryIO, stop: Callable[[], None]) -> None:
        self._target = target
        self._stop = stop
        self.digest = hashlib.sha256()
        self._abandoned = False

    def write(self, data) -> int:
        if self._abandoned:
            return len(data)
        self._stop()
        try:
            self._target.write(data)
        except OSError as exc:
            raise OutputClosed() from exc
        self.digest.update(data)
        return len(data)

    def flush(self) -> None:
        if not self._abandoned:
            try:
                self._target.flush()
            except OSError as exc:
                raise OutputClosed() from exc

    def abandon(self) -> None:
        """Nothing more reaches the target, so tidying up the zip can't fail or block."""
        self._abandoned = True


def pack(files: Sequence[tuple[Path, str]], target: BinaryIO, stop: Callable[[], None],
         on_file: Callable[[int], None] | None = None) -> tuple[bytes, list[tuple[str, Path, tuple[int, ...] | None]]]:
    """Write ``files``, as (original, name inside) pairs, into one zip on ``target``.

    Returns the SHA-256 of everything written, and the state of each original just before it was
    read, so that a check can tell afterwards whether any of them changed meanwhile. ``stop`` raises
    to cancel.
    """
    writer = _Writer(target, stop)
    states: list[tuple[str, Path, tuple[int, ...] | None]] = []
    archive = zipfile.ZipFile(writer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6)
    try:
        for index, (source, name) in enumerate(files):
            stop()
            if on_file is not None:
                on_file(index)
            states.append((name, source, file_state(source)))
            try:
                info = zipfile.ZipInfo.from_file(source, name, strict_timestamps=False)
                original = open(source, "rb")  # noqa: SIM115 - closed below, and its errors are worded apart
            except OSError as exc:
                raise ArchiveError(f"The original is gone: {name} couldn't be opened, so no archive was kept. "
                                   f"The reason given was: {exc.strerror or exc}") from exc
            info.compress_type = zipfile.ZIP_DEFLATED
            with original, archive.open(info, "w") as packed:
                while True:
                    try:
                        piece = original.read(_CHUNK)
                    except OSError as exc:
                        raise ArchiveError(f"{name} couldn't be read, so no archive was kept. "
                                           f"The reason given was: {exc.strerror or exc}") from exc
                    if not piece:
                        break
                    packed.write(piece)
        archive.comment = MARKER
        archive.close()
    except BaseException:
        writer.abandon()
        archive.close()
        raise
    return writer.digest.digest(), states


def is_archive(path: Path) -> bool:
    """Whether a decrypted file is an archive this app made, and so should be unpacked."""
    try:
        with zipfile.ZipFile(path) as archive:
            return archive.comment == MARKER
    except (OSError, ValueError, zipfile.BadZipFile):
        return False


def _member_parts(name: str) -> tuple[str, ...]:
    parts = tuple((name[:-1] if name.endswith("/") else name).split("/"))
    if name.startswith("/") or not all(is_safe_name_part(part) for part in parts):
        raise ArchiveError(f"This archive holds a name that can't be used safely, so nothing was unpacked: {name!r}")
    return parts


def _plan(infos: Sequence[zipfile.ZipInfo]) -> list[tuple[zipfile.ZipInfo, tuple[str, ...]]]:
    """Check every entry before anything is written, so that a bad one means nothing at all."""
    seen: set[tuple[str, ...]] = set()
    files: set[tuple[str, ...]] = set()
    folders: set[tuple[str, ...]] = set()
    plan = []
    for info in infos:
        if info.flag_bits & 0x1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ArchiveError("This archive uses a feature this app never writes, so nothing was unpacked. "
                               "Decrypt it with GnuPG and open it with another program.")
        parts = _member_parts(info.filename)
        key = tuple(part.casefold() for part in parts)
        if key in seen:
            raise ArchiveError(f"This archive holds the same name twice, so nothing was unpacked: {info.filename!r}")
        seen.add(key)
        folders.update(key[:depth] for depth in range(1, len(key)))
        (folders if info.is_dir() else files).add(key)
        plan.append((info, parts))
    if files & folders:
        raise ArchiveError("This archive holds a file and a folder with the same name, so nothing was unpacked.")
    return plan


def _keep_time(path: Path, date_time: tuple[int, ...]) -> None:
    try:
        stamp = time.mktime((*date_time, 0, 0, -1))
        os.utime(path, (stamp, stamp))
    except (OverflowError, ValueError, OSError):
        pass  # The file is right, and its time is only a convenience.


def unpack(path: Path, target: Path, stop: Callable[[], None], leftovers: list[Path]) -> int:
    """Unpack an archive into the folder ``target``, which mustn't exist yet. Returns how many files it held.

    Everything goes into a temporary folder beside ``target`` first, which only gets the final name
    once every file is out and has passed zip's own check. Otherwise it's removed, and anything that
    can't be removed is added to ``leftovers``, because it holds readable data.
    """
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise ArchiveError(f"This archive is damaged, so nothing was unpacked: {exc}") from exc
    staging = target.parent / f".myob-{uuid.uuid4().hex[:16]}.partial"
    with archive:
        plan = _plan(archive.infolist())
        needed = sum(info.file_size for info, _ in plan)
        free = shutil.disk_usage(target.parent).free
        if needed > free:
            raise ArchiveError(f"There isn't enough space to unpack this archive, so nothing was. It needs "
                               f"{needed / 1e9:.1f} GB, and {free / 1e9:.1f} GB is free.")
        staging.mkdir(mode=0o700)
        try:
            for info, parts in plan:
                stop()
                destination = staging.joinpath(*parts)
                if info.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as packed, open(destination, "xb") as unpacked:
                    while piece := packed.read(_CHUNK):
                        stop()
                        unpacked.write(piece)
                _keep_time(destination, info.date_time)
            os.rename(staging, target)
        except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
            _remove_folder(staging, leftovers)
            raise ArchiveError(f"This archive is damaged inside, so nothing was unpacked: {exc}") from exc
        except OSError as exc:
            _remove_folder(staging, leftovers)
            raise ArchiveError(f"This archive couldn't be unpacked here, so nothing was. "
                               f"The reason given was: {exc.strerror or exc}") from exc
        except BaseException:
            _remove_folder(staging, leftovers)
            raise
    return sum(1 for info, _ in plan if not info.is_dir())


def _remove_folder(folder: Path, leftovers: list[Path]) -> None:
    shutil.rmtree(folder, ignore_errors=True)
    if folder.exists():
        leftovers.append(folder)
