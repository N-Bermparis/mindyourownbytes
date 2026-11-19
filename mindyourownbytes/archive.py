"""Archives: many files in one zip, so that GnuPG can encrypt them as one .gpg file.

Whoever stores an encrypted archive sees one file, its name, and roughly its size. The names,
folders, number, and sizes of the files inside are encrypted along with their contents.

This module only packs and unpacks ordinary zip files. GnuPG does all the encryption, and
``core.encrypt_archive`` connects the two. Packing writes the zip straight into GnuPG, so no
readable archive touches disk. Unpacking needs the decrypted zip on disk, because a zip keeps
its table of contents at the end. On restore, ``core`` keeps that copy, and the folder it's
unpacked into, in a private workspace (see ``workspace``), and the folder only gets its final name,
through ``safefs``, once everything is out. Nothing that already exists is ever replaced.

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

from mindyourownbytes import safefs

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
    """Names inside the archive: each file's folders as listed, changed only where they couldn't all
    be unpacked side by side.

    A list can hold the same name twice, such as two folders called "docs" from different places, or
    a file called "docs" and a folder called "docs". Windows can't tell names apart by case, so names
    that differ only in case clash too. Characters that Windows can't use in a name become "_".
    """
    entries = [(tuple(_usable(part) for part in PurePosixPath(relative).parts), False) for relative in relatives]
    return ["/".join(parts) for parts in _side_by_side(entries)]


def _usable(part: str) -> str:
    """A file or folder name that every system this app runs on can create."""
    if is_safe_name_part(part):
        return part
    usable = "".join("_" if character in INVALID_NAME_CHARACTERS or ord(character) < 32 else character
                     for character in part)[:255] or "_"
    if usable.endswith((".", " ")):
        usable = usable[:254] + "_"
    if usable.split(".")[0].strip().upper() in RESERVED_NAMES:
        usable = "_" + usable[:254]
    return usable if is_safe_name_part(usable) else "_"


def _key(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(part.casefold() for part in parts)


def _numbered(folder: tuple[str, ...], part: str, taken: Callable[[tuple[str, ...]], bool],
              is_folder: bool) -> tuple[str, ...]:
    """``part`` inside ``folder``, numbered as "report (2).pdf" or "docs (2)" until ``taken`` says it's free."""
    candidate, number = (*folder, part), 2
    while taken(_key(candidate)):
        name = PurePosixPath(part)
        numbered = f"{part} ({number})" if is_folder else f"{name.stem} ({number}){name.suffix}"
        candidate, number = (*folder, numbered), number + 1
    return candidate


def _side_by_side(entries: Sequence[tuple[tuple[str, ...], bool]]) -> list[tuple[str, ...]]:
    """Names for (parts, is a folder) entries that can all be created at once, in the order given.

    A file whose name is taken, by a file or a folder, gets a number. So does a folder whose name a
    file took, and everything listed inside that folder moves with it. Folders with the same name
    are one folder, as they would be on disk.
    """
    files: set[tuple[str, ...]] = set()
    folders: set[tuple[str, ...]] = set()
    #: Each folder as listed, compared without case, and the name it really gets.
    placed: dict[tuple[str, ...], tuple[str, ...]] = {}
    names = []
    for parts, is_folder in entries:
        folder: tuple[str, ...] = ()
        for depth in range(1, len(parts) + 1 if is_folder else len(parts)):
            listed = _key(parts[:depth])
            if listed not in placed:
                placed[listed] = _numbered(folder, parts[depth - 1], files.__contains__, is_folder=True)
            folder = placed[listed]
            folders.add(_key(folder))
        if is_folder:
            names.append(folder)
            continue
        name = _numbered(folder, parts[-1], lambda key: key in files or key in folders, is_folder=False)
        files.add(_key(name))
        names.append(name)
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


def _member_info(name: str, status: os.stat_result) -> zipfile.ZipInfo:
    """What ``ZipInfo.from_file`` makes for an ordinary file, from the open file's status rather than its name's."""
    date_time = time.localtime(status.st_mtime)[:6]
    if date_time[0] < 1980:  # What a zip can hold.
        date_time = (1980, 1, 1, 0, 0, 0)
    elif date_time[0] > 2107:
        date_time = (2107, 12, 31, 23, 59, 59)
    name = os.path.normpath(os.path.splitdrive(name)[1])
    while name[0] in (os.sep, os.altsep):
        name = name[1:]
    info = zipfile.ZipInfo(name, date_time)
    info.external_attr = (status.st_mode & 0xFFFF) << 16
    info.file_size = status.st_size
    return info


def pack(files: Sequence[tuple[Path, str] | tuple[Path, str, tuple[int, int] | None]], target: BinaryIO,
         stop: Callable[[], None], on_file: Callable[[int], None] | None = None,
         ) -> tuple[bytes, list[tuple[str, Path, tuple[int, ...] | None]]]:
    """Write ``files``, as (original, name inside) pairs, into one zip on ``target``.

    Each original is opened once, and read only through that (see ``safefs.open_original``): never
    through a link, and, when a third item gives the identity it had when it was chosen, only if it's
    still that file. Returns the SHA-256 of everything written, and the state of each original just
    before it was read, so that a check can tell afterwards whether any of them changed meanwhile.
    ``stop`` raises to cancel.
    """
    writer = _Writer(target, stop)
    states: list[tuple[str, Path, tuple[int, ...] | None]] = []
    archive = zipfile.ZipFile(writer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6)
    try:
        for index, (source, name, *chosen) in enumerate(files):
            stop()
            if on_file is not None:
                on_file(index)
            try:
                original = safefs.open_original(source, chosen[0] if chosen else None)
            except safefs.NotTheOriginal as exc:
                raise ArchiveError(f"{name}: {exc.strerror}, so no archive was kept.") from exc
            except OSError as exc:
                raise ArchiveError(f"The original is gone: {name} couldn't be opened, so no archive was kept. "
                                   f"The reason given was: {exc.strerror or exc}") from exc
            status = os.fstat(original.fileno())
            states.append((name, source, (status.st_size, status.st_mtime_ns, status.st_ino, status.st_dev)))
            info = _member_info(name, status)
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
    """Check every entry before anything is written, so that a bad one means nothing at all.

    Names that clash, which archives made before ``member_names`` prevented it can hold, are numbered
    the same way, so that everything comes out rather than nothing.
    """
    entries = []
    for info in infos:
        if info.flag_bits & 0x1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            raise ArchiveError("This archive uses a feature this app never writes, so nothing was unpacked. "
                               "Decrypt it with GnuPG and open it with another program.")
        entries.append((_member_parts(info.filename), info.is_dir()))
    return list(zip(infos, _side_by_side(entries), strict=True))


def _keep_time(path: Path, date_time: tuple[int, ...]) -> None:
    try:
        stamp = time.mktime((*date_time, 0, 0, -1))
        os.utime(path, (stamp, stamp))
    except (OverflowError, ValueError, OSError):
        pass  # The file is right, and its time is only a convenience.


def _create_new(path: Path) -> BinaryIO:
    """Open a new file for writing, refusing anything already there, including a link, even one to nothing.

    Its mode follows the umask, as a restored single file's does. While it's being written, the private
    folder it's in keeps others out, on systems that have such permissions.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    return os.fdopen(os.open(path, flags, 0o666), "wb")


def extract(path: Path, folder: Path, stop: Callable[[], None]) -> int:
    """Unpack the archive ``path`` into ``folder``, an empty folder the caller made. Returns how many files it held.

    Every name is checked before anything is written, so that a bad one means nothing at all. Each file is
    cut off at the size it claims, checked against zip's own CRC as it's read, and written to the drive
    before the next one starts. Raises ArchiveError, with a message that's safe to show.

    What's in ``folder`` is only complete when this returns. After a failure it's partial, and it's the
    caller's job to remove it rather than give it a final name.
    """
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise ArchiveError(f"This archive is damaged, so nothing was unpacked: {exc}") from exc
    with archive:
        plan = _plan(archive.infolist())
        needed = sum(info.file_size for info, _ in plan)
        free = shutil.disk_usage(folder).free
        if needed > free:
            raise ArchiveError(f"There isn't enough space to unpack this archive, so nothing was. It needs "
                               f"{needed / 1e9:.1f} GB, and {free / 1e9:.1f} GB is free.")
        try:
            for info, parts in plan:
                stop()
                destination = folder.joinpath(*parts)
                if info.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as packed, _create_new(destination) as unpacked:
                    while piece := packed.read(_CHUNK):
                        stop()
                        unpacked.write(piece)
                    unpacked.flush()
                    os.fsync(unpacked.fileno())
                _keep_time(destination, info.date_time)
        except (zipfile.BadZipFile, zlib.error, EOFError) as exc:
            raise ArchiveError(f"This archive is damaged inside, so nothing was unpacked: {exc}") from exc
        except OSError as exc:
            raise ArchiveError(f"This archive couldn't be unpacked here, so nothing was. "
                               f"The reason given was: {exc.strerror or exc}") from exc
    return sum(1 for info, _ in plan if not info.is_dir())


def unpack(path: Path, target: Path, stop: Callable[[], None], leftovers: list[Path]) -> int:
    """Unpack an archive into the folder ``target``, which mustn't exist yet. Returns how many files it held.

    Everything goes into a temporary folder beside ``target`` first, which only gets the final name once
    every file is out and has passed zip's own check, and then only if nothing has that name, not even an
    empty folder: see ``safefs``. Otherwise it's removed, and anything that can't be removed is added to
    ``leftovers``, because it holds readable data.
    """
    staging = target.parent / f".myob-{uuid.uuid4().hex[:16]}.partial"
    staging.mkdir(mode=0o700)  # Fails rather than reuse anything already there, so this one is ours to remove.
    try:
        count = extract(path, staging, stop)
        try:
            safefs.publish_directory(staging, target)
        except FileExistsError as exc:
            raise ArchiveError(f"Something called {target.name} is already there, so nothing was unpacked, "
                               "and it wasn't touched.") from exc
        except safefs.PublishFailed as exc:
            raise ArchiveError(str(exc)) from exc
        except OSError as exc:
            raise ArchiveError(f"This archive couldn't be unpacked here, so nothing was. "
                               f"The reason given was: {exc.strerror or exc}") from exc
    except BaseException:
        _remove_folder(staging, leftovers)
        raise
    safefs.sync_directory(target.parent)
    return count


def _remove_folder(folder: Path, leftovers: list[Path]) -> None:
    """Remove a folder this module made, without following any link inside it."""
    if not os.path.lexists(folder):
        return
    shutil.rmtree(folder, ignore_errors=True)
    if os.path.lexists(folder):
        leftovers.append(folder)
