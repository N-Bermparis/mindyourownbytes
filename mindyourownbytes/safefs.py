"""Giving finished files and folders their names, without ever replacing anything or showing half of it.

Two promises rest on this module:

* **Nothing that already exists is replaced**: not a file, not a folder (even an empty one), not a link,
  and not a link that points nowhere.
* **A name only ever appears with its complete contents.** Everything is written under a temporary name
  first, and gets its final name in one step that the operating system carries out atomically.

``os.rename`` keeps the second promise everywhere, but not the first: on Linux and macOS it replaces an
empty folder, and a file, without a word. So each system gets the call that refuses instead:

* **Windows**: ``MoveFileExW`` without ``MOVEFILE_REPLACE_EXISTING``, which is what ``os.rename`` calls
  there. It fails if anything at all has the new name.
* **Linux**: ``renameat2`` with ``RENAME_NOREPLACE`` (Linux 3.15, glibc 2.28). The kernel checks the name
  and renames in one step, under the folder's lock.
* **macOS**: ``renamex_np`` with ``RENAME_EXCL`` (macOS 10.12).

A file can also be published with a hard link, which every system creates only if the name is free. A
drive that supports neither way, such as a network share that refuses both, makes publishing fail with
``PublicationUnsupported``. There is deliberately no fallback that copies into the final name, because
anyone looking during the copy would see a partial file under it.

**Atomic isn't the same as durable.** Atomic means nobody ever sees half a result. Durable means the result
survives a power cut. ``sync_file`` and ``sync_directory`` ask the system to write data and names to the
drive, which makes that much likelier, but drives and sync clients can still lose recent writes, so neither
is promised.
"""

from __future__ import annotations

import ctypes
import errno
import functools
import os
import platform
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

#: Errors that mean "this drive or system can't do that", rather than "that failed".
_UNSUPPORTED = frozenset({errno.EINVAL, errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP})

#: Errors from os.link that mean the drive has no hard links. EPERM is what Linux says for that.
_NO_HARD_LINKS = frozenset({errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EMLINK, errno.ENOSYS})

#: Errors from syncing that mean it can't be asked for here, rather than that data was lost.
_CANNOT_SYNC = frozenset({errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EBADF, errno.EACCES,
                          errno.EPERM, errno.EROFS, errno.EISDIR})

_AT_FDCWD = -100
_RENAME_NOREPLACE = 1  # linux/fs.h
_RENAME_EXCL = 0x00000004  # macOS stdio.h
#: For a C library without its own renameat2. These two are the processors the Linux download is built for.
_RENAMEAT2_SYSCALL = {"x86_64": 316, "amd64": 316, "aarch64": 276, "arm64": 276}

#: How many names publish_under_free_name tries when other programs keep taking them first.
_ATTEMPTS = 100


class PublishFailed(OSError):
    """A finished result couldn't be given its name. The message is safe to show the user.

    Nothing was replaced, and nothing appeared under the final name.
    """

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.errno = code


class PublicationUnsupported(PublishFailed):
    """This drive can't give a result its name without the risk of replacing something already there."""


def _unsupported(destination: Path, code: int | None) -> PublicationUnsupported:
    return PublicationUnsupported(
        f"The drive that holds {destination.parent} can't give a finished file its name without the risk of "
        "replacing one that's already there, so nothing was saved. Choose a folder on another drive, such as "
        "your computer's own disk.", code)


@functools.cache
def _libc() -> ctypes.CDLL:
    # None means the program itself and every library it has loaded, which includes the C library.
    return ctypes.CDLL(None, use_errno=True)


def _linux_rename_noreplace(source: bytes, destination: bytes) -> int:
    """renameat2(..., RENAME_NOREPLACE). Returns 0, or the error number."""
    libc = _libc()
    function = getattr(libc, "renameat2", None)
    if function is not None:
        function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        function.restype = ctypes.c_int
        result = function(_AT_FDCWD, source, _AT_FDCWD, destination, _RENAME_NOREPLACE)
    else:
        number = _RENAMEAT2_SYSCALL.get(platform.machine().lower())
        if number is None:
            return errno.ENOSYS
        libc.syscall.restype = ctypes.c_long
        result = libc.syscall(ctypes.c_long(number), ctypes.c_int(_AT_FDCWD), ctypes.c_char_p(source),
                              ctypes.c_int(_AT_FDCWD), ctypes.c_char_p(destination), ctypes.c_uint(_RENAME_NOREPLACE))
    return ctypes.get_errno() or errno.EIO if result != 0 else 0


def _macos_rename_excl(source: bytes, destination: bytes) -> int:
    """renamex_np(..., RENAME_EXCL). Returns 0, or the error number."""
    function = getattr(_libc(), "renamex_np", None)
    if function is None:
        return errno.ENOSYS
    function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    result = function(source, destination, _RENAME_EXCL)
    return ctypes.get_errno() or errno.EIO if result != 0 else 0


def _system() -> str:
    """Which way of renaming without replacing this system has: windows, linux, macos, or none."""
    if os.name == "nt":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    return "macos" if sys.platform == "darwin" else "none"


def rename_no_replace(source: Path, destination: Path) -> None:
    """Give ``source`` the name ``destination`` in one atomic step, or fail without changing anything.

    Raises FileExistsError if anything has that name, whether a file, a folder, or a link, and
    PublicationUnsupported if this system or drive can't refuse that reliably. Works for files and folders.
    """
    system = _system()
    if system == "windows":
        # MoveFileExW(source, destination, 0): documented to fail when the destination exists.
        os.rename(source, destination)
        return
    if system == "linux":
        call = _linux_rename_noreplace
    elif system == "macos":
        call = _macos_rename_excl
    else:
        raise _unsupported(destination, errno.ENOSYS)
    code = call(os.fsencode(source), os.fsencode(destination))
    if code == 0:
        return
    if code in _UNSUPPORTED:
        raise _unsupported(destination, code)
    # OSError picks the matching subclass, such as FileExistsError for EEXIST.
    raise OSError(code, os.strerror(code), str(source), None, str(destination))


def publish_file(staged: Path, destination: Path) -> None:
    """Give a complete, staged file its final name, unless something already has it.

    Raises FileExistsError if the name is taken, and PublicationUnsupported if the drive offers no
    atomic way to do this. ``staged`` may still exist afterwards, when a hard link was used: deleting it
    is the caller's job, as it is after a failure.
    """
    if _system() == "windows":
        try:
            # A hard link, first: unlike a rename, it works while a virus scanner still has the file open.
            os.link(staged, destination)
            return
        except FileExistsError:
            raise
        except OSError:
            pass  # FAT and exFAT have no hard links. Renaming without replacing works on every Windows drive.
        rename_no_replace(staged, destination)
        return
    try:
        rename_no_replace(staged, destination)
        return
    except PublicationUnsupported:
        pass  # Such as a network share. Many of those still make hard links, only if the name is free.
    try:
        os.link(staged, destination)
    except FileExistsError:
        raise
    except OSError as exc:
        if exc.errno in _NO_HARD_LINKS:
            raise _unsupported(destination, exc.errno) from exc
        raise


def publish_directory(staged: Path, destination: Path) -> None:
    """Give a complete, staged folder its final name, unless something already has it, even an empty folder."""
    rename_no_replace(staged, destination)


def unique_target(path: Path) -> Path:
    """Pick a free name, so earlier backups and restores are never overwritten.

    The counter goes before the inner extension, so ``report.pdf.gpg`` becomes
    ``report (2).pdf.gpg`` and later restores as ``report (2).pdf``. Placing it
    last would produce ``report.pdf (2)``, which no application can open.

    This only suggests a name. Another program can take it a moment later, so whatever is published
    under it must still refuse to replace anything, as ``publish_under_free_name`` does.
    """
    if not os.path.lexists(path):
        return path
    name = path.name
    outer = ""
    if name.lower().endswith((".gpg", ".pgp")):
        name, outer = name[:-4], name[-4:]
    stem, inner = os.path.splitext(name)
    for number in range(2, 10001):
        candidate = path.with_name(f"{stem} ({number}){inner}{outer}")
        if not os.path.lexists(candidate):
            return candidate
    raise RuntimeError("Too many backups with the same filename")


def publish_under_free_name(staged: Path, preferred: Path, publish: Callable[[Path, Path], None]) -> Path:
    """Publish under ``preferred``, or the first free name after it, such as "report (2).pdf". Returns it.

    Finding a free name and taking it can't be one step, so a name that another program, or another copy
    of this app, takes in between is skipped rather than replaced.
    """
    for _ in range(_ATTEMPTS):
        candidate = unique_target(preferred)
        try:
            publish(staged, candidate)
        except FileExistsError:
            continue
        return candidate
    raise PublishFailed(f"Other programs kept taking every free name like {preferred.name}, so nothing was saved.",
                        errno.EEXIST)


def _full_sync(descriptor: int) -> None:
    if sys.platform == "darwin":
        import fcntl
        try:
            # On a Mac, fsync only reaches the drive's cache. F_FULLFSYNC asks the drive to write it out.
            fcntl.fcntl(descriptor, fcntl.F_FULLFSYNC)
            return
        except (AttributeError, OSError):
            pass  # Not every drive supports it. fsync below is still worth asking for.
    os.fsync(descriptor)


def sync_file(path: Path) -> None:
    """Ask the system to write a file's data to the drive, before the file gets its final name.

    Raises OSError if the system reports that the data couldn't be written, such as for a full disk, so
    that it isn't published. Where syncing can't be asked for at all, this does nothing.
    """
    # Windows only flushes through a handle that may write.
    flags = (os.O_RDWR if os.name == "nt" else os.O_RDONLY) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno in _CANNOT_SYNC:
            return
        raise
    try:
        _full_sync(descriptor)
    except OSError as exc:
        if exc.errno not in _CANNOT_SYNC:
            raise
    finally:
        os.close(descriptor)


def sync_directory(path: Path) -> None:
    """Ask the system to write a folder's list of names to the drive, so a new name survives a power cut.

    Best effort, and only where the system offers it: Windows can't sync a folder this way, and some
    drives refuse. Its result is never a reason to report failure, because the name was already given.
    """
    if os.name == "nt":
        return
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        _full_sync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


# ------------------------------------------------------------------ reading originals by what they are


class NotTheOriginal(OSError):
    """A name no longer leads to the ordinary file that was chosen: it's a link now, say, or another file."""


#: What tells one file apart from another that later takes its name: (device, inode), or Windows' file ID.
Identity = tuple[int, int]

_GENERIC_READ = 0x80000000
#: Others may still read, write, rename, and delete the file while it's open, as they could before.
_FILE_SHARE_ALL = 0x1 | 0x2 | 0x4
_OPEN_EXISTING = 3
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000


def identity(status: os.stat_result) -> Identity | None:
    """None where the drive gives every file the same number, so that files can't be told apart by it."""
    return (status.st_dev, status.st_ino) if status.st_ino else None


def identity_of(path: Path) -> Identity | None:
    """The identity of the ordinary file named ``path`` itself, never of a link's target. None for anything else."""
    try:
        status = os.lstat(path)
    except OSError:
        return None
    return identity(status) if stat.S_ISREG(status.st_mode) else None


def _open_for_reading(path: Path) -> int:
    if os.name == "nt":
        import _winapi
        import msvcrt

        handle = _winapi.CreateFile(str(path), _GENERIC_READ, _FILE_SHARE_ALL, 0, _OPEN_EXISTING,
                                    _FILE_FLAG_SEQUENTIAL_SCAN, 0)
        try:
            return msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
        except BaseException:
            _winapi.CloseHandle(handle)
            raise
    # Never through a link at the end, and never stuck waiting, should a pipe have taken the name.
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise NotTheOriginal(exc.errno, f"{path.name} is a link now, so it wasn't read") from exc
        raise


def open_original(path: Path, expected: Identity | None = None) -> BinaryIO:
    """Open an original for reading, only if its name leads straight to an ordinary file: the one expected.

    Whatever reads it then reads only from the open file, never by its name again, so swapping the name
    meanwhile, for a link to another file say, changes nothing that's read. The name must not lead
    through a link at its end, the file must be an ordinary one, and, if ``expected`` is given, it must
    be the same file that had the name when it was chosen. Otherwise this raises ``NotTheOriginal``.

    ``still_named`` says afterwards whether the name still leads to the same file.
    """
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise NotTheOriginal(errno.EINVAL, f"{path.name} isn't an ordinary file any more, so it wasn't read. "
                                           "It may have been replaced by a link or a folder")
    descriptor = _open_for_reading(path)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(before):
            raise NotTheOriginal(errno.EINVAL, f"{path.name} was replaced as it was being opened, so it wasn't read")
        if expected is not None and identity(opened) is not None and identity(opened) != tuple(expected):
            raise NotTheOriginal(errno.EINVAL, f"{path.name} isn't the file that was chosen: another file has "
                                               "taken its name, so it wasn't read. Add it again to use it as it is now")
        if os.name != "nt":
            os.set_blocking(descriptor, True)
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def still_named(path: Path, original: BinaryIO) -> bool:
    """Whether ``path`` still leads to the open file ``original``, rather than to nothing, or to another file."""
    now = identity_of(path)
    opened = identity(os.fstat(original.fileno()))
    return now is not None and (opened is None or now == opened)
