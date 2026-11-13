"""Private folders for decrypted data on its way to its final name, remembered until they're gone.

Restoring decrypts. Until the result has its final name, it lives in a **workspace**: a hidden folder
named ``.myob-<16 hex digits>.partial``, made beside the destination so that publishing is a rename on
the same drive. Everything decrypted for one file goes in there, including a whole decrypted zip while
an archive is unpacked, so there's exactly one thing to delete afterwards.

* **Private.** It's made with mode 0700, so on Linux and macOS no other account can look inside, whatever
  the destination folder allows. Windows has no such mode: the workspace gets the destination's own
  permissions, which are what the restored files get anyway.
* **Provably the app's.** It holds a marker file with a random token. Only a real folder, not a link,
  named like a workspace, holding the matching token, and on Linux and macOS owned by you, is ever
  deleted as one. Nothing a person chose is ever deleted, and no link is ever followed.
* **Remembered.** Before anything readable goes in, the ``Journal`` notes where it is, in the app's own
  folder. The note goes when the workspace does. If the app is killed, crashes, or loses power, the note
  stays, and the next start can say exactly where readable data was left, and offer to delete it.
* **Several copies of the app** each hold a lock on their own session file while they run. A workspace is
  only called abandoned once the copy that made it has stopped, so one copy never deletes another's.

Deleting a file removes its name. It doesn't erase its contents from an SSD, a copy-on-write file
system, a backup, or a sync client's history, so nothing here claims to securely erase anything.
"""

from __future__ import annotations

import errno
import hmac
import json
import os
import re
import secrets
import shutil
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

PREFIX = ".myob-"
SUFFIX = ".partial"
#: The name of every workspace, and of every file staged while encrypting.
NAME = re.compile(r"\.myob-[0-9a-f]{16}\.partial")
#: Inside each workspace. Holds the token that proves the app made it.
MARKER = ".myob-workspace"
_TOKEN = re.compile(r"[0-9a-f]{32}")
#: Windows marks links and junctions as reparse points.
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


@dataclass(frozen=True)
class Workspace:
    path: Path
    token: str

    def __repr__(self) -> str:
        return f"Workspace({self.path})"


@dataclass(frozen=True)
class Leftover:
    """A workspace noted by a copy of the app that has stopped, and so was never deleted."""

    path: Path
    token: str


class WorkspaceError(OSError):
    """A workspace couldn't be made. The message is safe to show the user."""


def _is_reparse_point(status: os.stat_result) -> bool:
    return bool(getattr(status, "st_file_attributes", 0) & _REPARSE_POINT) or bool(getattr(status, "st_reparse_tag", 0))


def owned(path: Path, token: str) -> bool:
    """Whether ``path`` is, beyond doubt, the workspace made with ``token``.

    That's a real folder, not a link or junction, named like a workspace, holding a marker file (also not a
    link) whose content is exactly the token, and on Linux and macOS owned by this account. Anything less
    and it's left alone, because it could be someone's own folder.
    """
    if not _TOKEN.fullmatch(token) or not NAME.fullmatch(path.name):
        return False
    try:
        status = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISDIR(status.st_mode) or _is_reparse_point(status):
        return False
    if hasattr(os, "getuid") and status.st_uid != os.getuid():
        return False
    marker = path / MARKER
    try:
        marker_status = os.lstat(marker)
        if not stat.S_ISREG(marker_status.st_mode) or _is_reparse_point(marker_status) or marker_status.st_size > 64:
            return False
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(marker, flags)
        try:
            content = os.read(descriptor, 65)
        finally:
            os.close(descriptor)
    except OSError:
        return False
    return hmac.compare_digest(content, token.encode("ascii"))


def _remove_tree(path: Path) -> None:
    """Delete a folder already confirmed as a workspace. shutil.rmtree never follows links inside it.

    On Linux and macOS it works through open folder handles, so a link swapped in meanwhile can't redirect it.
    """
    status = os.lstat(path)
    if not stat.S_ISDIR(status.st_mode) or _is_reparse_point(status):
        raise OSError(errno.ENOTDIR, "Not a workspace folder", str(path))
    shutil.rmtree(path)


def create(parent: Path, journal: Journal | None = None) -> Workspace:
    """Make a new, empty, private workspace in ``parent``, noted in ``journal`` before anything goes in."""
    for _ in range(16):
        path = parent / f"{PREFIX}{secrets.token_hex(8)}{SUFFIX}"
        try:
            # mkdir never reuses anything already there, so whatever it makes is the app's to delete later.
            path.mkdir(mode=0o700)
        except FileExistsError:
            continue
        break
    else:
        raise WorkspaceError(f"No private folder could be made in {parent}, so nothing was restored.")
    token = secrets.token_hex(16)
    workspace = Workspace(path, token)
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path / MARKER, flags, 0o600)
        try:
            os.write(descriptor, token.encode("ascii"))
        finally:
            os.close(descriptor)
        if journal is not None:
            try:
                journal.record(workspace)
            except OSError as exc:
                # Without the note, readable data left by a crash couldn't be found again, so don't start.
                raise WorkspaceError(f"The app couldn't note where it keeps decrypted data while restoring, in "
                                     f"{journal.directory}, so nothing was restored. The reason given was: "
                                     f"{exc.strerror or exc}") from exc
    except BaseException:
        shutil.rmtree(path, ignore_errors=True)
        raise
    return workspace


def remove(workspace: Workspace, journal: Journal | None = None) -> bool:
    """Delete a workspace and everything in it. True if it's gone. Its note goes only once it has."""
    try:
        if os.path.lexists(workspace.path):
            _remove_tree(workspace.path)
    except OSError:
        pass
    gone = not os.path.lexists(workspace.path)
    if gone and journal is not None:
        journal.forget(workspace.token)
    return gone


def _lock(handle: BinaryIO) -> None:
    """Hold an exclusive lock on the file, without waiting. Raises OSError if another process holds it."""
    if os.name == "nt":
        import msvcrt
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class Journal:
    """Notes of every workspace in use, kept in the app's own folder rather than beside the workspaces.

    Each note is its own small file, named by its workspace's token, so copies of the app never write to
    the same file. A note holds a path and a session, never anything that was decrypted.
    """

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.session = secrets.token_hex(16)
        self._lock: BinaryIO | None = None
        #: Restores on several threads share one session, which must only be started once.
        self._guard = threading.Lock()

    def __repr__(self) -> str:
        return f"Journal({self.directory})"

    def _session_file(self, session: str) -> Path:
        return self.directory / f"session-{session}.lock"

    def _start_session(self) -> None:
        """Lock this copy's session file, which the system releases however this copy ends."""
        with self._guard:
            if self._lock is not None:
                return
            self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            handle = open(self._session_file(self.session), "a+b")  # noqa: SIM115 - held until close()
            try:
                _lock(handle)
            except OSError:
                handle.close()
                raise
            self._lock = handle

    def close(self) -> None:
        """End this copy's session. Its notes stay, for any workspace that couldn't be deleted."""
        with self._guard:
            if self._lock is None:
                return
            try:
                _unlock(self._lock)
            except OSError:
                pass
            self._lock.close()
            self._lock = None
            try:
                self._session_file(self.session).unlink()
            except OSError:
                pass

    def record(self, workspace: Workspace) -> None:
        self._start_session()
        note = {"path": str(workspace.path), "session": self.session,
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        target = self.directory / f"{workspace.token}.json"
        pending = self.directory / f".{workspace.token}.json.tmp"
        pending.write_text(json.dumps(note), encoding="utf-8")
        os.replace(pending, target)

    def forget(self, token: str) -> None:
        if _TOKEN.fullmatch(token):
            try:
                (self.directory / f"{token}.json").unlink(missing_ok=True)
            except OSError:
                pass

    def _session_running(self, session: str) -> bool:
        """Whether the copy of the app that started ``session`` still runs. When unsure, it does."""
        try:
            handle = open(self._session_file(session), "r+b")  # noqa: SIM115 - closed below
        except FileNotFoundError:
            return False
        except OSError:
            return True
        with handle:
            try:
                _lock(handle)
            except OSError:
                return True
            try:
                _unlock(handle)
            except OSError:
                pass
        return False

    def leftovers(self) -> list[Leftover]:
        """Workspaces noted by copies of the app that have stopped. Notes of ones already gone are dropped."""
        found: list[Leftover] = []
        if not self.directory.is_dir():
            return found
        ended: set[str] = set()
        for note_path in sorted(self.directory.glob("*.json")):
            token = note_path.stem
            if not _TOKEN.fullmatch(token):
                continue
            try:
                note = json.loads(note_path.read_text(encoding="utf-8"))
                path, session = Path(note["path"]), str(note["session"])
            except (OSError, ValueError, KeyError, TypeError):
                continue
            if session == self.session or (session not in ended and self._session_running(session)):
                continue
            ended.add(session)
            if not os.path.lexists(path):
                self.forget(token)
                continue
            found.append(Leftover(path, token))
        self._tidy_sessions()
        return found

    def _tidy_sessions(self) -> None:
        """Delete session files of copies that have stopped and left no notes."""
        noted = set()
        for note_path in self.directory.glob("*.json"):
            try:
                noted.add(str(json.loads(note_path.read_text(encoding="utf-8"))["session"]))
            except (OSError, ValueError, KeyError, TypeError):
                continue
        for lock_path in self.directory.glob("session-*.lock"):
            session = lock_path.stem.removeprefix("session-")
            if session != self.session and session not in noted and not self._session_running(session):
                try:
                    lock_path.unlink()
                except OSError:
                    pass

    def clean(self, leftovers: list[Leftover]) -> tuple[list[Path], list[Path]]:
        """Delete leftover workspaces that are provably the app's. Returns (couldn't be deleted, not confirmed).

        One that can't be confirmed is never touched, and its note is dropped, so it isn't offered again.
        One that couldn't be deleted keeps its note, so it's offered again next time.
        """
        failed: list[Path] = []
        unconfirmed: list[Path] = []
        for leftover in leftovers:
            if not os.path.lexists(leftover.path):
                self.forget(leftover.token)
            elif not owned(leftover.path, leftover.token):
                unconfirmed.append(leftover.path)
                self.forget(leftover.token)
            elif not remove(Workspace(leftover.path, leftover.token), self):
                failed.append(leftover.path)
        return failed, unconfirmed
