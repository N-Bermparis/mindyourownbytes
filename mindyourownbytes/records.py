"""A record, kept on this computer, of every encrypted file this app makes.

A cloud provider can't change what's on your own disk, so a checksum kept here can show
whether a downloaded file is exactly the one you made. Decrypting proves a file wasn't
damaged, and in passphrase mode that nobody without the passphrase made it. It can't show
that a provider handed back an older version, or swapped two files that share a passphrase.
This can, as long as the record survives.

The record is one line of JSON per file: its SHA-256, its name, where it was saved, its size,
and when. Names are visible to your provider anyway, but this file keeps them on your computer
too, so turning the record off, and clearing it, are both possible.

Checksums can also be saved as a plain ``SHA256SUMS`` file, which ``sha256sum --check`` or
PowerShell's ``Get-FileHash`` can verify without this app, and imported on another computer.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal

_CHUNK = 1024 * 1024
_SUMS_LINE = re.compile(r"^(?P<digest>[0-9a-fA-F]{64}) [ *](?P<path>.+)$")
#: What browsers and this app add to a name that's taken: " (2)", " (1)". Ignored when comparing names.
_NUMBERED = re.compile(r" \(\d+\)(?=(\.[^.\\/]*)*$)")

Verdict = Literal["match", "older", "renamed", "changed", "unknown"]


@dataclass(frozen=True)
class Record:
    sha256: str
    #: The file's name, such as "report.pdf.gpg".
    name: str
    #: Where it was saved, below the folder encrypted files go to, with "/" between folders.
    path: str
    size: int
    #: When it was made, in UTC. Empty for a record imported from a checksum file.
    made: str = ""
    #: Where an imported record came from. Empty for one made here.
    source: str = ""


@dataclass(frozen=True)
class Finding:
    verdict: Verdict
    #: Plain words for the person restoring. Empty when there's nothing to say.
    message: str
    record: Record | None = None
    #: The file a download matched, as "Medical/report.pdf.gpg", when other files made here share its name.
    #: Empty when the name alone says which file it is.
    where: str = ""

    @property
    def is_warning(self) -> bool:
        return self.verdict in ("older", "renamed", "changed")


def default_path(app_folder: Path) -> Path:
    return app_folder / "records.jsonl"


def sha256_of(path: Path, stop: Callable[[], None] | None = None) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        while piece := file.read(_CHUNK):
            if stop is not None:
                stop()
            digest.update(piece)
    return digest.hexdigest()


def _plain_name(name: str) -> str:
    """Compare names as people would: "report (1).pdf.gpg" is a download of "report.pdf.gpg"."""
    return _NUMBERED.sub("", name).casefold()


def _when(record: Record) -> str:
    if not record.made:
        return ""
    try:
        made = datetime.fromisoformat(record.made).astimezone()
    except ValueError:
        return ""
    return f" on {made:%Y-%m-%d %H:%M}"


def _folders(record: Record) -> tuple[str, ...]:
    """The folders a record was saved in, below where encrypted files go, compared as names are."""
    return tuple(_plain_name(part) for part in PurePosixPath(record.path).parts[:-1])


def _shown(record: Record) -> str:
    """Where a file was saved, as people would write it: "Taxes/report.pdf.gpg"."""
    return record.path or record.name


class Ledger:
    """The record file. Lines that can't be read are skipped and counted, never fatal."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.records: list[Record] = []
        self.unreadable = 0
        self._loaded = False

    def load(self) -> Ledger:
        self.records = []
        self.unreadable = 0
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            text = ""
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                fields = json.loads(line)
                record = Record(
                    str(fields["sha256"]).lower(), str(fields["name"]), str(fields["path"]), int(fields["size"]),
                    str(fields.get("made", "")), str(fields.get("source", "")),
                )
                if not re.fullmatch(r"[0-9a-f]{64}", record.sha256):
                    raise ValueError("not a SHA-256")
            except (ValueError, KeyError, TypeError):
                self.unreadable += 1
                continue
            self.records.append(record)
        self._loaded = True
        return self

    def add(self, records: Sequence[Record]) -> None:
        """Append, so that a crash can only ever lose the line being written."""
        if not records:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8", newline="\n") as file:
            for record in records:
                file.write(json.dumps(asdict(record), ensure_ascii=False) + "\n")
            file.flush()
            os.fsync(file.fileno())
        if self._loaded:
            self.records.extend(records)

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
        self.records = []
        self.unreadable = 0

    def check(self, path: Path, sha256: str) -> Finding:
        """Say whether a downloaded file is the one this computer made, and if not, how it differs.

        A name alone can't tell apart two files called "report.pdf.gpg" in different collections. So a
        download in a folder named like a collection that has a file of its name has to be that file.
        Anywhere else, a match says which file it matched whenever more than one has that name.
        """
        if not self._loaded:
            self.load()
        name = _plain_name(path.name)
        around = tuple(_plain_name(part) for part in path.parent.parts)
        named = [record for record in self.records if _plain_name(record.name) == name]
        # Files of this name from the collection whose folder the download is in, if it's in one.
        placed = [record for record in named if (folders := _folders(record)) and around[-len(folders):] == folders]
        same_content = [record for record in self.records if record.sha256 == sha256]
        here = [record for record in same_content if record in (placed or named)]
        if here:
            record = here[-1]
            # The same place only: "report (2).pdf.gpg" is a different file that this app named so, and a
            # file of the same name in another collection is a different file too.
            newer = [other for other in self.records if other.path.casefold() == record.path.casefold()
                     and other.sha256 != sha256 and other.made and record.made and other.made > record.made]
            if newer:
                return Finding("older", f"This is an older copy. A newer {_shown(record)} was made{_when(newer[-1])}, "
                                        "so your provider may have handed back an old version.", newer[-1])
            others = [other for other in named if other.sha256 != sha256 and _folders(other) != _folders(record)]
            if others and not placed:
                made = f"from {record.source}" if record.source else f"made here{_when(record)}"
                return Finding("match", f"Matches {_shown(record)}, {made}. {_shown(others[-1])} is a different file "
                                        "with the same name, so make sure this is the one you meant.",
                               record, _shown(record))
            words = (f"Matches the checksum from {record.source}." if record.source
                     else f"Matches the copy made here{_when(record)}.")
            return Finding("match", words, record)
        if same_content:
            other = same_content[-1]
            return Finding("renamed", f"This is the file that was saved as {_shown(other)}{_when(other)}. "
                                      "It may have been renamed, or swapped with another file.", other)
        if named:
            newest = (placed or named)[-1]
            where = f"from {newest.source}" if newest.source else f"made here{_when(newest)}"
            return Finding("changed", f"This isn't the {_shown(newest)} {where}. It may be an older version, "
                                      "or a different file with the same name.", newest)
        return Finding("unknown", "")


def records_for(outputs: Iterable[Path], root: Path, stop: Callable[[], None] | None = None) -> list[Record]:
    """Records for files just made, with their paths below ``root`` where they're inside it."""
    made = datetime.now(UTC).isoformat(timespec="seconds")
    records = []
    for output in outputs:
        try:
            where = output.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            where = output.name
        records.append(Record(sha256_of(output, stop), output.name, where, output.stat().st_size, made))
    return records


def checksum_file(entries: Iterable[tuple[str, str]]) -> str:
    """A ``SHA256SUMS`` file, from (SHA-256, path) pairs. ``sha256sum --check`` reads it as it is."""
    return "".join(f"{digest}  {PurePosixPath(path).as_posix()}\n" for digest, path in entries)


def read_checksum_file(text: str, source: str) -> tuple[list[Record], int]:
    """Records from a ``SHA256SUMS`` file, and how many of its lines couldn't be read."""
    records = []
    unreadable = 0
    for line in text.splitlines():
        line = line.strip().lstrip("﻿")
        if not line or line.startswith("#"):
            continue
        match = _SUMS_LINE.match(line)
        if not match:
            unreadable += 1
            continue
        path = match["path"].replace("\\", "/")
        records.append(Record(match["digest"].lower(), PurePosixPath(path).name, path, 0, "", source))
    return records, unreadable
