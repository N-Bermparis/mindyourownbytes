"""Organize encrypted exports into collections.

The filesystem is the catalog: a collection is simply a top-level folder of the
export directory. There is no database to fall out of sync or to leak, and files
stay organized in Explorer and on any cloud provider, with or without this app.
Everything here handles ciphertext only and never decrypts or deletes anything.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from mindyourownbytes.core import ENCRYPTED_SUFFIXES, is_link_or_junction, publish_no_overwrite, unique_target

MAX_COLLECTION_NAME = 64
_INVALID_CHARACTERS = set('<>:"/\\|?*')
_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


@dataclass(frozen=True)
class LibraryEntry:
    path: Path
    relative: Path
    #: The top-level folder, or "" for a file outside any collection.
    collection: str
    size: int
    modified: float

    @property
    def display_name(self) -> str:
        """The name the file will have once restored."""
        return self.path.name[:-4] if self.path.name.lower().endswith(ENCRYPTED_SUFFIXES) else self.path.name


def validate_collection_name(name: str) -> str:
    """Return a cleaned name that is one safe folder on every platform.

    This is what stops a typed name like ``..\\..\\Startup`` becoming a path, and
    it also rejects names that Windows cannot create.
    """
    cleaned = name.strip()
    if not cleaned:
        raise ValueError("A collection needs a name.")
    if len(cleaned) > MAX_COLLECTION_NAME:
        raise ValueError(f"Collection names can be at most {MAX_COLLECTION_NAME} characters.")
    if any(character in _INVALID_CHARACTERS or ord(character) < 32 for character in cleaned):
        raise ValueError('Collection names cannot contain < > : " / \\ | ? * or control characters.')
    if cleaned.startswith(".") or cleaned.endswith("."):
        raise ValueError("Collection names cannot start or end with a dot.")
    if cleaned.split(".")[0].upper() in _RESERVED_NAMES:
        raise ValueError(f"“{cleaned}” is a reserved name on Windows.")
    return cleaned


def list_collections(root: Path) -> list[str]:
    if not root.is_dir():
        return []
    names = [
        child.name for child in root.iterdir()
        if child.is_dir() and not child.name.startswith(".") and not is_link_or_junction(child)
    ]
    return sorted(names, key=str.casefold)


def create_collection(root: Path, name: str) -> Path:
    folder = root / validate_collection_name(name)
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def scan_library(root: Path) -> list[LibraryEntry]:
    """List every encrypted file under ``root``. Links are skipped, never followed."""
    entries: list[LibraryEntry] = []
    if not root.is_dir():
        return entries
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        here = Path(directory)
        dirnames[:] = sorted(name for name in dirnames if not is_link_or_junction(here / name))
        for filename in sorted(filenames):
            path = here / filename
            if path.suffix.lower() not in ENCRYPTED_SUFFIXES or is_link_or_junction(path):
                continue
            try:
                info = path.stat()
            except OSError:
                continue
            relative = path.relative_to(root)
            collection = relative.parts[0] if len(relative.parts) > 1 else ""
            entries.append(LibraryEntry(path, relative, collection, info.st_size, info.st_mtime))
    return entries


def move_to_collection(root: Path, paths: Iterable[Path], collection: str) -> list[Path]:
    """Move encrypted files into a collection, or to the top level with ``""``.

    Subfolders inside the old collection are kept, and an existing file is never
    overwritten.
    """
    target_folder = root / validate_collection_name(collection) if collection else root
    resolved_root = root.resolve()
    moved: list[Path] = []
    for path in paths:
        try:
            relative = path.resolve().relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError(f"This file is not in the library: {path.name}") from exc
        inner = Path(*relative.parts[1:]) if len(relative.parts) > 1 else relative
        destination = target_folder / inner
        if destination.resolve() == path.resolve():
            moved.append(path)
            continue
        destination = unique_target(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        publish_no_overwrite(path, destination)
        path.unlink(missing_ok=True)
        moved.append(destination)
    return moved
