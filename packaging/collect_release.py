"""Put the three downloads together for a release: one folder, one SHA256SUMS.txt, and the notes.

Each download is built and tested on its own system. CI runs this afterwards, in a job that can't
write to the repository, so the job that creates the draft release only uploads what this made.

    python packaging/collect_release.py downloads dist

reads the windows-download, linux-download and macos-download artifacts under the first folder,
and writes dist/release/ and dist/release-notes.md.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
from pathlib import Path

PARTS = ("windows-download", "linux-download", "macos-download")
#: The notes hold exactly one list of checksums, in a block like this.
_CHECKSUM_BLOCK = re.compile(r"```text\n.*?```", re.DOTALL)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while piece := file.read(1024 * 1024):
            digest.update(piece)
    return digest.hexdigest()


def release_folder(artifact: Path) -> Path:
    """An artifact holds its files either in release/ or at its top, depending on how it was uploaded."""
    nested = artifact / "release"
    return nested if nested.is_dir() else artifact


def collect(source: Path, target: Path) -> Path:
    """Copy every download's files into ``target``/release, then write the checksums and the notes."""
    release = target / "release"
    release.mkdir(parents=True)
    for part in PARTS:
        if not (source / part).is_dir():
            sys.exit(f"The {part} artifact is missing, so the release would be incomplete.")
        for path in sorted(release_folder(source / part).iterdir()):
            if not path.is_file() or path.name in ("SHA256SUMS.txt", "release-notes.md"):
                continue
            if (release / path.name).exists():
                sys.exit(f"Two downloads both made {path.name}.")
            shutil.copy2(path, release / path.name)
    checksums = "".join(f"{sha256(path)}  {path.name}\n" for path in sorted(release.iterdir()))
    with (release / "SHA256SUMS.txt").open("w", encoding="utf-8", newline="\n") as file:
        file.write(checksums)

    # The Windows build wrote the notes, with names for every download but only its own checksums.
    notes = (source / "windows-download" / "release-notes.md").read_text(encoding="utf-8")
    if len(_CHECKSUM_BLOCK.findall(notes)) != 1:
        sys.exit("The release notes should hold exactly one list of checksums.")
    notes = _CHECKSUM_BLOCK.sub(lambda _match: f"```text\n{checksums}```", notes)
    written = target / "release-notes.md"
    with written.open("w", encoding="utf-8", newline="\n") as file:
        file.write(notes)
    return release


def main() -> None:
    parser = argparse.ArgumentParser(description="Put the three downloads together for a release.")
    parser.add_argument("artifacts", type=Path, help="the folder the downloads' artifacts are in")
    parser.add_argument("target", type=Path, help="where to write release/ and release-notes.md")
    args = parser.parse_args()
    release = collect(args.artifacts, args.target)
    for path in sorted(release.iterdir()):
        print(f"{path.stat().st_size / 1048576:7.1f} MB  {path.name}")


if __name__ == "__main__":
    main()
