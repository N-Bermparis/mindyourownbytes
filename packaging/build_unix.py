"""Build the Linux or macOS download, on that system. CI runs this for every release, and so can you.

    python -m pip install --require-hashes -r requirements.txt -r requirements-build.txt
    python packaging/build_unix.py

It writes to dist/release/:

    mindyourownbytes-<version>-linux-x86_64.tar.gz   on Linux: the app in a folder, to unpack anywhere
    mindyourownbytes-<version>-macos-arm64.dmg       on a Mac: the app, to drag into Applications
    SHA256SUMS.txt

Unlike the Windows download, neither includes GnuPG. Linux distributions package it, and on a Mac it
comes from Homebrew or GPG Suite. The app says how to get it when it can't find it.
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tarfile
from importlib import metadata
from pathlib import Path

# The version, changelog and checksum rules are the same as for the Windows download.
import build_windows as shared

ROOT = shared.ROOT
PACKAGING = shared.PACKAGING
RELEASE = shared.RELEASE
DIST = ROOT / "dist"
APP = DIST / "mindyourownbytes"
MAC_APP = DIST / "mindyourownbytes.app"
#: The icon for a Mac goes here, where the PyInstaller recipe looks for it.
MAC_WORK = ROOT / "build" / "macos"
LINUX_WORK = ROOT / "build" / "linux"

#: Processor names as download pages show them, whatever the system calls them.
_MACHINES = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}


def system_name(platform_name: str = sys.platform) -> str:
    return "macos" if platform_name == "darwin" else "linux"


def base_name(version: str, platform_name: str = sys.platform, machine: str | None = None) -> str:
    machine = (machine or platform.machine()).lower()
    return f"mindyourownbytes-{version}-{system_name(platform_name)}-{_MACHINES.get(machine, machine)}"


def draw_icons(sizes: dict[Path, int]) -> None:
    """Draw the app's own icon at each size, from the same picture the app shows, rather than scaling one up."""
    code = (
        "import sys\n"
        "from PySide6.QtGui import QGuiApplication\n"
        "app = QGuiApplication([])\n"
        "from mindyourownbytes.gui import icons\n"
        "for target, size in zip(sys.argv[1::2], sys.argv[2::2]):\n"
        "    if not icons.app_pixmap(int(size)).save(target):\n"
        "        sys.exit(f'Could not draw {target}')\n"
    )
    arguments = [part for path, size in sizes.items() for part in (str(path), str(size))]
    # Drawn off screen, so this works on a build machine with no display.
    subprocess.run([sys.executable, "-c", code, *arguments], check=True, cwd=ROOT,
                   env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})


def make_mac_icon() -> Path:
    iconset = MAC_WORK / "mindyourownbytes.iconset"
    iconset.mkdir(parents=True)
    sizes = {}
    for size in (16, 32, 128, 256, 512):
        sizes[iconset / f"icon_{size}x{size}.png"] = size
        sizes[iconset / f"icon_{size}x{size}@2x.png"] = size * 2
    draw_icons(sizes)
    icns = MAC_WORK / "mindyourownbytes.icns"
    subprocess.run(["iconutil", "--convert", "icns", "--output", str(icns), str(iconset)], check=True)
    return icns


def run_pyinstaller(work: Path) -> None:
    subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--log-level", "WARN",
         "--distpath", str(DIST), "--workpath", str(work / "pyinstaller"),
         str(PACKAGING / "mindyourownbytes.spec")],
        check=True,
    )


def python_license() -> Path:
    """Python's license file, which sits in a different place in each kind of installation."""
    folder = Path(sys.base_prefix)
    candidates = [folder / "LICENSE.txt",
                  folder / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "LICENSE.txt"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    sys.exit("Python's license file wasn't found, and the download must include it.")


def add_licenses(folder: Path, version: str, libraries: str) -> None:
    """The licenses of everything inside, beside the app. ``libraries`` says where its libraries are."""
    licenses = folder / "licenses"
    licenses.mkdir()
    shutil.copy2(ROOT / "LICENSE", folder / "LICENSE.txt")
    shutil.copy2(python_license(), licenses / "Python.txt")
    bootloader = next(file for file in metadata.files("pyinstaller") if file.name == "COPYING.txt")
    shutil.copy2(bootloader.locate(), licenses / "PyInstaller.txt")
    qt = metadata.version("pyside6-essentials")
    notices = (PACKAGING / "THIRD-PARTY-NOTICES-unix.txt").read_text(encoding="utf-8")
    (folder / "THIRD-PARTY-NOTICES.txt").write_text(
        notices.format(
            version=version,
            libraries=libraries,
            qt=qt,
            qt_series=".".join(qt.split(".")[:2]),
            python=platform.python_version(),
            pyinstaller=metadata.version("pyinstaller"),
        ),
        encoding="utf-8",
    )


def _nobodys(entry: tarfile.TarInfo) -> tarfile.TarInfo:
    """An archive shouldn't carry the build machine's user and group names."""
    entry.uid = entry.gid = 0
    entry.uname = entry.gname = ""
    return entry


def make_linux_archive(version: str) -> Path:
    """The app folder, with a script that adds it to the applications menu, as one .tar.gz."""
    script = APP / "add-to-menu.sh"
    shutil.copy2(PACKAGING / "linux" / "add-to-menu.sh", script)
    script.chmod(0o755)
    draw_icons({APP / "mindyourownbytes.png": 256})
    add_licenses(APP, version, "_internal")
    archive = RELEASE / f"{base_name(version)}.tar.gz"
    with tarfile.open(archive, "w:gz", compresslevel=9) as output:
        output.add(APP, arcname=APP.name, filter=_nobodys)
    return archive


def make_mac_disk_image(version: str) -> Path:
    """A disk image holding the app beside a shortcut to Applications, so that installing is one drag."""
    staging = MAC_WORK / "disk-image"
    staging.mkdir(parents=True)
    shutil.copytree(MAC_APP, staging / MAC_APP.name, symlinks=True)
    (staging / "Applications").symlink_to("/Applications")
    add_licenses(staging, version, "mindyourownbytes.app/Contents/Frameworks")
    image = RELEASE / f"{base_name(version)}.dmg"
    subprocess.run(
        ["hdiutil", "create", "-volname", f"mindyourownbytes {version}", "-srcfolder", str(staging),
         "-fs", "HFS+", "-format", "UDZO", "-ov", str(image)],
        check=True,
    )
    return image


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the Linux or macOS download.")
    parser.add_argument("--tag", help="the git tag being released, which must match the app's version")
    args = parser.parse_args()
    if sys.platform not in ("linux", "darwin"):
        sys.exit("Build this on Linux or macOS. On Windows, use build_windows.py.")

    version = shared.app_version()
    if args.tag and args.tag != f"v{version}":
        sys.exit(f"The tag {args.tag} doesn't match the app's version, {version}.")
    shared.changelog_section(version)  # Better to find out now than after a long build.

    mac = sys.platform == "darwin"
    work = MAC_WORK if mac else LINUX_WORK
    for path in (APP, MAC_APP, RELEASE, work):
        shutil.rmtree(path, ignore_errors=True)
    RELEASE.mkdir(parents=True)
    work.mkdir(parents=True)
    if mac:
        make_mac_icon()
    run_pyinstaller(work)
    if mac:
        make_mac_disk_image(version)
    else:
        make_linux_archive(version)
    shared.write_checksums()
    for path in sorted(RELEASE.iterdir()):
        print(f"{path.stat().st_size / 1048576:7.1f} MB  {path.name}")


if __name__ == "__main__":
    main()
