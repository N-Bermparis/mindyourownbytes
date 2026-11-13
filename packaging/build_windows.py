"""Build the Windows download. CI runs this for every release, and so can you.

    python -m pip install --require-hashes -r requirements.txt -r requirements-build.txt
    python packaging/build_windows.py

It needs 7-Zip, and writes to dist/release/:

    mindyourownbytes-<version>-windows-x64-setup.exe     the installer most people want
    mindyourownbytes-<version>-windows-x64-portable.zip  the same app, without installing
    gnupg-w32-<version>.tar.xz                           source code of the included GnuPG
    SHA256SUMS.txt

Everything downloaded here is checked against a hash pinned below. To move to a newer
GnuPG, follow docs/RELEASE_CHECKLIST.md.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from dataclasses import dataclass
from fnmatch import fnmatch
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGING = ROOT / "packaging"
WORK = ROOT / "build" / "windows"
APP = ROOT / "dist" / "mindyourownbytes"
RELEASE = ROOT / "dist" / "release"
REPOSITORY = "https://github.com/N-Bermparis/mindyourownbytes"


@dataclass(frozen=True)
class Download:
    url: str
    sha256: str

    @property
    def name(self) -> str:
        return self.url.rsplit("/", 1)[1]


GNUPG_VERSION = "2.5.24"
GNUPG = Download(
    "https://gnupg.org/ftp/gcrypt/binary/gnupg-w32-2.5.24_20260923.exe",
    "ea6f9dee2cccd83287432625b8b399173805add81d27067fcaf019c0c4da1ad8",
)
GNUPG_SOURCE = Download(
    "https://gnupg.org/ftp/gcrypt/gnupg/gnupg-w32-2.5.24_20260923.tar.xz",
    "4d18ae79e3a787ceab011f27c1557f407f6ba45e467d483c01434f0dd5fa115a",
)
INNO_SETUP = Download(
    "https://github.com/jrsoftware/issrc/releases/download/is-7_1_1/innosetup-7.1.1-x64.exe",
    "8a5a6711c3766a6e5fb74f280ba0e3551e719ce94538d901fdbd1f8f9920b3f0",
)

GNUPG_LISTING = "https://gnupg.org/ftp/gcrypt/binary/"

#: Left out of the app's copy of GnuPG: the only parts that reach the network, which this
#: app never needs, and the installer's temporary copies of files.
GNUPG_LEFT_OUT = ("dirmngr*", "gpg-wks-client.exe", "libntbtls-0.dll", "*.tmp")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(download: Download) -> Path:
    """Download a file once, and never use it unless it matches its pinned hash."""
    target = WORK / "downloads" / download.name
    if not (target.is_file() and sha256(target) == download.sha256):
        target.parent.mkdir(parents=True, exist_ok=True)
        print(f"Downloading {download.url}", flush=True)
        # The URLs are the constants above, so they are always https.
        with urllib.request.urlopen(download.url, timeout=120) as response, target.open("wb") as file:  # noqa: S310
            shutil.copyfileobj(response, file)
    actual = sha256(target)
    if actual != download.sha256:
        target.unlink()
        sys.exit(f"{download.name} doesn't match its pinned checksum. Got {actual}.")
    return target


def find_7zip() -> str:
    folders = [Path(os.environ.get(name, "")) / "7-Zip" for name in ("ProgramFiles", "ProgramFiles(x86)")]
    folders += [Path(entry) for entry in os.environ.get("PATH", "").split(os.pathsep)]
    for folder in folders:
        candidate = folder / "7z.exe"
        if folder.is_absolute() and candidate.is_file():
            return str(candidate)
    sys.exit("This build needs 7-Zip, to unpack GnuPG's installer: https://www.7-zip.org/")


def install_gnupg(target: Path) -> None:
    """Copy what the app uses from the official package, whose files keep their own signatures.

    The package is unpacked rather than run, because its installer needs administrator
    rights, and its silent mode hangs on the CI server image.
    """
    package = WORK / "gnupg-package"
    shutil.rmtree(package, ignore_errors=True)
    subprocess.run([find_7zip(), "x", "-y", f"-o{package}", str(fetch(GNUPG))],
                   check=True, stdout=subprocess.DEVNULL)
    shutil.rmtree(target, ignore_errors=True)

    def left_out(_folder: str, names: list[str]) -> list[str]:
        return [name for name in names if any(fnmatch(name, pattern) for pattern in GNUPG_LEFT_OUT)]

    shutil.copytree(package / "bin", target / "bin", ignore=left_out)
    shutil.copytree(package / "share" / "gnupg", target / "share" / "gnupg")
    shutil.copy2(package / "README.txt", target / "README.txt")


def read_gnupg_listing() -> str:
    # The URL is the constant above, so it's always https.
    with urllib.request.urlopen(GNUPG_LISTING, timeout=60) as response:  # noqa: S310
        return response.read().decode("utf-8", errors="replace")


def newest_gnupg_build(listing: str) -> str:
    names = set(re.findall(r"gnupg-w32-\d+\.\d+\.\d+_\d+\.exe", listing))
    if not names:
        sys.exit(f"Found no Windows builds of GnuPG at {GNUPG_LISTING}. Has the page changed?")
    return max(names, key=lambda name: [int(number) for number in re.findall(r"\d+", name)])


def check_gnupg_is_current() -> None:
    newest = newest_gnupg_build(read_gnupg_listing())
    if newest != GNUPG.name:
        sys.exit(f"{newest} is out, but the download still includes {GNUPG.name}. "
                 'Follow "Updating GnuPG" in docs/RELEASE_CHECKLIST.md.')
    print(f"{GNUPG.name} is the newest Windows build of GnuPG.")


def app_version() -> str:
    text = (ROOT / "mindyourownbytes" / "__init__.py").read_text(encoding="utf-8")
    return re.search(r'__version__ = "([^"]+)"', text).group(1)


def add_licenses(version: str) -> None:
    licenses = APP / "licenses"
    licenses.mkdir()
    shutil.copy2(ROOT / "LICENSE", APP / "LICENSE.txt")
    shutil.copy2(Path(sys.base_prefix) / "LICENSE.txt", licenses / "Python.txt")
    bootloader = next(file for file in metadata.files("pyinstaller") if file.name == "COPYING.txt")
    shutil.copy2(bootloader.locate(), licenses / "PyInstaller.txt")
    notices = (PACKAGING / "THIRD-PARTY-NOTICES.txt").read_text(encoding="utf-8")
    qt = metadata.version("pyside6-essentials")
    (APP / "THIRD-PARTY-NOTICES.txt").write_text(
        notices.format(
            version=version,
            gnupg=GNUPG_VERSION,
            gnupg_source=GNUPG_SOURCE.name,
            gnupg_source_url=GNUPG_SOURCE.url,
            qt=qt,
            qt_series=".".join(qt.split(".")[:2]),
            python=platform.python_version(),
            pyinstaller=metadata.version("pyinstaller"),
        ),
        encoding="utf-8",
    )


def build_app(version: str) -> None:
    subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--log-level", "WARN",
         "--distpath", str(APP.parent), "--workpath", str(WORK / "pyinstaller"),
         str(PACKAGING / "mindyourownbytes.spec")],
        check=True,
    )
    install_gnupg(APP / "gnupg")
    add_licenses(version)


def make_portable(base_name: str) -> Path:
    archive = RELEASE / f"{base_name}-portable.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for path in sorted(APP.rglob("*")):
            if path.is_file():
                output.write(path, Path(APP.name) / path.relative_to(APP))
    return archive


def inno_compiler() -> Path:
    folder = WORK / "innosetup"
    compiler = folder / "ISCC.exe"
    if not compiler.is_file():
        print("Unpacking Inno Setup", flush=True)
        # Portable mode writes nothing outside this folder: no Start menu or Apps entry.
        subprocess.run(
            [str(fetch(INNO_SETUP)), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-",
             "/CURRENTUSER", "/NOICONS", "/PORTABLE=1", f"/DIR={folder}"],
            check=True, timeout=300,
        )
    return compiler


def make_installer(version: str, base_name: str) -> Path:
    numeric = ".".join(re.match(r"(\d+)\.(\d+)\.(\d+)", version).groups()) + ".0"
    subprocess.run(
        [str(inno_compiler()), "/Q", f"/DAppVersion={version}", f"/DNumericVersion={numeric}",
         f"/DBaseName={base_name}", f"/DAppFolder={APP}", f"/O{RELEASE}", str(PACKAGING / "installer.iss")],
        check=True,
    )
    return RELEASE / f"{base_name}-setup.exe"


def write_checksums() -> Path:
    checksums = RELEASE / "SHA256SUMS.txt"
    lines = [f"{sha256(path)}  {path.name}\n" for path in sorted(RELEASE.iterdir()) if path != checksums]
    with checksums.open("w", encoding="utf-8", newline="\n") as file:
        file.writelines(lines)
    return checksums


def changelog_section(version: str) -> str:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = rf"^## \[{re.escape(version)}\][^\n]*\n"
    section = re.search(heading + r"(.*?)(?=^## \[|\Z)", changelog, re.MULTILINE | re.DOTALL)
    if section is None:
        sys.exit(f"CHANGELOG.md has no section for {version}.")
    return section.group(1).strip()


def write_release_notes(version: str, setup: Path, portable: Path, checksums: Path) -> Path:
    notes = ROOT / "dist" / "release-notes.md"
    template = (PACKAGING / "release-notes.md").read_text(encoding="utf-8")
    notes.write_text(
        template.format(
            downloads=f"{REPOSITORY}/releases/download/v{version}",
            repository=REPOSITORY,
            setup=setup.name,
            portable=portable.name,
            # Built on their own systems by build_unix.py, which names them the same way.
            linux=f"mindyourownbytes-{version}-linux-x86_64.tar.gz",
            macos=f"mindyourownbytes-{version}-macos-arm64.dmg",
            gnupg=GNUPG_VERSION,
            gnupg_source=GNUPG_SOURCE.name,
            checksums=checksums.read_text(encoding="utf-8").strip(),
            changes=changelog_section(version),
        ),
        encoding="utf-8",
    )
    return notes


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the Windows download.")
    parser.add_argument("--gnupg-only", type=Path, metavar="FOLDER",
                        help="only unpack the GnuPG that ships into FOLDER, and print its bin folder")
    parser.add_argument("--check-gnupg", action="store_true",
                        help="only check that the included GnuPG is the newest official build")
    parser.add_argument("--tag", help="the git tag being released, which must match the app's version")
    args = parser.parse_args()
    if args.check_gnupg:
        check_gnupg_is_current()
        return
    if sys.platform != "win32":
        sys.exit("The Windows download can only be built on Windows.")

    if args.gnupg_only:
        target = args.gnupg_only.resolve()
        install_gnupg(target)
        print(target / "bin")
        return

    version = app_version()
    if args.tag and args.tag != f"v{version}":
        sys.exit(f"The tag {args.tag} doesn't match the app's version, {version}.")
    changelog_section(version)  # Better to find out now than after a long build.
    import signing  # Beside this script. Only needed for a build, so the tests can load this file without it.
    try:
        certificate = signing.windows_signing()
    except signing.SigningError as exc:
        sys.exit(str(exc))
    print(signing.describe(windows=certificate), flush=True)

    shutil.rmtree(APP, ignore_errors=True)
    shutil.rmtree(RELEASE, ignore_errors=True)
    RELEASE.mkdir(parents=True)
    build_app(version)
    if certificate is not None:
        # Before it goes into the zip and the installer, so that both hold the signed program.
        signing.sign_windows([APP / "mindyourownbytes.exe"], certificate)
    base_name = f"mindyourownbytes-{version}-windows-x64"
    portable = make_portable(base_name)
    setup = make_installer(version, base_name)
    if certificate is not None:
        signing.sign_windows([setup], certificate)
    shutil.copy2(fetch(GNUPG_SOURCE), RELEASE / GNUPG_SOURCE.name)
    checksums = write_checksums()
    write_release_notes(version, setup, portable, checksums)
    for path in sorted(RELEASE.iterdir()):
        print(f"{path.stat().st_size / 1048576:7.1f} MB  {path.name}")


if __name__ == "__main__":
    main()
