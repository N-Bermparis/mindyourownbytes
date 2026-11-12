"""Check that the Linux or macOS download holds no network code.

    python3 packaging/check_unix_download.py dist/mindyourownbytes          # Linux, once unpacked
    python3 packaging/check_unix_download.py /Applications/mindyourownbytes.app

CI runs this on each finished download, after unpacking or installing it as people do. It needs
only the standard library of Python 3.9 or later, so a test machine's own Python can run it.
check_windows_download.py does the same for the Windows download, among its other checks.
"""

from __future__ import annotations

import os
import sys
from fnmatch import fnmatch
from pathlib import Path

#: The README and the threat model promise that the downloads hold no network code of their own.
#: These are Qt's network library, the plugins and the Kerberos libraries it brings, Python's socket
#: and SSL modules, and OpenSSL, wherever PyInstaller puts them. A folder or a link with such a name
#: counts too.
FORBIDDEN_NAMES = (
    "*Qt*Network*",  # libQt6Network.so.6 on Linux, QtNetwork.framework and its links on a Mac
    "*/plugins/tls/*",
    "*/plugins/networkinformation/*",
    "*/plugins/generic/*tuio*",  # Touch input over UDP.
    "*/plugins/platforms/*vnc*",  # Shows the window to VNC viewers, over the network.
    "*/libgssapi*",
    "*/libkrb5*",
    "*/libk5crypto*",
    "*/_socket.*",
    "*/_ssl.*",
    "*/libssl*",
    "*/libcrypto*",
)
#: Some Pythons compile their network modules into libpython itself, where no file name shows them.
FORBIDDEN_CONTENTS = (b"PyInit__socket", b"PyInit__ssl")
#: Proof that the folder is the app, so that a wrong path can't pass by holding nothing.
EXPECTED_NAMES = ("*Qt*Core*", "*Qt*Widgets*")


def entries(app: Path) -> list[str]:
    """Every file, folder, and link inside, as a path relative to the app. Links aren't followed."""
    found = []
    for folder, folders, files in os.walk(app):
        for name in folders + files:
            found.append((Path(folder) / name).relative_to(app).as_posix())
    return sorted(found)


def problems(app: Path) -> list[str]:
    names = entries(app)
    missing = [pattern for pattern in EXPECTED_NAMES if not any(fnmatch(name, pattern) for name in names)]
    if missing:
        return [f"{app} doesn't look like the app: nothing in it matches {', '.join(missing)}"]
    found = []
    reported = ()
    for name in names:
        # A forbidden folder is reported once, rather than with everything inside it.
        if name.startswith(reported) or not any(fnmatch(name, pattern) for pattern in FORBIDDEN_NAMES):
            continue
        found.append(f"{name} is included")
        reported += (f"{name}/",)
    for name in names:
        path = app / name
        if path.is_symlink() or not path.is_file():
            continue
        content = path.read_bytes()
        found += [f"{name} contains {marker.decode()}" for marker in FORBIDDEN_CONTENTS if marker in content]
    return found


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    app = Path(sys.argv[1])
    if not app.is_dir():
        sys.exit(f"FAILED: {app} isn't a folder")
    found = problems(app)
    for problem in found:
        print(f"FAILED: {problem}", flush=True)
    if found:
        sys.exit(f"FAILED: {app} holds network code, which the downloads promise to leave out")
    print(f"ok: {app} holds no network code", flush=True)


if __name__ == "__main__":
    main()
