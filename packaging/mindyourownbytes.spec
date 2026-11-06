# PyInstaller recipe for the Windows app folder. Run it through packaging/build_windows.py.
#
# One folder rather than one file: nothing unpacks to a temp directory at each launch,
# antivirus raises fewer false alarms, and each bundled library stays visible and replaceable.

import re
from fnmatch import fnmatch
from pathlib import Path

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo,
    StringFileInfo,
    StringStruct,
    StringTable,
    VarFileInfo,
    VarStruct,
    VSVersionInfo,
)

ROOT = Path(SPECPATH).parent
PACKAGE = ROOT / "mindyourownbytes"
VERSION = re.search(r'__version__ = "([^"]+)"', (PACKAGE / "__init__.py").read_text(encoding="utf-8")).group(1)
NUMERIC = tuple(int(part) for part in re.match(r"(\d+)\.(\d+)\.(\d+)", VERSION).groups()) + (0,)

# The app opens no network connections, so the download ships no code for them.
EXCLUDED_MODULES = [
    "PySide6.QtNetwork",
    "_hashlib",
    "_socket",
    "_ssl",
    "asyncio",
    "ftplib",
    "http",
    "pdb",
    "pydoc",
    "socket",
    "ssl",
    "tkinter",
    "unittest",
    "urllib.request",
    "xmlrpc",
]

# Paths inside the bundle, as written by PyInstaller. Qt's hooks collect far more than a
# widgets app uses, and each of these was checked by running the app without it.
UNWANTED_FILES = [
    "PySide6/Qt6Network.dll",
    "PySide6/opengl32sw.dll",  # A software OpenGL fallback. Widgets don't draw with OpenGL.
    "PySide6/plugins/generic/*",  # Touch input over UDP.
    "PySide6/plugins/networkinformation/*",
    "PySide6/plugins/platforms/qdirect2d.dll",
    "PySide6/plugins/platforms/qminimal.dll",
    "PySide6/plugins/platforms/qoffscreen.dll",
    "PySide6/plugins/tls/*",
    "PySide6/translations/*",  # The app is in English, and its file dialogs are Windows' own.
    "libcrypto-*",
    "libssl-*",
    # Image decoders for formats the app never opens: its icons are drawn from inline SVG.
    "PySide6/plugins/imageformats/qgif.dll",
    "PySide6/plugins/imageformats/qicns.dll",
    "PySide6/plugins/imageformats/qjpeg.dll",
    "PySide6/plugins/imageformats/qtga.dll",
    "PySide6/plugins/imageformats/qtiff.dll",
    "PySide6/plugins/imageformats/qwbmp.dll",
    "PySide6/plugins/imageformats/qwebp.dll",
]


def wanted(entry) -> bool:
    name = entry[0].replace("\\", "/")
    return not any(fnmatch(name, pattern) for pattern in UNWANTED_FILES)


a = Analysis(
    [str(PACKAGE / "__main__.py")],
    pathex=[str(ROOT)],
    datas=[(str(PACKAGE / "styles.qss"), "mindyourownbytes")],
    excludes=EXCLUDED_MODULES,
)
a.binaries = [entry for entry in a.binaries if wanted(entry)]
a.datas = [entry for entry in a.datas if wanted(entry)]

exe = EXE(
    PYZ(a.pure),
    a.scripts,
    [],
    exclude_binaries=True,
    name="mindyourownbytes",
    console=False,
    upx=False,  # Compressed executables attract antivirus false alarms.
    icon=str(ROOT / "packaging" / "app.ico"),
    # Without this, Task Manager and the file's Properties show no name or version.
    version=VSVersionInfo(
        ffi=FixedFileInfo(filevers=NUMERIC, prodvers=NUMERIC),
        kids=[
            StringFileInfo([StringTable("040904B0", [
                StringStruct("CompanyName", "mindyourownbytes contributors"),
                StringStruct("FileDescription", "mindyourownbytes"),
                StringStruct("FileVersion", VERSION),
                StringStruct("InternalName", "mindyourownbytes"),
                StringStruct("LegalCopyright", "GPL-3.0-or-later"),
                StringStruct("OriginalFilename", "mindyourownbytes.exe"),
                StringStruct("ProductName", "mindyourownbytes"),
                StringStruct("ProductVersion", VERSION),
            ])]),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    ),
)
COLLECT(exe, a.binaries, a.datas, upx=False, name="mindyourownbytes")
