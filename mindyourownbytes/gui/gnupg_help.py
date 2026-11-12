"""Where to get GnuPG and make a key, in the words that fit the system the app is running on.

Windows has Gpg4win, a Mac has GPG Suite or Homebrew, and Linux has its package manager. Telling
someone on a Mac to install Gpg4win would leave them stuck.
"""

from __future__ import annotations

import sys
from typing import NamedTuple


class GnuPGHelp(NamedTuple):
    #: For the bar that says GnuPG is missing. ``{minimum}`` is the oldest version that works.
    banner: str
    #: The button on that bar, and the page it opens.
    button: str
    url: str
    #: When someone starts a job without GnuPG.
    required: str
    #: When the saved passphrases can't open without GnuPG.
    vault: str
    #: In the list of keys, when there are none.
    no_keys: str
    #: When someone chooses a key but has none.
    make_key: str


_WINDOWS = GnuPGHelp(
    banner="Install Gpg4win (GnuPG {minimum} or newer), then restart this app, or locate gpg.exe yourself.",
    button="Get Gpg4win",
    url="https://gpg4win.org/download.html",
    required="Install Gpg4win (https://gpg4win.org/) and restart this application, "
             "or use Tools > Locate GnuPG to select gpg.exe.",
    vault="Install Gpg4win, or use Tools > Locate GnuPG, then try again.",
    no_keys="No keys found. Create one in Kleopatra, part of Gpg4win.",
    make_key="Create an OpenPGP key in Kleopatra, then refresh the list. Kleopatra comes with Gpg4win "
             "(https://gpg4win.org/).",
)

_MACOS = GnuPGHelp(
    banner="Install GPG Suite, or GnuPG {minimum} or newer from Homebrew with brew install gnupg, then "
           "restart this app, or locate gpg yourself.",
    button="Get GPG Suite",
    url="https://gpgtools.org/",
    required="Install GPG Suite (https://gpgtools.org/), or GnuPG from Homebrew with brew install gnupg, "
             "and restart this application, or use Tools > Locate GnuPG to select gpg.",
    vault="Install GPG Suite, or GnuPG from Homebrew, or use Tools > Locate GnuPG, then try again.",
    no_keys="No keys found. Create one in GPG Keychain, part of GPG Suite.",
    make_key="Create an OpenPGP key in GPG Keychain, then refresh the list. GPG Keychain comes with "
             "GPG Suite (https://gpgtools.org/).",
)

_LINUX = GnuPGHelp(
    banner="Install GnuPG {minimum} or newer with your package manager, such as sudo apt install gnupg, then "
           "restart this app, or locate gpg yourself.",
    button="How to get GnuPG",
    url="https://gnupg.org/download/",
    required="Install GnuPG with your package manager, such as sudo apt install gnupg, and restart this "
             "application, or use Tools > Locate GnuPG to select gpg.",
    vault="Install GnuPG with your package manager, or use Tools > Locate GnuPG, then try again.",
    no_keys="No keys found. Create one with Kleopatra, or gpg --full-generate-key.",
    make_key="Create an OpenPGP key with Kleopatra, or with gpg --full-generate-key in a terminal, then "
             "refresh the list.",
)


def for_this_system(platform: str | None = None) -> GnuPGHelp:
    system = platform or sys.platform
    if system == "win32":
        return _WINDOWS
    return _MACOS if system == "darwin" else _LINUX
