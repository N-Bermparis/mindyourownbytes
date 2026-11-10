"""How to restore your files on another computer, step by step, with or without this app.

The same steps appear in the app (Help > Restore on another computer) and in a plain text file
it can save, so that the instructions can sit beside your backups. They hold no secrets: no
passphrases, keys, file names, or anything else about you.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Platform = Literal["windows", "macos", "linux"]
PLATFORMS: dict[Platform, str] = {"windows": "Windows", "macos": "macOS", "linux": "Linux"}

REPOSITORY_URL = "https://github.com/N-Bermparis/mindyourownbytes"


@dataclass(frozen=True)
class Step:
    title: str
    #: Paragraphs of plain text.
    text: tuple[str, ...]
    #: Commands to type, if any, for this platform.
    commands: tuple[str, ...] = ()


def _install(platform: Platform) -> Step:
    if platform == "windows":
        return Step("Set up the other computer", (
            "Install this app from its releases page. GnuPG, which does all the encryption, comes with it. "
            "If you'd rather not install anything, the portable zip works the same.",
            "Or, without this app, install Gpg4win from gpg4win.org, which includes GnuPG and Kleopatra.",
            f"Releases: {REPOSITORY_URL}/releases",
        ))
    if platform == "macos":
        return Step("Set up the other computer", (
            "Install GnuPG. With Homebrew, type the command below in Terminal. GPG Suite, from gpgtools.org, "
            "is another way. This app can also run from source on macOS, but it hasn't been tested there.",
        ), ("brew install gnupg",))
    return Step("Set up the other computer", (
        "Install GnuPG with your package manager. Many Linux systems already have it. This app can also "
        "run from source on Linux, as its README describes.",
    ), ("sudo apt install gnupg      # Debian and Ubuntu", "sudo dnf install gnupg2     # Fedora"))


def _secret(platform: Platform) -> Step:
    vault = {
        "windows": r"%APPDATA%\mindyourownbytes\vault.gpg",
        "macos": "~/Library/Application Support/mindyourownbytes/vault.gpg",
        "linux": "~/.config/mindyourownbytes/vault.gpg",
    }[platform]
    return Step("Bring the secret that opens them", (
        "With a passphrase you typed, there's nothing to bring. You just need to remember it, or have it "
        "written down.",
        "With saved passphrases, bring a copy of the vault file and remember its master passphrase. "
        f"For this app to find it, put it here: {vault}. Without this app, the second command below shows "
        "every saved passphrase.",
        "With an OpenPGP key, bring the backup of your private key, which Kleopatra exports. Import it with "
        "Kleopatra's Import, or with the first command below. Without it, files encrypted to the key can't "
        "be opened by anyone.",
    ), ("gpg --import my-private-key.asc", "gpg --decrypt vault.gpg"))


def _restore(platform: Platform) -> Step:
    text = (
        "With this app: open Restore, drop the downloaded .gpg files or their folder onto it, and click "
        "Restore. It works out how they were protected, and keeps their folders.",
        "Without this app, GnuPG restores one file with the first command below, and asks for the "
        "passphrase. The second command restores every .gpg file in the current folder and the folders "
        "inside it, next to where each one is.",
    )
    one = "gpg --output report.pdf --decrypt report.pdf.gpg"
    if platform == "windows":
        every = ("Get-ChildItem -Recurse -Filter *.gpg | ForEach-Object { "
                 "gpg --output ($_.FullName -replace '\\.gpg$', '') --decrypt $_.FullName }")
        return Step("Restore the files", (*text, "Type them in PowerShell."), (one, every))
    every = "find . -name '*.gpg' -exec sh -c 'gpg --output \"${1%.gpg}\" --decrypt \"$1\"' _ {} \\;"
    return Step("Restore the files", (*text, "Type them in Terminal."), (one, every))


def _afterwards() -> Step:
    return Step("Afterwards", (
        "Open a few restored files to check them.",
        "Restored files are readable by anyone with access to that computer. Keep them out of folders a "
        "cloud service syncs, unless you mean to upload them unencrypted.",
        "On a computer that isn't yours, delete the restored files when you're done, and remove your "
        "private key if you imported one, with the command below or in Kleopatra.",
    ), ("gpg --delete-secret-keys YOUR-KEY-ID",))


def steps(platform: Platform) -> list[Step]:
    return [
        Step("Gather what you need", (
            "Your encrypted .gpg files, downloaded from wherever you keep them.",
            "The secret that opens them: your passphrase, your saved passphrases and their master "
            "passphrase, or your private key's backup. Nobody can recover these for you, including this app.",
            "A computer you trust. Anything that can read its screen or memory can read your files once "
            "they're open.",
        )),
        _install(platform),
        _secret(platform),
        _restore(platform),
        _afterwards(),
    ]


def as_text(platform: Platform) -> str:
    """The whole guide as plain text, to keep beside your backups."""
    lines = [
        f"How to restore files encrypted with mindyourownbytes, on {PLATFORMS[platform]}",
        "",
        "Your files are standard OpenPGP files, so GnuPG opens them with or without this app.",
        "This guide holds no secrets. Keep it anywhere.",
    ]
    for number, step in enumerate(steps(platform), 1):
        lines += ["", f"{number}. {step.title}", ""]
        lines += [f"   {paragraph}" for paragraph in step.text]
        if step.commands:
            lines += [""] + [f"       {command}" for command in step.commands]
    lines += ["", f"More: {REPOSITORY_URL}", ""]
    return "\n".join(lines)
