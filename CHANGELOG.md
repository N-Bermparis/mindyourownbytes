# Changelog

All notable changes are documented here. This project uses a lightweight versioning
convention until a stable `1.0.0` release.

## [0.1.0-alpha.1] - Unreleased

First public version. Not independently audited.

### Added

- A guided, plain-language desktop app using native controls, with the system's light or dark mode.
- Simple and advanced modes. New installations start simple, with a passphrase or a saved one,
  AES-256, and the check after encrypting. Tools > Show advanced options adds OpenPGP keys, the
  algorithm, and GnuPG's own prompt. Anyone already using those starts in advanced mode.
- Drag-and-drop encryption of files and folders to standard OpenPGP `.gpg` files.
- Encrypt everything into one archive, an ordinary zip inside one `.zip.gpg` file, which hides the
  names, folders, and number of the files inside. Restoring it gives the folder back.
- **Encrypt with mindyourownbytes** in File Explorer's right-click menu, added by the installer for
  your account only. It adds the files to the list in the open window, and encrypts nothing by itself.
- Passphrase encryption with a choice of AES-256 (the default), Twofish, or Camellia-256, and
  public-key encryption with Kleopatra/GnuPG keys, with each key's type shown in the list.
- Type one passphrase for a whole batch, instead of one prompt per file.
- Generate a passphrase wherever you choose one: seven random words from EFF's Long Wordlist, or 30
  random letters and digits, with its exact strength stated in plain words.
- Each file encrypted with a typed or saved passphrase is decrypted again and compared with its
  original before it's reported as done. A copy that fails is deleted, with the reason shown.
  It's on by default, and can be turned off in the Tools menu.
- Encrypted vault for saved passphrases, with generation and auto-lock. Stored as a plain
  GnuPG file that opens without this application.
- Library screen with collections, search, and moving files between collections.
- "What your provider sees", which shows the same files as you see them and as your cloud provider
  does, with lists of what it can and can't see.
- Restore that selects how to unlock files, can try every saved passphrase, and retries only what failed.
  One batch can mix passphrase files and files for your key, and the Library restores everything shown,
  such as a whole collection, keeping its folders.
- A step-by-step guide to restoring on another computer, under Help, for Windows, macOS, or Linux,
  with or without this app. It can be saved as a text file to keep beside your backups.
- Warnings before restoring into a synced folder, when originals already appear to be in
  one, and before encrypting to a key you can't decrypt with.
- Real-GnuPG test suite, including forged, tampered, and truncated input.
- A Windows installer and portable download with GnuPG included, so there's nothing else to
  install. Both are built by CI, with published checksums, and tested by installing, upgrading,
  and uninstalling for real.

### Security

These issues were found and fixed during the pre-release review, before any public release.

- Restoring accepted unencrypted OpenPGP data as a valid backup, with no key or passphrase.
- A `gpg.exe` planted in the current directory could be executed at startup.
- Passphrases stayed cached in gpg-agent after encrypting, so restoring needed no prompt.
- The S2K iteration count was left to defaults, which could fall back to 65,536. It is now pinned.
- Windows junctions were followed outside the selected folder on Python 3.11 and earlier.
- Revoked and expired keys were offered as encryption targets.
- Keys without a local private key looked the same as your own, risking files you couldn't restore.
- Scrolling the page with the pointer over a dropdown could quietly pick a different key or saved passphrase.

### Changed

- Requires Python 3.12 or newer. On Linux, PySide6 6.12.0 loses a reference to `None` on every
  void Qt call under Python 3.11, which crashes the interpreter during normal use.

### Known limitations

- **File and folder names, and approximate sizes, are visible to your provider**, unless you
  encrypt them into one archive. An archive's own name and size still show.
- Rollback and swapping of files aren't detected, and public-key files aren't signed.
- Files encrypted to an OpenPGP key, or through GnuPG's own passphrase prompt, aren't checked after
  encrypting. Nothing checks that an upload reached your provider intact.
- With `textmode` in `gpg.conf`, GnuPG changes line endings in what it encrypts. The check after
  encrypting refuses such files, but files that aren't checked are affected without any warning.
- Hands-on testing with real Pinentry dialogs on a wider range of systems is still needed.
- The Windows download isn't code-signed yet, so Windows warns about it, and Smart App Control
  blocks it. Its builds aren't reproducible yet either.
- The GnuPG included in the Windows download only updates when the app does.

See the [threat model](docs/THREAT_MODEL.md) for the full list.
