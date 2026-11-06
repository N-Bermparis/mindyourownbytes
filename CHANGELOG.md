# Changelog

All notable changes are documented here. This project uses a lightweight versioning
convention until a stable `1.0.0` release.

## [0.1.0-alpha.1] - Unreleased

First public version. Not independently audited.

### Added

- A guided, plain-language desktop app using native controls, with the system's light or dark mode.
- Drag-and-drop encryption of files and folders to standard OpenPGP `.gpg` files.
- Passphrase encryption (AES-256) and public-key encryption with Kleopatra/GnuPG keys.
- Type one passphrase for a whole batch, instead of one prompt per file.
- Encrypted vault for saved passphrases, with generation and auto-lock. Stored as a plain
  GnuPG file that opens without this application.
- Library screen with collections, search, and moving files between collections.
- Restore that selects how to unlock files, can try every saved passphrase, and retries only what failed.
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

### Changed

- Requires Python 3.12 or newer. On Linux, PySide6 6.12.0 loses a reference to `None` on every
  void Qt call under Python 3.11, which crashes the interpreter during normal use.

### Known limitations

- **File and folder names, and approximate sizes, are visible to your provider.**
- Rollback and swapping of files aren't detected, and public-key files aren't signed.
- Hands-on testing with real Pinentry dialogs on a wider range of systems is still needed.
- The Windows download isn't code-signed yet, so Windows warns about it, and Smart App Control
  blocks it. Its builds aren't reproducible yet either.
- The GnuPG included in the Windows download only updates when the app does.

See the [threat model](docs/THREAT_MODEL.md) for the full list.
