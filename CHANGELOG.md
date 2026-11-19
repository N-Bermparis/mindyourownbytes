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
  names, folders, and number of the files inside. Restoring it gives the folder back. Names that
  would clash inside it, such as a file and a folder both called `docs`, are numbered instead.
- **Encrypt with mindyourownbytes** in File Explorer's right-click menu, added by the installer for
  your account only. It adds the files to the list in the open window, and encrypts nothing by itself.
- Passphrase encryption with a choice of AES-256 (the default), Twofish, or Camellia-256, and
  public-key encryption with Kleopatra/GnuPG keys, with each key's type shown in the list.
- Type one passphrase for a whole batch, instead of one prompt per file.
- A post-quantum assistant, under Tools, which checks whether GnuPG can make post-quantum keys,
  explains who can open files encrypted to them, and can create one or add a post-quantum part to
  a key of yours. GnuPG asks for any passphrase itself.
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
- A checksum of each encrypted file, saved on your computer, so that restoring flags a download that
  is an older version or a swapped file, even between collections, and asks before decrypting it.
  Checksums can be saved as a `SHA256SUMS` list and imported on another computer.
- A step-by-step guide to restoring on another computer, under Help, for Windows, macOS, or Linux,
  with or without this app. It can be saved as a text file to keep beside your backups.
- Restoring into a folder that looks synced, such as one inside OneDrive or Dropbox, is refused, with a
  folder on this computer suggested, because restored files are readable. In advanced mode, **Tools >
  Allow restoring into synced folders** warns and asks instead. A link into a synced folder counts too.
- Warnings when originals already appear to be in a synced folder, and before encrypting to a key you
  can't decrypt with.
- Real-GnuPG test suite, including forged, tampered, and truncated input.
- A Windows installer and portable download with GnuPG included, so there's nothing else to
  install. Both are built by CI, with published checksums, and tested by installing, upgrading,
  and uninstalling for real.
- Downloads for macOS, for Apple silicon, and for Linux, for 64-bit Intel and AMD processors, built
  and tested by CI like the Windows one. They use the computer's own GnuPG, from GPG Suite,
  Homebrew, or the package manager, and the app says how to get it when it can't find it.
- Sign-and-encrypt: when encrypting to a key, **Also sign them with** adds a standard OpenPGP signature
  with a key of yours. It's ticked whenever you have a key that can sign, unless you've unticked it.
  GnuPG asks for its passphrase itself.
- Every restored file for a key says who made it, as far as signatures can tell: signed by a key you've
  verified, signed with a key you haven't verified, revoked, or expired, or not signed, with the full
  fingerprint in its tooltip. The finished restore sums this up.
- A file for your key that no key you've verified signed isn't restored without asking, because anyone
  who has your public key could have made it. It's decrypted, deleted again, and listed as **not
  restored yet**. **Restore anyway…** shows what each one showed, with any signing key's fingerprint,
  and restores it only if it still shows exactly that when decrypted again. **Tools > Files for your key
  with no verified signature** can instead never restore them, or, in advanced mode, restore them and
  say so, for backups made before signing existed. Passphrase files are never affected.
- New passphrases are checked on your computer: common ones, common ones dressed up, single words,
  two words, runs of keys, repeats, and digit strings are refused for new files and new vault master
  passphrases, with the reason. Anything typed to open something is never judged.
- After an interrupted restore, the next start lists exactly where readable data was left, and offers
  to delete what it can prove it made. **Tools > Clean up after an interrupted restore** does the same.
- Optional code signing in the release workflow (Authenticode, Developer ID with notarization) and an
  OpenPGP signature for the checksum list, ready for when the keys exist. Every signature is verified
  before a release can be drafted. None is configured yet, so the downloads are still unsigned.
- CI also runs the tests on macOS. Windows runs them against the included GnuPG 2.5, Linux against 2.4.
- CI checks every locked dependency file with pip-audit, reports test coverage, and a weekly workflow
  fuzzes the code that reads archive names, zip files, checksum and record files, GnuPG's status
  reports, and passphrases, with a new seed each time, printed so that a failure can be repeated.
- A release can require its tag to be signed by a listed key, once that's set up, and its notes then
  say which key signed it. Setting that up, and protecting version tags, is in the release checklist.

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
- With `textmode` in `gpg.conf`, GnuPG changed line endings in what it encrypted. The check after
  encrypting refused such files, but files for a key, which aren't checked, came back different,
  and archives for a key came back damaged, without a warning. Every GnuPG call now turns
  `textmode` off.
- On Linux and macOS, restoring an archive replaced an existing **empty folder** of the same name,
  including one created by another program between the name being chosen and used, because
  `os.rename` replaces empty folders there. Folders and files are now published with
  `renameat2(RENAME_NOREPLACE)` on Linux, `renamex_np(RENAME_EXCL)` on macOS, and a rename without
  replacing on Windows, which refuse anything already there. A name taken meanwhile is skipped for
  the next free one, and a drive that can't refuse a taken name now fails with an explanation.
- On Linux and macOS, a drive without hard links got the finished file by creating its final name and
  copying into it, so a partial file could be seen, and kept by a crash, under the final name. That
  copy is gone: files get their name in one atomic step, or not at all, after being written to the drive.
- Decrypted data during a restore was written beside the destination with the default permissions,
  and a crash could leave it with no way to find it again. It now waits in a private workspace (mode
  0700 on Linux and macOS), noted in the app's own folder, so that leftovers are found and offered for
  deletion at the next start. Only folders the app can prove it made are ever deleted.
- A line of deeply nested brackets in the record of checksums stopped every restore with an error,
  instead of being skipped like any other damaged line. Found by the new fuzz tests.
- GnuPG opened each original by its name, so a file swapped, after it was chosen, for a link to another
  file, for another file, or reached through a folder swapped for a link elsewhere, was encrypted in its
  place, and passed the check after encrypting. Each original is now opened once, never through a link,
  checked to be the file that was chosen, and given to GnuPG over a pipe from that open file. Archives
  are packed the same way. A copy is only kept if the name still leads to the file that was read.

### Changed

- Requires Python 3.12 or newer. On Linux, PySide6 6.12.0 loses a reference to `None` on every
  void Qt call under Python 3.11, which crashes the interpreter during normal use.

### Known limitations

- **File and folder names, and approximate sizes, are visible to your provider**, unless you
  encrypt them into one archive. An archive's own name and size still show.
- Rollback and swapping of files are only flagged for files with a saved checksum. Files for a key
  only show who made them if they were signed, and files encrypted before signing existed weren't, so
  restoring those asks first.
- Synced folders are recognized by name and by OneDrive's own settings, so a synced folder with an
  unusual name can still go unnoticed.
- Files encrypted to an OpenPGP key, or through GnuPG's own passphrase prompt, aren't checked after
  encrypting. Nothing checks that an upload reached your provider intact.
- A crash during a restore leaves decrypted data in a hidden folder until the app next starts, and
  deleting it isn't secure erasure. Drives that can't refuse a taken name, such as some network shares,
  can't be used as a destination.
- Hands-on testing with real Pinentry dialogs on a wider range of systems is still needed.
- The downloads aren't code-signed yet, so Windows and macOS warn about them, and Smart App
  Control blocks the Windows one. Their builds aren't reproducible yet either.
- The GnuPG included in the Windows download only updates when the app does.

See the [threat model](docs/THREAT_MODEL.md) for the full list.
