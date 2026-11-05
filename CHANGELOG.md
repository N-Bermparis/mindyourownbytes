# Changelog

All notable changes will be documented here. This project uses a lightweight
versioning convention until a stable `1.0.0` release.

## [0.1.0-alpha.1] - Unreleased

### Added

- Local-only desktop interface with file and folder drag-and-drop.
- Individual `.gpg` exports with AES-256 password-based encryption.
- Optional encryption to an OpenPGP public key managed by GnuPG/Kleopatra.
- Restore workflow for downloaded `.gpg`/`.pgp` files.
- Configurable export and restore directories.
- Per-file status, cancellation, and collision-safe output names.
- Basic unit tests and community documentation.

### Known limitations

- Native Windows GUI and complete GnuPG/Pinentry recovery are awaiting broader
  independent testing.
- Filenames and folder paths remain visible in the exported tree.
- Individual files only; no encrypted multi-file archive or metadata vault.
- No automatic cloud integration, by design.
- No signed or reproducible installer yet.
