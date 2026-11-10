# Roadmap

Community-driven, with no guaranteed dates. Priorities can change, so open a
Discussion if you think something should move up or down.

We do **not** plan to require an account, add telemetry, or upload files to any
specific provider. Those are not missing features; they are the point.

## Now: 0.1 — Earn trust

- [x] Drag-and-drop encryption for files and folders
- [x] Passphrase mode with pinned, verified settings
- [x] Public-key mode with Kleopatra and GnuPG keys
- [x] Restore that rejects forged and tampered files
- [x] Encrypted vault for saved passphrases
- [x] Library with collections, search, and move
- [x] Real-GnuPG test suite on Windows and Linux
- [ ] Hands-on testing on Windows 10 and 11 with real Pinentry
- [ ] Restore on a second, clean computer
- [ ] **Independent review of the GnuPG invocation and vault design**

## Next: 0.2 — Close the biggest privacy gap

- [ ] **Hide file and folder names** (encrypted archive mode or name mapping)
- [ ] Sign-and-encrypt, so public-key restores can detect forged files
- [ ] Optional `--throw-keyids`, to hide the recipient in public-key mode
- [x] Verify each file after encrypting it, wherever the app has the passphrase
- [ ] Verify files encrypted to your own key, without asking for anything extra
- [ ] Encrypt to several recipients, such as yourself and a recovery key
- [ ] Preserve file timestamps and empty folders

## Then: 0.3 — Easier to install and trust

- [x] A Windows installer with GnuPG included, built in CI with published checksums
- [ ] Code-signed Windows releases, so that Windows stops warning about them
- [ ] Reproducible builds
- [ ] Linux and macOS packages (Flatpak, Homebrew)
- [ ] A command-line interface for scripting
- [ ] Copy Mark-of-the-Web onto restored files

## Quality and reach

- [ ] Accessibility and full keyboard navigation
- [ ] Translations
- [ ] Move folder scanning off the UI thread for very large trees
- [ ] Better detection of cloud-synced folders
- [ ] Periodic restore-test reminders
- [ ] Input fuzzing

Items that are good places to start are labelled
[`good first issue`](https://github.com/N-Bermparis/mindyourownbytes/labels/good%20first%20issue).
