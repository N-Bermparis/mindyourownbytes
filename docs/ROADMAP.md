# Roadmap

The roadmap is community-driven and intentionally has no guaranteed dates.

## 0.1.x — Prove the basics

- [x] Local GUI and drag-and-drop files/folders
- [x] AES-256 password encryption using GnuPG
- [x] Public-key encryption using local OpenPGP keys
- [x] Restore and output collision protection
- [x] Initial test suite and documentation
- [ ] Validate the complete GUI workflow on Windows 10/11 with Gpg4win 5.x
- [ ] Verify password and private-key recovery on a second computer
- [ ] Expand negative tests and security analysis

## 0.2 — Quality and usability

- [ ] Accessibility and keyboard navigation review
- [ ] File-level verification and clearer diagnostics
- [ ] Optional filename obfuscation / encrypted metadata manifest
- [ ] Safer handling of cloud-synced restore directories
- [ ] Internationalization

## 0.3 — Packaging and trust

- [ ] Windows signed release workflow
- [ ] Reproducible-build and checksum instructions
- [ ] Release compatibility matrix and migration guidance
- [ ] Threat-model review and community security testing

## Ideas for later

- [ ] Encrypted folder archive mode that hides internal filenames
- [ ] Platform-native macOS/Linux front ends
- [ ] Multiple recipients and key selection improvements
- [ ] Optional integrity manifests and periodic restore-test reminders

We intentionally do **not** plan to require an account or upload files to any
specific provider. Open a Discussion to suggest alternatives or priorities.
