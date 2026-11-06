# Release checklist

Each box needs a real check by a person. Record who checked it, and when, in the
release pull request. Passing this list is not a security certification.

## Before the repository first goes public

- [ ] Review the whole git history for secrets, ciphertext, and personal or client data.
- [ ] Confirm every commit uses a no-reply or intended public email address.
- [ ] Enable Issues and Discussions.
- [ ] Enable private vulnerability reporting, then re-read `SECURITY.md`.
- [ ] Add a `main` ruleset requiring a pull request and passing CI, with no force pushes.
- [ ] Enable secret scanning, push protection, and Dependabot alerts.
- [ ] Upload `docs/assets/social-preview.png` as the social preview (Settings → General → Social preview).

## Functional checks with real Pinentry, on Windows

- [ ] Encrypt and restore with each method: passphrase, GnuPG's own prompt (Tools menu), saved passphrase, key.
- [ ] Drag and drop files and folders onto the Encrypt and Restore screens.
- [ ] Encrypt, upload manually, download, restore, and compare file hashes.
- [ ] Restore on a second, clean computer, using only your backup of the passphrase or key.
- [ ] Open a file and the vault using plain `gpg`, without this app.
- [ ] Try a wrong passphrase, a missing key, a corrupt file, and Cancel.
- [ ] Test spaces, Unicode, very long names, and name collisions.
- [ ] Test from an ordinary, non-administrator account.
- [ ] Check keyboard use, and that every screen and dialog is readable in light and dark Windows themes.

## Safety and packaging

- [ ] Re-read the threat model against the code, and update whatever has changed.
- [ ] `pip-audit -r requirements.txt` reports nothing unexplained.
- [ ] CI is green on every platform, with no skipped GnuPG tests.
- [ ] Publish checksums for any binaries, and build them in CI from a tagged commit.
- [ ] Do not present unsigned binaries as verified.
- [ ] State "alpha" and "not independently audited" prominently in the release notes.

## Releasing

- [ ] Update the version in `mindyourownbytes/__init__.py` and in `CHANGELOG.md`.
- [ ] Tag the release and mark it as a pre-release until an independent review has happened.
- [ ] Do not describe the project as audited or production-ready unless that has been established.
