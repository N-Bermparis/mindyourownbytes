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
- [ ] Have the first release ready to publish, because the README's download link leads to the Releases page.

## Functional checks with real Pinentry, on Windows

- [ ] On a fresh installation, check that the app starts in simple mode, and that More options switches to
      advanced. Upgrade an installation that used a key, and check that it starts in advanced mode.
- [ ] Encrypt and restore with each method: passphrase, GnuPG's own prompt (Tools menu), saved passphrase, key.
- [ ] Encrypt and restore with each algorithm: AES-256, Twofish, Camellia-256.
- [ ] Check what each method reports: "Encrypted and checked" with a typed or saved passphrase, and
      "Encrypted, not checked" with GnuPG's own prompt or a key. Turn the check off in the Tools menu, and on again.
- [ ] Drag and drop files and folders onto the Encrypt and Restore screens.
- [ ] Encrypt a folder into one archive, then restore it, and also decrypt it with plain `gpg` and open
      the zip by double-clicking it in File Explorer.
- [ ] In File Explorer, right-click a file, a folder, and a selection of several files, and choose
      **Encrypt with mindyourownbytes**: once with the app closed and once with it open. Each time,
      one window should show them all. On Windows 11, use **Show more options**.
- [ ] Encrypt, upload manually, download, restore, and compare file hashes. The row should say
      **matches your record**. Then restore a renamed copy, and check that it's flagged.
- [ ] Save checksums in the Library, import them on a second computer, and restore there.
- [ ] Restore on a second, clean computer, using only your backup of the passphrase or key.
- [ ] Open a file and the vault using plain `gpg`, without this app.
- [ ] Try a wrong passphrase, a missing key, a corrupt file, and Cancel.
- [ ] Restore one batch that mixes passphrase files with files for a key that has its own passphrase,
      and restore a whole collection from the Library with nothing selected.
- [ ] Test spaces, Unicode, very long names, and name collisions.
- [ ] Generate a passphrase of each kind when encrypting, in the vault, and for the master passphrase,
      and check that encrypting waits until "I've saved this passphrase" is ticked.
- [ ] Test from an ordinary, non-administrator account.
- [ ] Check keyboard use, and that every screen and dialog is readable in light and dark Windows themes.
- [ ] Open "What your provider sees" from Help, from the Encrypt screen with files listed, and from the
      Library, and check that it shows those files both ways.

## Safety and packaging

- [ ] Re-read the threat model against the code, and update whatever has changed.
- [ ] `pip-audit -r requirements.txt` reports nothing unexplained.
- [ ] CI is green on every platform, with no skipped GnuPG tests.
- [ ] The included GnuPG is the newest release (see [Updating GnuPG](#updating-gnupg)).
- [ ] Do not present unsigned binaries as verified.

## Releasing

- [ ] Update the version in `mindyourownbytes/__init__.py`, and the version and date in `CHANGELOG.md`.
- [ ] Merge that, then tag the merged commit and push the tag:

      git tag v1.2.3
      git push origin v1.2.3

  The **Windows download** workflow builds from the tag, tests the result, and creates a **draft**
  pre-release with the files, checksums, and warnings already in place. Nothing is public yet.
- [ ] In the workflow's `check-results-*` artifacts, look at the pictures of the window.
- [ ] Download the installer from the draft onto a clean Windows computer or
      [Windows Sandbox](https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview),
      and go through the warning, the install, an encrypt and restore, and the uninstall.
- [ ] Check the files with an antivirus scanner. Report any false alarm before publishing, because
      new unsigned downloads attract them.
- [ ] Read the draft's notes, then publish it. Keep it marked as a pre-release until an independent
      review has happened.
- [ ] On the first release after the repository goes public, confirm that the workflow's attestation step
      ran, and that `gh attestation verify FILE --repo N-Bermparis/mindyourownbytes` works. It can't run
      on a private repository.
- [ ] Do not describe the project as audited or production-ready unless that has been established.

## Updating GnuPG

The Windows download includes GnuPG, so **a security fix in GnuPG means a new release of this app**.
Follow the [gnupg-announce](https://lists.gnupg.org/mailman/listinfo/gnupg-announce) list, and release
promptly when a fix matters to how this app uses GnuPG. As a backstop, the **GnuPG update check** workflow
runs weekly, and fails as soon as there's a newer official build.

1. Find the new Windows installer and its source package on the
   [GnuPG download page](https://gnupg.org/download/).
2. Download both, with their `.sig` files, and verify them with the release keys from a copy of
   GnuPG you already trust. Also compare the installer with the
   [published checksums](https://gnupg.org/download/integrity_check.html):

       gpgv --keyring "C:\Program Files\GnuPG\share\gnupg\distsigkey.gpg" FILE.sig FILE

3. Update `GNUPG_VERSION`, `GNUPG`, and `GNUPG_SOURCE` in `packaging/build_windows.py`.
4. Open a pull request. CI runs the whole test suite against the new version, and checks the
   download built with it, including that every file still carries g10 Code's signature.
