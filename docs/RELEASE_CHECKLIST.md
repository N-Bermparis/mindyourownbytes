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
- [ ] In Tools > Post-quantum keys, create a key and add a part to an older one, answering GnuPG's own
      window, then encrypt and restore with each. Check that a GnuPG older than 2.5 is explained.
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
- [ ] Restore on a second, clean computer, using only your backup of the passphrase or key, by following
      Help > Restore on another computer, once with the app and once with its plain GnuPG commands.
- [ ] Open a file and the vault using plain `gpg`, without this app.
- [ ] Try a wrong passphrase, a missing key, a corrupt file, and Cancel.
- [ ] Encrypt to your own key with **Also sign them with**, answering GnuPG's own window for the key's
      passphrase, and once cancelling it. Restore: the row says **signed by** your name, and the tooltip
      shows your key's full fingerprint. Decrypt the same file with plain `gpg --decrypt`, and check
      that GnuPG reports a good signature.
- [ ] Restore a file encrypted to your key without signing: it says **not signed**. Turn on **Tools >
      Require a signature on files for a key**, and check that the same file is refused, and that a
      passphrase file still restores. Turn it off again.
- [ ] Restore a file signed by someone else's key that you haven't certified: it's flagged as **signed
      with a key you haven't verified**. Certify the key in Kleopatra, and check it then says **signed by**.
- [ ] Choose a new passphrase such as `Password123!`, and check that it's refused with the reason, and
      that a generated one is accepted. Do the same for a new vault master passphrase. Check that a file
      made with a weak passphrase before still restores.
- [ ] Start a large archive restore, and end the app from Task Manager partway through. Start the app
      again, check that it lists the hidden folder it left, and that **Delete** removes it.
- [ ] Restore an archive into a folder that already holds an empty folder of the archive's name, and
      check that the empty folder is still there, and that the archive came out as `Name (2)`.
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
- [ ] In the build logs, each download says either **UNSIGNED** or how it was signed. The release notes,
      `SECURITY.md`, the README, and the threat model must say the same. Their text assumes unsigned
      downloads: update it in the release pull request before the first signed release.

## Setting up signing (prerequisites, not yet done)

Nothing here is configured, so every download is built unsigned, and says so. The workflow only reaches
for any of these on a version tag. Never commit a key, a certificate, or a password, and never paste one
into an issue or a log.

**Windows (Authenticode).** Code-signing keys now have to be kept in hardware: a token, or a cloud
signing service from a CA, which installs a key storage provider that puts the certificate in the
Windows certificate store. Add that provider's own setup step to the **Build for Windows** job, before
the build, as its vendor documents. Then set the repository variables `WINDOWS_SIGN_CERT_SHA1` (the
certificate's thumbprint) and `WINDOWS_SIGN_TIMESTAMP_URL` (the RFC 3161 server your CA names).
`packaging/signing.py` signs the app's program, then the installer, and checks both with
`Get-AuthenticodeSignature`. Inno Setup's uninstaller isn't signed yet: that needs its `SignTool`
setting in `packaging/installer.iss`.

**macOS (Developer ID and notarization).** Set the variable `MAC_SIGN_IDENTITY` to the full
"Developer ID Application: …" name, and the secrets `MAC_DEVELOPER_ID_P12_BASE64` and
`MAC_DEVELOPER_ID_P12_PASSWORD`. To notarize, also create an App Store Connect API key, and set the
variables `MAC_NOTARY_KEY_ID` and `MAC_NOTARY_ISSUER` and the secret `MAC_NOTARY_API_KEY_P8`. Test a
signed build on a Mac before relying on it: Qt or Python may need entitlements under the hardened
runtime, which hasn't been tried yet.

**Release key (OpenPGP signature of `SHA256SUMS.txt`).** Make a dedicated signing key, kept offline
apart from this use. Create a `release-signing` environment that requires a person's approval, with the
secrets `RELEASE_SIGNING_KEY` (the armored private key) and `RELEASE_SIGNING_PASSPHRASE`, and set the
variable `RELEASE_KEY_FINGERPRINT` (40 hex digits, no spaces). Publish the fingerprint in `SECURITY.md`
and through at least one other channel you control, before the first signed release.

After any of these is set up, run the **Downloads** workflow on a test tag, check every signature by
hand on each system as the README describes, then delete the test release and tag.

## Releasing

- [ ] Update the version in `mindyourownbytes/__init__.py`, and the version and date in `CHANGELOG.md`.
- [ ] Merge that, then tag the merged commit and push the tag:

      git tag v1.2.3
      git push origin v1.2.3

  The **Downloads** workflow builds the Windows, Linux, and macOS downloads from the tag, tests each,
  and creates a **draft** pre-release with all their files, checksums, and warnings already in
  place. Nothing is public yet.
- [ ] In the workflow's `check-results-*` artifacts, look at the pictures of the window.
- [ ] Download the installer from the draft onto a clean Windows computer or
      [Windows Sandbox](https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview),
      and go through the warning, the install, an encrypt and restore, and the uninstall.
- [ ] On a Mac with Apple silicon, download the disk image from the draft, go through macOS's warning,
      drag the app into Applications, and encrypt and restore a file with GnuPG from GPG Suite or Homebrew.
- [ ] On a Linux desktop, unpack the archive, run `add-to-menu.sh`, start the app from the menu, and
      encrypt and restore a file.
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
