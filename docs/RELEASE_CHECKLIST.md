# Release checklist

Each box needs a real check by a person. Record who checked it, and when, in the
release pull request. Passing this list is not a security certification.

## Before the repository first goes public

- [ ] Review the whole git history for secrets, ciphertext, and personal or client data.
- [ ] Confirm every commit uses a no-reply or intended public email address.
- [ ] Enable Issues and Discussions.
- [ ] Enable private vulnerability reporting, then re-read `SECURITY.md`.
- [ ] Add a `main` ruleset requiring a pull request and passing CI, with no force pushes.
- [ ] Add a tag ruleset for `v*` tags that restricts creating, updating, and deleting them to admins
      (see [Protecting and signing tags](#protecting-and-signing-tags)).
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
- [ ] Restore a file and an archive downloaded in a browser, and check that each restored file's
      Properties show the **Unblock** box, as the download's do (Mark-of-the-Web).
- [ ] Save checksums in the Library, import them on a second computer, and restore there.
- [ ] Restore on a second, clean computer, using only your backup of the passphrase or key, by following
      Help > Restore on another computer, once with the app and once with its plain GnuPG commands.
- [ ] Open a file and the vault using plain `gpg`, without this app.
- [ ] Try a wrong passphrase, a missing key, a corrupt file, and Cancel.
- [ ] Encrypt to your own key, and check that **Also sign them with** is ticked without being asked to,
      answering GnuPG's own window for the key's passphrase, and once cancelling it. Restore: the row says
      **signed by** your name, and the tooltip shows your key's full fingerprint. Decrypt the same file with
      plain `gpg --decrypt`, and check that GnuPG reports a good signature.
- [ ] Restore a file encrypted to your key without signing: it's **not restored yet**, and nothing is left
      in the folder. Choose **Restore anyway…**, read the question, answer No, then do it again and answer
      Yes: it's restored and says **not signed**. Under **Tools > Files for your key with no verified
      signature**, choose **Never restore them** and check that the same file is refused with no offer, and
      **Restore them, and say so** to check that it's restored straight away. Check that a passphrase file
      restores with each choice, and that simple mode always asks unless **Never** was chosen.
- [ ] Restore a file signed by someone else's key that you haven't certified: it waits as **signed with a
      key you haven't verified**, and **Restore anyway…** shows that key's full fingerprint, never its
      name. Certify the key in Kleopatra, and check it then restores at once and says **signed by**.
- [ ] Set the restore folder to one inside OneDrive or Dropbox, and check that restoring is refused, with a
      folder on this computer suggested. Turn on **Tools > Allow restoring into synced folders** in advanced
      mode, and check that you're warned and asked instead. In simple mode it's refused again.
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
- [ ] The **Dependency audit** CI job is green. It runs pip-audit, locked by `requirements-audit.txt`, over
      every locked requirements file. To run it by hand:
      `pip install --require-hashes -r requirements-audit.txt`, then
      `pip-audit --strict --disable-pip --require-hashes -r requirements.txt -r requirements-build.txt
      -r requirements-dev.txt -r requirements-audit.txt`.
- [ ] The latest weekly **Fuzz** run is green. A failure prints the seed that repeats it.
- [ ] Read the coverage report from the CI run on Linux (in its summary, and as an artifact), and look at
      what security-sensitive code no test reaches. Coverage measures what runs, not whether it's right.
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

### Protecting and signing tags

A version tag is what the **Downloads** workflow builds and releases from, so who can push one matters
more than any check inside the workflow: whoever can push a tag can also push a commit that changes the
workflow itself.

**Who can push a tag.** Add a tag ruleset (Settings > Rules > Rulesets > New tag ruleset) that targets
`v*` tags, restricts creations, updates, and deletions, and lets only the Repository admin role bypass
it. Rulesets need a public repository, or a paid plan for a private one. With the GitHub CLI, from a
file `release-tags.json`:

    {"name": "Release tags", "target": "tag", "enforcement": "active",
     "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
     "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
     "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]}

    gh api repos/N-Bermparis/mindyourownbytes/rulesets --method POST --input release-tags.json

**Signed tags.** GitHub doesn't require tag signatures itself. A tag made with `git tag -s` lets anyone
check, with `git verify-tag`, that the holder of a maintainer's key chose that commit. To sign tags:

1. Use a key of your own for tags (or the release key), and tell git: `git config user.signingkey
   FINGERPRINT`. Keep its private part off shared machines.
2. Export its public part into `packaging/release-keys.asc` (`gpg --armor --export FINGERPRINT`), and
   commit it through a pull request.
3. Set the repository variable `TAG_SIGNING_FINGERPRINTS` to its full fingerprint: 40 hex digits, no
   spaces. Several keys go one per line. Only admins can change variables.
4. Publish the fingerprint in `SECURITY.md` and through at least one other channel you control.

From then on, the workflow's **Check the tag's signature** job stops a release whose tag isn't signed by
one of those keys, and the draft's notes say which key signed it. Without the variable, the job only
warns. It catches mistakes, such as an unsigned tag, and not an attacker who can push: the ruleset is
what stops them. `gh release create --verify-tag`, in the publishing step, only makes sure the tag
already exists. It checks no signature.

## Releasing

- [ ] Update the version in `mindyourownbytes/__init__.py`, and the version and date in `CHANGELOG.md`.
- [ ] Merge that, then tag the merged commit, signing the tag once signing tags is set up, and push it:

      git tag -s v1.2.3 -m "mindyourownbytes v1.2.3"
      git verify-tag v1.2.3
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
