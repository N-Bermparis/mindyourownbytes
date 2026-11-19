# Security policy

## Status

mindyourownbytes is **alpha software and has not been independently audited**. Please
don't rely on it as the only protection, or the only copy, of anything critical. There
is no stable release yet, so only the latest release and the latest commit on `main` are supported.

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability.

Use **[Report a vulnerability](https://github.com/N-Bermparis/mindyourownbytes/security/advisories/new)**
on the Security tab. This reaches the maintainer privately through GitHub, with no email
address needed.

Please include:

- The commit or version, your operating system, and your GnuPG or Gpg4win version.
- Steps to reproduce, using **synthetic test data only**.
- What you expected, what happened, and the likely impact.
- Any suggested fix.

**Never send real private keys, passphrases, personal documents, or real backups.**

This is a small volunteer project, with no guaranteed response time and no bug bounty.
Reports will be read, investigated, and fixed in good faith, and you'll be credited in
the advisory unless you prefer otherwise. Please allow reasonable time for a fix before
disclosing publicly.

## What is especially useful to report

- Any way to read file contents without the passphrase or key.
- A forged or altered file that restores without an error, or a signature reported as valid, or as
  made by a key you've verified, when it isn't.
- Passphrases reaching a disk, a log, a command line, or a place they shouldn't be.
- Plaintext ending up in the export folder, or decrypted data left behind after a restore without the
  app offering to delete it.
- Losing data: replacing or overwriting anything, even an empty folder, showing a partial file under
  its final name, or reporting success when a file wasn't protected.
- Getting this application to run a program other than GnuPG.
- Problems in the Windows download, including a bundled GnuPG with a known vulnerability.
- Weaknesses in the vault's design.

Findings about GnuPG itself should go to the
[GnuPG project](https://gnupg.org/documentation/security.html).

## Known limitations, not vulnerabilities

The [threat model](docs/THREAT_MODEL.md) documents limits we already know about, including
visible file names and sizes, rollback and file swapping without a saved checksum, forged files in
public-key mode when they aren't signed, decrypted data that a crash leaves until the next start,
drives that can't publish without risking a replacement, and secrets staying in memory while the
vault is unlocked. Ideas for closing those gaps are very welcome as ordinary issues.

## Verifying a download

What can be checked today, and what can't yet:

- **Checksums**: every release lists the SHA-256 of each file. A match shows that your file is the
  one on the release page. It can't help if the GitHub account itself were compromised.
- **Build attestations**: once the repository is public, `gh attestation verify FILE --repo
  N-Bermparis/mindyourownbytes` ties a file to the workflow run and commit that built it.
- **Code signatures**: none yet. The downloads are **not** code-signed, so Windows and macOS warn
  about them. The release workflow is ready to sign once a certificate and a Developer ID exist.
- **Release key**: none yet. When one exists, its full fingerprint will be published here, and a
  release may then include `SHA256SUMS.txt.asc`. Check it against the fingerprint given here, never
  against one found beside the download.
- **Signed tags**: none yet. Once the maintainer's tag-signing key is listed here, each version tag
  will be signed, and `git verify-tag v1.2.3` in a copy of the repository checks it, after you import
  that key and compare its fingerprint with this page. The release workflow then refuses a tag that
  isn't signed by it. A tag signature says which commit the maintainer chose. It says nothing about
  the downloads, which only code signatures and the release key cover.

Treat any claim that a download is signed, made anywhere else, with suspicion until this section says so.
