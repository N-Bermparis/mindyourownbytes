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
- A forged or altered file that restores without an error.
- Passphrases reaching a disk, a log, a command line, or a place they shouldn't be.
- Plaintext ending up in the export folder.
- Losing data: overwriting a file, or reporting success when a file wasn't protected.
- Getting this application to run a program other than GnuPG.
- Problems in the Windows download, including a bundled GnuPG with a known vulnerability.
- Weaknesses in the vault's design.

Findings about GnuPG itself should go to the
[GnuPG project](https://gnupg.org/documentation/security.html).

## Known limitations, not vulnerabilities

The [threat model](docs/THREAT_MODEL.md) documents limits we already know about, including
visible file names and sizes, rollback and file swapping without a saved checksum, forged files in
public-key mode, and secrets staying in memory while the vault is unlocked. Ideas for
closing those gaps are very welcome as ordinary issues.
