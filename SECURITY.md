# Security Policy

## Status

mindyourownbytes is **pre-alpha security software** and has not received an
independent assessment. It should not be the sole backup or confidentiality
measure for critical data. No stable release is currently supported.

## Reporting a vulnerability

Please **do not open a public GitHub Issue** for a suspected vulnerability,
especially if it includes a reproduction technique or sensitive material.

After the repository's **Private vulnerability reporting** feature is enabled,
use GitHub's *Report a vulnerability* workflow under the Security tab. If the
feature is unavailable, contact the maintainer through a trusted private
channel before sharing technical details.

Useful information includes:

- Affected release/commit and operating system.
- GnuPG and Gpg4win versions.
- Steps to reproduce using **synthetic test data only**.
- Expected versus observed behavior and likely security impact.
- Any suggested mitigation.

Please do not send genuine private keys, passphrases, sensitive documents,
or real customer backups. We will acknowledge reports as capacity permits,
investigate, and coordinate disclosure and fixes in good faith. No guaranteed
response time or bug bounty program is currently offered.

## Security boundaries

- All file encryption is performed through the installed GnuPG executable.
- The GUI never intentionally sends data to a cloud provider.
- Local plaintext is outside the application's encrypted-backup guarantee.
- File/folder names and file sizes are exposed unless users change outer
  names or use a future metadata-hiding archive mode.
- Protection depends on passphrase/key quality, local machine security, and
  the GnuPG implementation and its configuration.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for additional details.
