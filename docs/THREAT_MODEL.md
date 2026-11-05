# Threat model (draft)

This is a description of the intended security boundaries, not an audit.

## Assets

- Confidential file contents before cloud upload.
- Recoverability of encrypted backups and original files.
- OpenPGP private keys and password-based encryption passphrases.

## Intended threat

An untrusted or curious storage provider—or someone who obtains a copy of the
encrypted cloud backup—should not be able to read the underlying file content
without the necessary decryption secret.

The user encrypts locally, uploads only the resulting `.gpg` files, and later
downloads and decrypts them locally.

## Trust assumptions

1. The user's operating system and local machine are not compromised.
2. The installed GnuPG executable and Gpg4win components are authentic and
   supported; the local keyring and Pinentry are trusted.
3. For password encryption, the user chooses a sufficiently strong passphrase.
4. For public-key encryption, recipients verify keys and protect private keys.
5. The user uploads **ciphertext only**, not readable originals.
6. Recovery destinations are not automatically synchronized to third-party
   cloud services.

## Protections currently implemented

- No cloud credentials, telemetry, uploads, or remote backend.
- `subprocess` argument arrays; no shell command string interpolation.
- GnuPG does the cryptography rather than application-defined ciphers.
- Individual-file processing isolates most failures to one item.
- Unique output names prevent intentional overwrites.
- Temporary ciphertext/output paths are removed after failed operations.
- Symlinks are skipped; user-visible relative paths are constructed from
  dropped files, and the app does not follow linked directories.
- Decryption explicitly chooses an output path instead of trusting an
  embedded ciphertext filename.

## Out of scope / remaining exposure

| Issue | Implication |
| --- | --- |
| Visible filenames and directories | Provider can infer topics/projects from the encrypted path |
| File sizes, count, timestamps | Metadata remains visible |
| Weak password or lost private key | Confidentiality or recoverability can fail |
| Malware/compromised endpoint | Can read local plaintext or steal passphrases |
| Cloud-synced restore destination | Decrypted plaintext may be uploaded |
| Corrupt, truncated, or malicious input | Decryption must fail safely; broad fuzz testing is pending |
| GnuPG or package compromise | Encryption security depends on the installed supply chain |
| Classical OpenPGP recipient keys | No automatic post-quantum resistance |
| No independent audit | Undiscovered vulnerabilities are possible |

## Future hardening

- Independent Windows encryption/decryption interoperability tests.
- Better filename/metadata privacy through archive mode.
- Explicit restore-location cloud-sync detection and warnings.
- Signed Windows releases and reproducible-build documentation.
- Input fuzzing, unusual path testing, Windows filesystem edge cases.
- A documented key-recovery drill and backup verification UX.
