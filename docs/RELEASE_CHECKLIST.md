# Private-to-public release checklist

Do not treat this as an automated certification. Each box requires a real
check and the reviewer/date should be recorded in the release PR.

## Repository governance

- [ ] Choose and add an explicit open-source `LICENSE` file.
- [ ] Confirm the repository description, owner, visibility, and topics.
- [ ] Enable Issues and Discussions.
- [ ] Enable private vulnerability reporting and review `SECURITY.md`.
- [ ] Enable branch rules requiring review and CI checks on `main`.
- [ ] Inspect history for accidentally committed secrets, ciphertext, or
      personal/client data before making the repository public.

## Functional validation

- [ ] Test both encryption modes on Windows with real Gpg4win/Pinentry.
- [ ] Encrypt, upload manually, download, decrypt, and compare file hashes.
- [ ] Restore files to a fresh second machine.
- [ ] Test invalid passwords, missing keys, corrupt ciphertext, and cancel.
- [ ] Test files/folders with spaces, Unicode, long names, and collisions.
- [ ] Test on an ordinary user account (non-admin).

## Safety and packaging

- [ ] Review the threat model against implementation.
- [ ] Check dependency and code-security warnings.
- [ ] Confirm no credentials, filenames from private projects, or test secrets
      exist in release source/assets.
- [ ] Audit any binaries and their build provenance; never distribute unsigned
      binaries as if they were independently verified.
- [ ] Display prominent alpha/audit disclaimers in release notes.
- [ ] Release checksums and installation/recovery instructions.

## Launch

- [ ] Switch repository visibility to Public only after explicit owner approval.
- [ ] Publish a pre-release with known limitations, not a stable 1.0 label.
- [ ] Start an introductory Discussion explaining the project and asking for
      safe feature feedback (without posting real sensitive data).
