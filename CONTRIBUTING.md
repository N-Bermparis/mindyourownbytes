# Contributing to mindyourownbytes

Thanks for helping people keep readable copies of their files off cloud
providers. Contributions of code, testing, translations, accessibility, and
documentation are welcome.

## Before opening a contribution

- Search existing Issues and Discussions to avoid duplication.
- For small fixes, open a pull request with a clear explanation.
- For major changes to cryptographic behavior, storage layout, dependencies,
  or the threat model, open a design discussion **before** implementation.
- **Never include personal documents, private keys, credentials, passwords, or
  genuine sensitive ciphertext in issues, screenshots, tests, or PRs.**
- Do not post exploit details publicly. See [SECURITY.md](SECURITY.md).

## Local development

Requirements: Python 3.10+, PySide6, and GnuPG/Gpg4win.

```bash
python -m venv .venv
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python main.py
```

On Windows, activate your environment first (or run the provided `.bat`
scripts). If GnuPG is not available on the testing machine, the integration
test may skip; note this explicitly in your PR.

## Pull request checklist

1. Explain the user problem and the behavior change.
2. Add or update tests, including failure and recovery cases.
3. If the change touches encryption, decryption, paths, or process invocation,
   explain the security implications and update the threat model.
4. Confirm plaintext is never unexpectedly exported to the encrypted folder.
5. Confirm errors do not overwrite prior backups or leave misleading outputs.
6. Keep new dependencies minimal and document why each is needed.
7. Include Windows screenshots for visible GUI changes, with only dummy data.

Please use descriptive commit messages (e.g. `fix: keep incomplete exports
out of backup folder`). This project uses reviewable feature branches and
pull requests, not direct pushes to the protected `main` branch once CI rules
are enabled.

## Design philosophy

- **Local first:** no service account, telemetry, or mandatory network access.
- **Established cryptography:** use GnuPG; do not implement custom ciphers.
- **No silent data loss:** never delete or overwrite user content by default.
- **Small attack surface:** validate paths, avoid shell invocation, and ask
  for explicit permission before changing backup locations or behavior.
- **Honest security claims:** document metadata leakage, unsupported cases,
  and things we have not independently verified.

By contributing, you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).
