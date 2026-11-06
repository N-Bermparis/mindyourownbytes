# Contributing to mindyourownbytes

Thanks for helping people keep readable copies of their files away from cloud
providers. Code is only one way to help: testing on different setups, translations,
accessibility fixes, documentation, and security review are all just as welcome.

**New here?** Look for [`good first issue`](https://github.com/N-Bermparis/mindyourownbytes/labels/good%20first%20issue),
or try the app and tell us where you got stuck. That feedback is valuable in itself.

## Three rules

1. **Never share real data.** No personal documents, private keys, passphrases, or real
   ciphertext in issues, screenshots, tests, or pull requests.
2. **Report vulnerabilities privately.** See [SECURITY.md](SECURITY.md).
3. **Discuss before changing the cryptography.** Anything touching encryption, the vault
   format, stored data, or new dependencies needs a design discussion first.

## Setting up

You need Python 3.12+ and GnuPG 2.2.8+ ([Gpg4win](https://gpg4win.org/) on Windows).

```bash
python -m venv .venv
.venv\Scripts\activate             # Linux and macOS: source .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt
python -m pip install --require-hashes -r requirements-dev.txt
python -m mindyourownbytes
```

## Running the checks

```bash
python -m unittest discover -s tests -t . -v
python -m ruff check .
```

The tests use a temporary GnuPG home and never touch your real keyring. Without GnuPG,
the cryptography tests are skipped, so if that happens please say so in your pull request.
CI always runs them.

## Where things live

| Path | Purpose |
| --- | --- |
| `mindyourownbytes/core.py` | Finding GnuPG, expanding inputs, encrypting, restoring |
| `mindyourownbytes/vault.py` | The saved passphrase vault |
| `mindyourownbytes/library.py` | Collections and the library scan |
| `mindyourownbytes/gui/` | The PySide6 interface. No cryptography goes here |
| `tests/` | One test file per module, plus real-GnuPG integration tests |
| `docs/THREAT_MODEL.md` | What is and isn't protected. Keep this accurate |

## Pull request checklist

1. Explain the user's problem and how the behaviour changes.
2. Add tests, including failure and recovery cases.
3. If you touch encryption, decryption, paths, or how processes are started, explain the
   security implications and update the threat model.
4. Confirm plaintext can't reach the export folder, and that errors can't overwrite or lose data.
5. Keep dependencies to a minimum and explain any you add. Lock files are generated with
   [`uv pip compile --universal --generate-hashes`](https://docs.astral.sh/uv/pip/compile/),
   from `pyproject.toml` and `requirements-dev.in`.
6. For visible changes, attach Windows screenshots using dummy data only.

Commit messages follow a light convention, for example
`fix: keep incomplete exports out of the backup folder`.

## Design principles

- **Local first.** No accounts, telemetry, or required network access. Ever.
- **Established cryptography only.** GnuPG does the work; we never write our own.
- **No lock-in.** Everything must stay readable with plain `gpg`, with or without this app.
- **No silent data loss.** Never overwrite or delete user files. Tell the user about anything that was skipped.
- **Small attack surface.** No shell invocation, validated paths, and few dependencies.
- **Honest claims.** Document what we don't protect, as clearly as what we do.

## License

This project is licensed under the [GNU General Public License v3.0 or later](LICENSE).
By contributing, you agree that your contributions are licensed the same way, and that
you have the right to submit them. Please also follow our [Code of Conduct](CODE_OF_CONDUCT.md).
