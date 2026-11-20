# Contributing to mindyourownbytes

Thanks for helping people keep readable copies of their files away from cloud
providers. Code is only one way to help: testing on different setups, translations,
accessibility fixes, documentation, and security review are all just as welcome.

## Your first contribution

New to open source? You're welcome here, and small, focused changes are the easiest to review.

1. Pick an issue, such as a [`good first issue`](https://github.com/N-Bermparis/mindyourownbytes/labels/good%20first%20issue),
   and say in a comment that you'd like to work on it.
2. Fork the repository, and make a branch for that one change.
3. Make the change, and run the [checks](#running-the-checks).
4. Open a pull request that says what changed and why.

You don't have to write code to help:

- **Test it on another system.** On a Mac, follow [the testing guide](docs/TESTING_MACOS.md).
- **Report what confused you**, from installing to restoring.
- **Improve the instructions**, accessibility, or documentation.
- **Question the security assumptions** in the [threat model](docs/THREAT_MODEL.md).

## Three rules

1. **Never share real data.** No personal documents, private keys, passphrases, or real
   ciphertext in issues, screenshots, tests, or pull requests.
2. **Report vulnerabilities privately.** See [SECURITY.md](SECURITY.md).
3. **Discuss before changing the cryptography.** Anything touching encryption, the vault
   format, stored data, or new dependencies needs a design discussion first.

## Setting up

You need Python 3.12+ and GnuPG 2.2.8+ ([Gpg4win](https://gpg4win.org/) on Windows). For a
Windows download that you can simply run, see the [README](README.md#getting-started).

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

## Building the downloads

You rarely need to: every pull request that could affect the download builds and tests it, and keeps
the result as a workflow artifact. To do it yourself, you need [7-Zip](https://www.7-zip.org/):

```bash
python -m pip install --require-hashes -r requirements.txt -r requirements-build.txt
python packaging/build_windows.py
python packaging/check_windows_download.py
```

The last command really installs, upgrades, and uninstalls the app, so read the top of that file
first. `build_windows_exe.bat` does the first two steps for you.

On Linux or macOS, `python packaging/build_unix.py`, after the same `pip install`, builds that
system's download into the same folder. On Linux, first install the X11 libraries listed in
`.github/workflows/release.yml`, because the download carries a copy of each one the build finds.
A Mac builds with `iconutil` and `hdiutil`, which every Mac has. Neither includes GnuPG, so the app
uses the computer's own. `python packaging/check_unix_download.py dist/mindyourownbytes` (on a Mac,
`dist/mindyourownbytes.app`) then checks it for network code, as CI does. Build with a Python that
keeps its socket and SSL modules in separate files, as CPython does by default. The standalone
Pythons that uv installs, and Ubuntu's own, build them into Python itself, so the check fails.

## Where things live

| Path | Purpose |
| --- | --- |
| `mindyourownbytes/core.py` | Finding GnuPG, expanding inputs, encrypting, restoring |
| `mindyourownbytes/archive.py` | Packing files into one zip, and unpacking it safely |
| `mindyourownbytes/records.py` | Checksums of what was encrypted here, to check downloads against |
| `mindyourownbytes/generator.py` | Random passphrases, from words or characters |
| `mindyourownbytes/eff_large_wordlist.txt` | EFF's word list, exactly as published. Never edit it |
| `mindyourownbytes/vault.py` | The saved passphrase vault |
| `mindyourownbytes/library.py` | Collections and the library scan |
| `mindyourownbytes/recovery.py` | The steps for restoring on another computer |
| `mindyourownbytes/gui/` | The PySide6 interface. No cryptography goes here |
| `mindyourownbytes/styles.qss` | Only what native controls can't do. Colors live in `gui/theme.py` |
| `mindyourownbytes/selftest.py` | The check that the built app runs on itself |
| `packaging/` | The downloads for Windows, Linux, and macOS: their recipes, and the scripts that check them |
| `tests/` | One test file per module, plus real-GnuPG integration tests |
| `docs/THREAT_MODEL.md` | What is and isn't protected. Keep this accurate |
| `docs/index.html` | The project's website, with `site.css` and `site.js`. It loads nothing from anywhere else |

## Pull request checklist

1. Explain the user's problem and how the behaviour changes.
2. Add tests, including failure and recovery cases.
3. If you touch encryption, decryption, paths, or how processes are started, explain the
   security implications and update the threat model.
4. Confirm plaintext can't reach the export folder, and that errors can't overwrite or lose data.
5. Keep dependencies to a minimum and explain any you add. Lock files are generated with
   [`uv pip compile --universal --generate-hashes`](https://docs.astral.sh/uv/pip/compile/),
   from `pyproject.toml`, `requirements-dev.in`, and `requirements-build.in`.
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
- **Native first.** Use the platform's own controls, and write for people who've never heard of OpenPGP.

## License

This project is licensed under the [GNU General Public License v3.0 or later](LICENSE).
By contributing, you agree that your contributions are licensed the same way, and that
you have the right to submit them. Please also follow our [Code of Conduct](CODE_OF_CONDUCT.md).
