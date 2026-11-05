# mindyourownbytes

**Your files. Your keys. None of their business.**

Cloud providers can store your bytes. They don't need to read them.

**mindyourownbytes** is a local-only Windows desktop utility that encrypts files
*before* you upload them to any cloud provider. Drag in individual files or
folders, create `.gpg` copies using the same GnuPG engine as Kleopatra, and
upload the encrypted exports wherever you choose. To restore, download the
`.gpg` files and decrypt them locally.

> [!CAUTION]
> **Pre-alpha software (0.1.0-alpha.1). Not independently audited.**
> Windows integration, GnuPG Pinentry behavior, and recovery scenarios still
> need broad validation. Test with non-sensitive files first and keep other
> verified backups. Do not rely on this prototype as the only protection for
> confidential or irreplaceable data.

## Why this exists

You shouldn't need to trust a storage provider with readable copies of your
private reports, photos, code, or records. This project gives you a small GUI
for preparing encrypted backups **without a cloud account, API token, browser
extension, telemetry service, or backend**.

It does not replace cloud storage. It puts encryption under your control first.

## What it does

| Feature | Current status |
| --- | --- |
| Drag-and-drop files and folders | Implemented |
| Encrypt files individually to `.gpg` | Implemented |
| Password encryption with AES-256 | Implemented via GnuPG |
| Public-key encryption using Kleopatra-managed keys | Implemented via GnuPG |
| Downloaded `.gpg` file restoration | Implemented |
| Preserve relative directory layout | Implemented |
| Never overwrite existing outputs | Implemented |
| Cloud upload integration | Intentionally not included |
| Windows installer / signed binary | Planned |
| Independent security review | Needed before stable release |

### Encryption and restoration

```text
LOCAL ORIGINALS             LOCAL APP                  YOUR STORAGE
report.pdf           ──▶   GnuPG encrypts  ──▶   report.pdf.gpg
code/main.cpp        ──▶   GnuPG encrypts  ──▶   code/main.cpp.gpg

Downloaded .gpg file ──▶   GnuPG decrypts  ──▶   local restored file
```

The application never automatically uploads, modifies, or deletes an original
file. Only you decide when and where to copy the encrypted exports.

## Install on Windows

Requires:

1. Windows 10/11 (64-bit recommended).
2. [Python 3.10+](https://www.python.org/downloads/).
3. [Gpg4win](https://gpg4win.org/download.html) including Kleopatra and GnuPG.

Then:

1. Download the project ZIP (or clone the repository).
2. Run **`setup_windows.bat`** once. It creates a local `.venv` and installs
   PySide6; internet access is needed for this first dependency install only.
3. Run **`start_windows.bat`** to open the GUI.
4. If the GnuPG engine is not detected, click **Locate GnuPG** and choose
   `gpg.exe` from your Gpg4win installation.

The Python application itself makes **no network calls** during encryption or
restoration.

## Usage

### Encrypt

1. Open the **Encrypt files** screen.
2. Drop files/folders into the window or use **Add files / Add folder**.
3. Select **Password · AES-256** or **OpenPGP public key**.
4. Choose an output folder if desired. Default:
   `%USERPROFILE%\mindyourownbytes\Encrypted Exports`.
5. Click **Encrypt files**. GnuPG's Pinentry dialog will request a passphrase
   when required.
6. Upload only the generated `.gpg` files to your cloud or other backup media.

### Restore

1. Download the encrypted files from your storage provider.
2. Select the **Restore files** screen.
3. Drop `.gpg` or `.pgp` files into the application.
4. Choose a **local-only** destination (not a cloud-synced folder). Default:
   `%USERPROFILE%\mindyourownbytes\Restored Files`.
5. Click **Restore files** and provide the relevant passphrase if asked.
6. Open the restored originals. Existing names are preserved safely by adding
   a numbered suffix rather than overwriting files.

Dragging a folder preserves its relative layout. For example:

```text
Research/QKD/report.pdf     →     Research/QKD/report.pdf.gpg
Research/QKD/plot.png       →     Research/QKD/plot.png.gpg
```

## What it protects—and what it doesn't

- The contents of successfully encrypted files are protected by GnuPG.
- **File and folder names, sizes, timestamps, and the number of files can still
  be visible** in the exported structure.
- Password strength and private-key backup practices are critical. The app does
  not store your passphrase, although GnuPG's agent may cache it temporarily.
- This tool does not protect plaintext while it is open or stored on your own
  computer. It also cannot protect against a compromised local machine.
- Restoring into a synced folder can upload decrypted data to a cloud service.
- OpenPGP public-key encryption is **not automatically quantum-resistant**;
  algorithm and key selection matter.
- It is not an authorized workaround for organizational data-handling policies.

Read the [threat model](docs/THREAT_MODEL.md) and [security policy](SECURITY.md)
before evaluating the utility for sensitive data.

## Develop and test

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python main.py
```

The GUI uses **PySide6**, and the cryptographic operations call an installed
**GnuPG** executable. No custom cryptographic primitive is implemented.

The optional `build_windows_exe.bat` packages a Windows EXE using PyInstaller;
it is not a code-signing or security-audit process. Gpg4win is still required.

## Roadmap and community

- [Roadmap](docs/ROADMAP.md): Windows validation, signing, packaging, metadata
  privacy, and accessibility.
- [Contributing](CONTRIBUTING.md): issues, pull requests, tests, and review.
- [Security](SECURITY.md): please report vulnerabilities privately.
- [Code of Conduct](CODE_OF_CONDUCT.md): respectful community participation.

Use **Issues** for reproducible bugs and concrete feature requests. Use
**Discussions** for questions, ideas, and roadmap proposals once enabled.

## Licensing

A permanent open-source license will be selected before the repository is
made public. While this repository is private and unlicensed, do not assume
permission to redistribute its contents.

Maintained by [Nikolaos Bermparis](https://github.com/N-Bermparis).
