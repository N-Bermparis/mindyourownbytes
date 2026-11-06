# mindyourownbytes

**Your files. Your keys. None of their business.**

Encrypt your files on your own computer, then put them on any cloud you like. No
account, no API keys, no new file format: just standard OpenPGP files that open with
plain GnuPG, with or without this app.

[![CI](https://github.com/N-Bermparis/mindyourownbytes/actions/workflows/ci.yml/badge.svg)](https://github.com/N-Bermparis/mindyourownbytes/actions/workflows/ci.yml)
[![License: GPL v3+](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)](LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange)

![Encrypting a folder with one passphrase, then browsing it in the library](docs/assets/demo.gif)

> [!CAUTION]
> **Alpha software, not independently audited.** Security review is exactly what this
> release is asking for. Please test with non-sensitive files first, keep other verified
> backups, and read [what it does and doesn't protect](#what-it-protects-and-what-it-doesnt).

## Why this exists

Mainstream cloud storage can read what you upload, because the provider holds the keys.
This isn't a secret, and it's right there in the terms:

- [Dropbox's terms](https://www.dropbox.com/terms) say it accesses and scans stored files
  to provide features such as search and previews.
- [Google's terms](https://policies.google.com/terms) describe automated systems analyzing
  content, including while it is stored.
- [Microsoft's Services Agreement](https://www.microsoft.com/en-us/servicesagreement) says
  automated systems and people may review content for things like spam and fraud.
- [Apple holds the keys to iCloud Drive](https://support.apple.com/en-us/102651) unless you
  turn on Advanced Data Protection.

These are mostly about features, abuse, and legal duties rather than someone reading your
tax return for fun. But whatever a company *can* read can also be breached, subpoenaed,
misused by an insider, or fed into next year's product.

The fix is old and simple: encrypt before you upload, so the provider stores only bytes it
can't read. This app makes that a drag and drop.

## What it does

- **Drag in files or folders** and get encrypted `.gpg` copies, with folder structure kept.
  Your originals are never changed, and existing files are never overwritten.
- **One passphrase for a whole batch**, typed once.
- **Save different passphrases** for different kinds of documents, in an optional vault
  encrypted under one master passphrase. It can also generate strong ones.
- **Organize into collections** such as Taxes or Medical, then browse, search, and move files
  in the Library. Collections are plain folders, so they work in Explorer and on any cloud too.
- **Or use OpenPGP keys** you already manage in Kleopatra, including post-quantum Kyber keys
  with GnuPG 2.5 or later.
- **Restore safely.** Forged, tampered, and truncated files are rejected, with nothing written.
- **Works with any storage**, because it never talks to any: Google Drive, OneDrive, Dropbox,
  iCloud, a NAS, or a USB stick. You upload the files yourself.

| Library | Saved passphrases |
| --- | --- |
| ![The library, showing files grouped in collections](docs/assets/screenshot-library.png) | ![The vault, listing saved passphrases by name](docs/assets/screenshot-vault.png) |

No telemetry, no accounts, and no network calls. All cryptography is done by
[GnuPG](https://gnupg.org/): this project does not implement any of its own.

## Getting started

You need [Python 3.12+](https://www.python.org/downloads/) and GnuPG, which on Windows means
[Gpg4win](https://gpg4win.org/download.html).

**Windows**

1. [Download the code](https://github.com/N-Bermparis/mindyourownbytes/archive/refs/heads/main.zip) and unzip it.
2. Run `setup_windows.bat` once. It needs internet access to install the interface library, with
   every package checked against a hash in `requirements.txt`.
3. Run `start_windows.bat`.

**Linux and macOS (experimental)**

```bash
git clone https://github.com/N-Bermparis/mindyourownbytes.git
cd mindyourownbytes
python3 -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements.txt
python -m mindyourownbytes
```

CI runs the tests on Linux, but the app is mainly developed and used on Windows, and it hasn't
been tested on macOS. Reports are very welcome.

## How to use it

**Encrypt**

1. Drop files or folders into the window.
2. Choose how to protect them. *Type once for this batch* is the simplest.
3. Optionally type a collection name, such as `Taxes`.
4. Click **Encrypt files**, and upload what appears in the output folder. By default that's
   `%USERPROFILE%\mindyourownbytes\Encrypted Exports`.

**Restore**

1. Download your `.gpg` files, or select them in the **Library**.
2. Choose how to unlock them, then a folder that no cloud service syncs.
3. Click **Restore files**.

### Which method should I choose?

| Method | Good for | Trade-off |
| --- | --- | --- |
| **Type once for this batch** | Most people | The passphrase passes through this app |
| **GnuPG asks for each file** | Keeping passphrases away from this app | One prompt per file, so slow for folders |
| **Saved passphrase** | Different secrets for different documents | One master passphrase guards them all |
| **OpenPGP public key** | Existing Kleopatra users | You must back up your private key, and forged files aren't detected ([why](docs/THREAT_MODEL.md#tampering)) |

## No lock-in

Your data never depends on this project still existing. With this app gone, plain GnuPG
still works:

```bash
gpg --output report.pdf --decrypt report.pdf.gpg
```

The vault is the same kind of file. This prints every saved passphrase:

```bash
gpg --decrypt "%APPDATA%\mindyourownbytes\vault.gpg"
```

During review, files from both encryption modes were also decrypted byte for byte by
[OpenPGP.js](https://openpgpjs.org/), an entirely separate implementation. For the details on
file formats, see the [threat model](docs/THREAT_MODEL.md#how-the-design-defends-you).

**Back up your passphrases, master passphrase, and private keys somewhere other than the
cloud you're protecting against.** If you lose them, nobody can recover your files. That
is the point, and also the risk.

## What it protects and what it doesn't

**Protected:** the contents of your files, from your cloud provider and from anyone who gets
a copy of your cloud data, as long as your passphrase is strong.

**Not protected:**

- ⚠️ **File and folder names and approximate sizes are visible.** `divorce-settlement.pdf.gpg`
  says plenty by itself. Keep names vague, or use one of the tools below until
  [this gets fixed](docs/ROADMAP.md).
- **Files already in a synced folder.** If your originals live in OneDrive or Dropbox, the provider
  likely has them already. The app warns when it recognizes such a folder.
- **Rollback and swaps.** A provider could serve an old version of a file, or swap two files that
  share a passphrase. Neither is detected.
- **A compromised computer.** Malware can read whatever you can.
- **A weak passphrase.** Use five or more random words, or the Generate button.

The [threat model](docs/THREAT_MODEL.md) has the full picture, including the vault's trade-offs.

## How it compares

Many good tools already exist, so here's an honest comparison.

| | mindyourownbytes | [Cryptomator](https://cryptomator.org/) | [rclone crypt](https://rclone.org/crypt/) | [Kleopatra](https://www.openpgp.org/software/kleopatra/) |
| --- | --- | --- | --- | --- |
| **Interface** | Desktop app | Desktop and mobile apps | Command line | Desktop app |
| **File format** | Standard OpenPGP | Its own documented format | Its own documented format | Standard OpenPGP |
| **Open without the app** | GnuPG or other OpenPGP tools | A compatible tool | rclone or a compatible tool | GnuPG or other OpenPGP tools |
| **Hides file names** | ❌ Not yet | ✅ | ✅ On by default | ❌ |
| **Saved passphrases by purpose** | ✅ | One per vault | Per remote | ❌ |
| **Independent audit** | ❌ Not yet | ✅ [2017](https://community.cryptomator.org/t/has-there-been-a-security-review-audit-of-cryptomator/44) | | |

**Choose this if** you want plain, durable `.gpg` files you can open with anything, without
mounting a vault. **Choose [Cryptomator](https://cryptomator.org/) if** you need hidden file names
or an audited tool today, as it's excellent at both. **Choose rclone crypt if** you're comfortable
on the command line and want automated sync.

## Get involved

This project needs people who care about privacy, and not all of them write code.

- **Review the security.** Try to break it. The [threat model](docs/THREAT_MODEL.md) is a good
  starting point, and vulnerabilities go through [private reporting](SECURITY.md).
- **Test it** on your setup and say what confused you.
- **Pick up an issue.** Start with [`good first issue`](https://github.com/N-Bermparis/mindyourownbytes/labels/good%20first%20issue),
  or take on the big one: [hiding file names](docs/ROADMAP.md).
- **Help with** translations, accessibility, and packaging.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, and the [roadmap](docs/ROADMAP.md) for where this
is going. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[GNU General Public License v3.0 or later](LICENSE). Anyone who distributes a modified version
must publish its source, so nobody can ship a closed copy of a privacy tool that can't be audited.

Maintained by [Nikolaos Bermparis](https://github.com/N-Bermparis). Not affiliated with any cloud
provider, or with the GnuPG project.
