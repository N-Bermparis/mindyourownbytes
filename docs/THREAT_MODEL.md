# Threat model

This describes what mindyourownbytes is designed to protect against and what it
is not. It is a design document, **not an audit**. No independent party has
reviewed this software. If you find a gap, please see [SECURITY.md](../SECURITY.md).

## What is being protected

- The contents of your files, before and after they reach a cloud provider.
- Your ability to get those files back, including without this application.
- The passphrases and private keys that protect them.

## The adversaries

| Adversary | Can do | Designed to stop them? |
| --- | --- | --- |
| **Curious provider or employee** reads what you stored | Read every byte and all metadata | **Yes** for contents. **No** for names and sizes (see below) |
| **Attacker with a leaked copy** of your cloud data | Same, offline, indefinitely | **Yes** for contents, if your passphrase is strong |
| **Active provider** alters what it serves you | Replace, corrupt, or remove files; serve old versions | **Partly** (see "Tampering") |
| **Someone at your unlocked computer** | Use anything you have open | **Partly** (auto-lock, no agent cache) |
| **Malware on your computer** | Everything you can do | **No.** Nothing here can defend against this |

## Trust assumptions

1. Your operating system and computer are not compromised.
2. The GnuPG in use is authentic, whether you installed it or it came with the Windows
   download. Everything rests on it.
3. Your passphrases are strong, and you can find them again.
4. For public-key mode, you protect and back up your private key.
5. You upload only `.gpg` files, never originals.
6. You restore to a folder no cloud service synchronizes.

## How the design defends you

**Cryptography is GnuPG's job.** This project implements no cipher, KDF, or file
format, and a test confirms that plain `gpg` can decrypt its output with no help from
this application. During review, files from both encryption modes were also decrypted
byte for byte by OpenPGP.js 6.3.2, an independent implementation.

The two modes differ in format. Passphrase mode produces the long-established RFC 4880
format (AES-256 by default, with an MDC integrity check), which is the most widely readable. Public-key
mode uses whatever the recipient's key asks for. With keys made by GnuPG 2.4 or later,
that is a newer OCB packet, which GnuPG older than 2.3 and some other tools cannot read.

**Explicit, verified encryption settings.** Passphrase mode pins these options
rather than relying on defaults:

```text
--symmetric --cipher-algo AES256    (or TWOFISH or CAMELLIA256, if chosen)
--s2k-mode 3 --s2k-digest-algo SHA512 --s2k-count 65011712
```

GnuPG's defaults are not safe to rely on here. During review, the same command
produced 37,748,736 S2K iterations with one GnuPG build and only **65,536** with
another, because the fallback applies whenever gpg-agent can't be reached.

**A short list of algorithms.** Passphrase mode offers AES-256, which is the default, Twofish, and
Camellia-256. All have 256-bit keys and 128-bit blocks, and get the same key derivation, format, and
integrity check. This is about preference and policy rather than extra protection: there's no known
practical attack on any of them, and the real weak point is the passphrase.

The list is fixed in the code, so a setting can't add to it, and the app only shows what the GnuPG in
use says it supports. IDEA, 3DES, CAST5, and Blowfish are left out because their 64-bit blocks are too
small: [RFC 9580](https://www.rfc-editor.org/rfc/rfc9580#section-9.3) forbids encrypting with the first
three, and GnuPG 2.5 refuses all four by default. Smaller AES and Camellia keys are left out because
they bring no benefit, and leave less margin against quantum computers.

The real cost of choosing is compatibility. RFC 9580 asks every implementation to support AES-256, but
the other two are optional. During review, OpenPGP.js 6.3.2 opened AES-256 and Twofish files, but failed
on Camellia-256 with a misleading "session key decryption failed" error. GnuPG opened all three. The
vault always uses AES-256. Public-key mode leaves the choice to the recipient's key, because forcing
another could leave the recipient unable to open the file.

**Restores must prove decryption happened.** `gpg --decrypt` exits successfully on
OpenPGP data that was never encrypted, without asking for a key or passphrase.
Trusting the exit code would let anyone who controls your storage replace a backup
with content of their choosing, and it would restore as if nothing had happened. The
app requires GnuPG's `DECRYPTION_OKAY` status and rejects anything without it. The
vault applies the same check when it loads.

**Nothing lingers in gpg-agent.** Every call uses `--no-symkey-cache`. Without it,
encrypting a file leaves the passphrase cached, so anyone at the keyboard could
decrypt the file with no prompt for as long as the cache lasts.

**Passphrases never appear on a command line.** Command lines are visible to other
local processes. Passphrases reach GnuPG through Pinentry or a stdin pipe.

**GnuPG is located safely.** The current directory is never searched, and standard
install locations are checked first, then the copy inside the Windows download, then
PATH. A `gpg.exe` planted in a folder such as Downloads will not be executed.

**Failures stay contained.** Files are staged under a temporary name and published
only after success, without overwriting anything. A failed file leaves nothing behind
and doesn't stop the rest of the batch. Links and junctions are never followed, and
folders that can't be read are reported rather than silently left out.

**Each new file is checked before it counts.** People may delete an original once its copy is
reported as encrypted, so that report has to be true. Whenever the app has the passphrase (typed
once for a batch, or saved), GnuPG decrypts each new file again while it still has its temporary
name. The passphrase goes over a pipe, as it does for encrypting. The decrypted bytes come back over
another pipe, are hashed with SHA-256 a piece at a time, and are never written to disk. The file gets
its final name only if GnuPG exits without an error, reports `DECRYPTION_OKAY`, and the hash equals a
hash of the original, which is read last. Otherwise the file is deleted, that row fails with the
reason, and the rest of the batch carries on. If the original changed while this was happening, the
app says so, rather than calling anything damaged.

During review this caught a real case. With `textmode` in `gpg.conf`, GnuPG encrypts and decrypts
without complaint, but the file that comes back has different line endings.

What a passed check shows: at that moment, on this computer, with this GnuPG and the passphrase the
app was given, the file decrypts to exactly the bytes of the original. What it can't show:

- **That an upload reached your provider intact**, or that a file stays intact afterwards. The check
  happens once, before the file leaves your computer.
- **That the passphrase is the one you meant.** The same passphrase is used both ways, so a typing
  mistake made in both boxes still passes.
- **Anything about files it doesn't check.** That's every file encrypted to an OpenPGP key, or
  through "Let GnuPG ask for each passphrase", because checking those would mean asking you again.
  They're marked "Encrypted, not checked". It's also every file if you turn the check off in the
  Tools menu.
- **That another OpenPGP tool can open the file.** Only the GnuPG in use is asked.
- **That GnuPG is honest.** The same program encrypts and decrypts, so this adds nothing against a
  GnuPG that has been tampered with.
- **A change to the original after its check.** The copy holds the file as it was then.

The check costs time, because each file is decrypted once more and its passphrase is stretched once
more. Measured on one computer with the Windows download's own hashing: one 256 MB file took 9.3
seconds in place of 6.5, and 200 files of 4 KB took 56 seconds in place of 34.

Two smaller limits: the decrypted bytes pass through this app's memory, a megabyte at a time, on
their way to being hashed. And on Linux and macOS, a drive that doesn't support hard links gets the
final file as a copy of the checked one, and that copy isn't checked again.

**Decrypted filenames come from you.** Output paths are chosen by the app, so a name
embedded in a malicious file cannot write outside the restore folder.

## What is NOT protected

Please read this section. These are real limits, not fine print.

### Names and sizes are visible

| Visible to your provider | Why it matters |
| --- | --- |
| File and folder names | `divorce-settlement.pdf.gpg` reveals a great deal |
| Collection names | They are ordinary folders |
| File sizes, approximately | Can help identify known files |
| File count and timestamps | Reveal activity patterns |
| Your account, IP, and upload times | Encryption cannot hide these |

Encrypting a name would need an archive mode or a name-mapping layer, which is on the
[roadmap](ROADMAP.md). **If you need hidden names today, use a tool that encrypts them,
such as [Cryptomator](https://cryptomator.org/) or
[rclone crypt](https://rclone.org/crypt/).** In the meantime, keep names vague, or put
files in an archive before encrypting it.

### Tampering

| Attack | Status |
| --- | --- |
| Corrupting or altering a file | **Detected**: integrity check fails, nothing restored |
| Replacing a file with unencrypted data | **Detected**: rejected on restore |
| Deleting files | **Not preventable**: keep other copies |
| Serving an older version (rollback) | **Not detected** |
| Swapping two files encrypted with the same secret | **Not detected**: names aren't bound to contents |
| **Public-key mode only:** replacing a file with new content encrypted to your public key | **Not detected** |

The last row deserves emphasis. Public keys are public and files are not signed, so
anyone who has your public key can create a file that decrypts perfectly. Passphrase
mode is not affected, because creating a valid file requires the passphrase. Sign-and-encrypt
is on the roadmap.

### Your recipient key ID is visible in public-key mode

Each file records the key ID it is encrypted to, without any encryption. A provider can
link all such files together and, if your key is on a public keyserver, to your identity.
Passphrase mode has no such identifier.

### Passphrase strength is on you

OpenPGP's S2K function is deliberately slow but **not memory-hard**, so it resists
GPU cracking far less than modern functions such as Argon2. A strong passphrase is what
really protects you. Use five or more random words, or the Generate button, which gives
about 147 bits. A weak passphrase cannot be fixed by any setting.

### The saved passphrase vault

The vault is optional. Its design:

- One GnuPG-encrypted JSON file, with the settings above. Plaintext exists only in
  pipes and in memory, and each save is decrypted and compared before it replaces
  the previous version.
- `gpg --decrypt vault.gpg` opens it without this application, so nothing is locked in.

Its costs, which you should weigh:

- **It is a single point of failure.** One weak master passphrase exposes every saved
  passphrase. One forgotten master passphrase loses all of them, with no recovery.
- **Secrets stay in memory while it is unlocked.** Python cannot reliably erase strings,
  and memory can reach the pagefile or a hibernation file. Locking drops the app's
  references, but copies may persist until that memory is reused. Full-disk encryption
  reduces this risk.
- **Typed passphrases pass through this app.** Turning on "Let GnuPG ask for each passphrase"
  in the Tools menu keeps
  them in Pinentry, so the app never sees them, at the cost of one prompt per file. The app then
  can't check the new files either, because it has no passphrase to decrypt them with.
- **The clipboard is exposed while a secret is on it.** Copying is cleared after 30 seconds
  and requests exclusion from Windows clipboard history and cloud sync, but other software
  on your computer can still read it, and not every clipboard tool honors the request.
- **A deleted entry may survive for one save** in `vault.bak.gpg`, encrypted under the
  same master passphrase. Changing the master passphrase removes that backup. Neither
  operation securely erases old disk sectors.

### Your own computer

- Originals and restored files are ordinary, unencrypted files.
- **If your originals sit in OneDrive, Dropbox, or similar, your provider likely already has
  them.** Encrypting a copy doesn't undo that. The app warns when it recognizes such a
  folder, but detection is a heuristic and misses clients it doesn't know.
- Restoring into a synced folder would upload the plaintext. The app warns about this too,
  with the same limitation.
- A crash or power cut during a restore can leave a hidden `.myob-*.partial` file containing
  plaintext in the restore folder.
- The operating system may keep traces such as thumbnails, search indexes, and recent-file lists.
- Restored files do not carry Windows' Mark-of-the-Web, so SmartScreen will not warn about
  them. Be careful running anything you restored, particularly in public-key mode.

### Other limits

- **Malicious compressed input** can expand hugely on restore and fill your disk. It cannot
  overwrite anything, and the partial output is removed.
- **Quantum computers.** AES-256 is considered comfortable against known quantum attacks,
  so passphrase mode has a good margin. Classical public keys (RSA, ECC) are not safe against
  a future quantum attacker who has saved your ciphertext. GnuPG 2.5 and later can create
  post-quantum Kyber keys (`gpg --quick-generate-key "You <you@example.com>" pqc`), and a test
  runs one through this app whenever GnuPG is new enough. The app's key list names each key's type,
  so you can tell them apart. These keys are still new, and older GnuPG and other OpenPGP tools may
  not be able to read the files they produce.
- **Signed files from other tools** will not restore until you import the signer's public
  key, because GnuPG reports the unverifiable signature as an error. The app explains this
  rather than restoring a file whose signature it can't check.
- **This is not a backup system.** It has no versioning or scheduling, and it doesn't verify that
  files reached your provider. The check after encrypting ends on your own computer. It is also not a workaround for your organization's data-handling policies.

## The Windows download

Running a download means trusting whoever built it, so here is exactly what you're trusting.

**Who builds it.** GitHub Actions builds it from a tagged commit, using this repository's
public workflow. Python packages are checked against hashes, and GnuPG and the installer
tool against pinned SHA-256 checksums. A person checks each release and publishes it.

**It isn't code-signed yet.** Windows therefore warns about it and can't tell you who made
it. The published checksums show that your file matches the release page, but someone who
took over the GitHub account could change both. Once this repository is public, each file
also gets a [build attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations),
which ties it to the workflow and commit that produced it:

```bash
gh attestation verify FILE --repo N-Bermparis/mindyourownbytes
```

That still trusts GitHub, and builds aren't reproducible yet, so nobody can yet confirm a
file by building it themselves. Code signing and reproducible builds are on the
[roadmap](ROADMAP.md).

**The included GnuPG.** These are the official Windows files, unmodified, and each one
carries g10 Code's signature, which you can see under its Properties. Files that reach
the network (`dirmngr`, `gpg-wks-client`, `libntbtls`) are left out, as are translations,
and CI fails if any of them, or Qt's or Python's network code, reappear. A GnuPG you
installed yourself takes priority, unless it's broken or too old to use. When the app
closes, it stops the included GnuPG's background helpers, which also clears any private
key passphrase that gpg-agent had remembered.

**Updates are manual.** The app never connects to anything, so it can't tell you when
there's a new version, and the included GnuPG only updates when the app does. A security
fix in GnuPG leads to a new release, but you have to install it. If you'd rather get
GnuPG updates separately, install Gpg4win, and the app will use it.

**It installs for your account only.** That avoids asking for administrator rights, but
it means that anything running as you could replace the app or its GnuPG. Such a program
could also do much else, as [your own computer](#your-own-computer) explains. Gpg4win in
Program Files can't be changed that way, so it's somewhat better protected.

## Testing

The test suite runs against real GnuPG and covers forged, tampered, truncated, and
garbage input, plus the agent cache via a scripted Pinentry. See `tests/`. **Passing tests
are not a security audit.** An independent review is needed before a stable release.
