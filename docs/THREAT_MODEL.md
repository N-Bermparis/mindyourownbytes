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

**Safe settings unless you ask for others.** New installations start in simple mode, which always
uses AES-256, always checks each new file, and always asks for passphrases in this app, whatever
was chosen before. **Tools > Show advanced options** offers the rest. Anyone who already relies on
an advanced option, such as a key of their own, starts in advanced mode, and the choice is then
remembered.

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
PATH. A `gpg.exe` planted in a folder such as Downloads will not be executed. On a Mac and on
Linux, the usual places come first too: Homebrew's, GPG Suite's, MacPorts', and the system's.

**Failures stay contained.** Files are staged under a temporary name and published
only after success. A failed file leaves nothing behind and doesn't stop the rest of the
batch. Links and junctions are never followed, and folders that can't be read are reported
rather than silently left out.

**What's encrypted is the file you chose.** Each original's identity (its device and file number)
is noted when it's chosen. When its turn comes, it's opened once, never through a link at the end of
its name (`O_NOFOLLOW` on Linux and macOS; on Windows, its identity before and after opening must
match), and only if it's still that very file. GnuPG never gets its name: it's given the contents over
a pipe, read from that open file, and hashed on the way, so the check after encrypting compares with
exactly what GnuPG was given, then reads the original again through the same open file. The same goes
for each file packed into an archive. Swapping the file meanwhile for a link to another file, for
another file, for a pipe, or a folder on its way for a link elsewhere, is refused, and nothing is
encrypted in its place. If its name no longer leads to the file that was read once encrypting ends,
the copy isn't kept. Tests make each of these swaps happen at each moment, against real GnuPG. A file
that's rewritten in place while it's read, keeping its size and time, is only caught by the check after
encrypting, which files for a key don't get.

**Nothing is replaced, and nothing appears half-made.** A finished file or folder gets its final
name in one step, which the operating system carries out atomically, and only if nothing at all has
that name: not a file, not a folder, even an empty one, and not a link, even one to nothing. Each
system needs its own call for this, because Python's `os.rename` replaces an empty folder, or a file,
on Linux and macOS without a word. During review, restoring an archive did exactly that to an empty
folder of the same name, and a drive without hard links got a partial file under its final name
while it was being copied. The calls now used are:

| System | Call | Refuses a taken name |
| --- | --- | --- |
| Windows | `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` (what `os.rename` uses there), after trying a hard link | Always |
| Linux | `renameat2(..., RENAME_NOREPLACE)`, or a hard link where that isn't supported, such as on NFS | When the file system supports either |
| macOS | `renamex_np(..., RENAME_EXCL)`, or a hard link | When the file system supports either |

A drive that supports neither, which can happen with some network and FUSE file systems, and with
WSL's view of Windows drives, makes the file or folder fail with a message saying so. There is
deliberately no fallback that copies into the final name, or renames in a way that could replace
something. The name was only ever a suggestion: if another program, or another copy of this app,
takes it between the moment it's chosen and the moment it's used, the next free name is used instead,
such as `report (2).pdf`.

Atomic isn't durable. Before a file gets its name, the app asks the system to write it to the drive
(`fsync`, and `F_FULLFSYNC` on a Mac), and a failure there, such as a full disk, stops it being
published. Afterwards it asks for the folder too, where the system allows. That makes a file far more
likely to survive a power cut, but drives, virtual machines, and sync clients can still lose recent
writes, so it isn't promised.

**Each new file is checked before it counts.** People may delete an original once its copy is
reported as encrypted, so that report has to be true. Whenever the app has the passphrase (typed
once for a batch, or saved), GnuPG decrypts each new file again while it still has its temporary
name. The passphrase goes over a pipe, as it does for encrypting. The decrypted bytes come back over
another pipe, are hashed with SHA-256 a piece at a time, and are never written to disk. The file gets
its final name only if GnuPG exits without an error, reports `DECRYPTION_OKAY`, and the hash equals a
hash of the original, which is read last. Otherwise the file is deleted, that row fails with the
reason, and the rest of the batch carries on. If the original changed while this was happening, the
app says so, rather than calling anything damaged.

During review this caught a real case. With `textmode` in `gpg.conf`, GnuPG encrypted and decrypted
without complaint, but the file that came back had different line endings. Every GnuPG call now
passes `--no-textmode`, so that setting can't change any file, including the ones this check can't
cover.

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

One smaller limit: the decrypted bytes pass through this app's memory, a megabyte at a time, on
their way to being hashed. The checked file itself is what gets the final name, never a copy of it.

**Decrypted filenames come from you.** Output paths are chosen by the app, so a name
embedded in a malicious file cannot write outside the restore folder.

**Archives are packed and unpacked carefully.** An archive is an ordinary zip, made with
Python's standard `zipfile` and written straight into GnuPG, so no readable archive touches disk
while it's made. GnuPG's own compression is turned off for archives (`--compress-algo none`),
because the zip is compressed already. Everything else, including the key derivation and the
integrity check, is the same as for a single file. The check after encrypting decrypts the
archive again and compares it with the exact zip that was packed. It doesn't read the originals
a second time, which could take as long again for a large folder. Instead, each original's size,
time, and identity must be what they were just before it was packed.

Restoring needs the decrypted zip on disk for a while, because a zip keeps its table of contents
at its end. Holding it in memory instead would put a limit on archives, and reading it without its
table of contents would give up the checks below, so it's written to disk, inside the restore's
private workspace (see [below](#decrypted-data-on-its-way-to-its-name)), and deleted with it. Only a zip that
carries this app's mark in its comment is unpacked. Any other zip you encrypted as an ordinary
file restores as that zip. Before anything is written, every name inside is checked: none may
leave the folder (`..`, an absolute path, or a drive), or be a name Windows can't create, and no
name may appear twice. The total size it claims must fit on the disk, and each file is cut off at
the size it claims. Each file is created new, never through a link, and written to the drive before
the next. Everything is unpacked inside the workspace, and the folder only gets its final name once
every file is out and has passed zip's own CRC check, in one step that never replaces anything.
Anything that fails leaves nothing.

Someone who knows the passphrase, or anyone who has your public key, can make an archive that
passes all of this, just as they can make a single file. It still can't write outside the folder.
A signature, [below](#who-made-a-file-signatures), is what shows who made it.

### Decrypted data on its way to its name

Everything a restore decrypts goes into a **workspace**: a hidden folder named `.myob-<16 hex
digits>.partial`, made beside the destination, so that publishing is a rename on the same drive.
That's the decrypted file, or for an archive the decrypted zip and the folder being unpacked from it.
Only a finished result leaves it, by getting its final name. The workspace is then deleted, whether
the restore worked, failed, was cancelled, or met an unexpected error.

- **Private.** On Linux and macOS it's made with mode 0700, so no other account can look inside,
  whatever the destination folder allows. Windows has no such mode, so the workspace gets the
  destination folder's own permissions, the same that the restored files get. The default restore
  folder, in your user profile, is private to your account.
- **Noted before use.** Before anything readable goes in, a note of where it is goes into the app's
  own folder, beside the vault. The note goes once the workspace has. If the app is killed, crashes,
  or loses power, the note stays, and the next start lists exactly where readable data was left,
  wherever that was, and offers to delete it. **Tools > Clean up after an interrupted restore** does
  the same at any time.
- **Deleted only when provably the app's.** A workspace holds a marker with a random token, which its
  note also holds. Only a real folder, not a link or junction, named like a workspace, holding the
  matching token, and on Linux and macOS owned by you, is ever deleted, and never without asking.
  Anything else is listed and left alone. Deleting never follows a link inside the workspace.
- **Several copies of the app** each hold a lock on a session file while they run. A workspace only
  counts as left behind once the copy that made it has stopped, so one copy never deletes another's.
- A workspace that can't be deleted, perhaps because another program has a file in it open, is named
  when the restore ends, and offered again at the next start.

What remains: between a crash and the next start, readable data sits in that hidden folder, and an
empty one can be left if the app stops in the moment between making a workspace and noting it.
Encrypting stages its output as a hidden `.myob-*.partial` file too, but that holds only encrypted
data. Deleting a file removes its name: on an SSD, a copy-on-write file system, in a backup, or in a
sync client's history, its contents can survive, so nothing here claims secure erasure.

### Who made a file: signatures

Five things can be true of a restored file, and they're kept apart, in the app and here:

1. **Encrypted** (confidentiality): only the passphrase or the private key opens it.
2. **Decrypted** (integrity, as far as decrypting goes): GnuPG reported `DECRYPTION_OKAY`, and its
   integrity check passed. With a passphrase, whoever made the file knew the passphrase. With a key,
   **anyone who has the public key** could have made it, and the public key is meant to be public.
3. **Matches your record**: it has the checksum this computer saved when it made the file.
4. **Validly signed** (authenticity): it hasn't changed since the holder of one particular private key
   signed it. GnuPG reported `VALIDSIG` with that key's fingerprint.
5. **Signed by someone you trust**: GnuPG considers the key valid (`TRUST_ULTIMATE` for your own keys,
   `TRUST_FULLY` for keys you certified in Kleopatra), or you named its fingerprint yourself.

Only 4 and 5 say who made a file. **Sign-and-encrypt**, offered when encrypting to a key in advanced
mode, adds an ordinary OpenPGP signature with a key of yours, made by GnuPG's own `--sign --local-user
<fingerprint>`. GnuPG asks for that key's passphrase through Pinentry, so the app never sees it or
any private key. The file is standard OpenPGP: plain `gpg --decrypt` opens it and checks the
signature, and a test confirms that. A signed file must also report `SIG_CREATED`, or it isn't kept.

On restore, signatures are judged from GnuPG's status lines, never from its translated text:

| What GnuPG reported | What the app does |
| --- | --- |
| No signature, file opened with a passphrase | Restores it. Whoever made it knew the passphrase |
| No signature, file opened with a key | **Held**: decrypted, deleted again, and listed as **not restored yet, not signed**, until you choose **Restore anyway…** (see below) |
| A valid signature by a key that's yours or certified | Restores it, **signed by** the key's name, with its fingerprint in the tooltip |
| A valid signature by any other key | **Held**, as **signed with a key you haven't verified**, with its fingerprint. The name is never shown as the signer |
| A valid signature by a revoked key | **Held**, as **signed with a revoked key** |
| A valid signature by a key that has expired since | **Held**, as **signed with a key that has expired** |
| An invalid signature (`BADSIG`) | **Refused**, and nothing is kept |
| A signature that can't be checked (`ERRSIG`), such as by a key you don't have | **Refused**, with the reason |
| A report that's incomplete or contradicts itself | **Refused** |

`GOODSIG` alone is never enough: a valid signature also needs `VALIDSIG`, naming the same key. Any
signature reported twice, any result without its own `NEWSIG`, or any second trust verdict for the same
signature makes the whole report "incomplete", and refused. GnuPG writes its status lines and its own
messages to the same stream here, and GnuPG 2.2.8 and later, which this app requires, escape untrusted
text in those messages (CVE-2018-12020), so these rules are a second line of defence.

Who is trusted follows GnuPG's own trust model, including any `trust-model` in your `gpg.conf`. The
app never trusts a key by itself, and never treats a name or an email address as proof of anything.
With `trust-model always`, GnuPG reports no trust at all, so every signer shows as unverified rather
than trusted. Once a signing key expires, GnuPG gives no trust verdict for it either, even for your
own key, so its signatures show as **signed with a key that has expired**, and a requirement for a
signature refuses them. This matters for backups, because keys made by this app last three years:
extending a key's expiry date in Kleopatra makes its signatures verify again.

Files encrypted to a key before signing existed have no signature, so they say **not signed**, and
they keep restoring unless you turn the requirement on.

## What is NOT protected

Please read this section. These are real limits, not fine print.

### Names and sizes are visible

With separate files, which is the default:

| Visible to your provider | Why it matters |
| --- | --- |
| File and folder names | `divorce-settlement.pdf.gpg` reveals a great deal |
| Collection names | They are ordinary folders |
| File sizes, approximately | Can help identify known files |
| File count and timestamps | Reveal activity patterns |
| Your account, IP, and upload times | Encryption cannot hide these |
| The algorithm of a passphrase file, such as AES-256 | Says nothing about the contents |

**Help > What your provider sees** shows this with your own files: the Encrypt screen's list, the
Library's files, or examples. One switch flips between your view and your provider's. For files
already encrypted, it shows 16 real bytes from the middle of each, which is all their contents look
like to anyone without the secret. With **One archive** chosen, your provider's view shows the single
file it gets.

**One archive hides the names inside.** Under "Save as", choosing **One archive** puts every
file into one zip, which GnuPG encrypts as one `.zip.gpg` file. The names, folders, number, and
sizes of the files inside are then encrypted along with their contents. Your provider still sees:

| Still visible with an archive | Why it matters |
| --- | --- |
| The archive's own name, and its collection | You choose them, so keep them vague. The suggestion is a date |
| Its size, approximately | The total of what's inside, after compression |
| When it was uploaded, and when it changes | Encryption cannot hide these |

The cost: the archive is one file, so changing one file inside means encrypting and uploading the
whole archive again, and restoring one file means restoring them all. Separate files avoid both,
but show their names. A name-mapping mode, which would hide names and keep files separate, is
still on the [roadmap](ROADMAP.md). [Cryptomator](https://cryptomator.org/) and
[rclone crypt](https://rclone.org/crypt/) already work that way.

### Tampering

| Attack | Status |
| --- | --- |
| Corrupting or altering a file | **Detected**: integrity check fails, nothing restored |
| Replacing a file with unencrypted data | **Detected**: rejected on restore |
| Deleting files | **Not preventable**: keep other copies |
| Serving an older version (rollback) | **Flagged, with a record**: see below. Otherwise not detected |
| Swapping two files encrypted with the same secret | **Flagged, with a record**: see below. Names aren't bound to contents |
| **Public-key mode only:** replacing a file with new content encrypted to your public key | **Flagged, with a record. Held** until you agree, as not signed, or signed by an unverified key, whether or not you signed your own files. **Refused** with **Never restore them**. Restored, and reported, with **Restore them, and say so** |
| Altering a signed file, or forging its signature | **Detected**: an invalid signature is refused, and nothing is restored |

The public-key row deserves emphasis. Public keys are public, so anyone who has yours can create a
file that decrypts perfectly. Passphrase mode is not affected, because creating a valid file requires
the passphrase. Signing your files when you encrypt them to a key closes the gap for files made from
then on: a forged file then either has no signature, or one by a key you haven't verified, so the
restore holds it until you agree, or refuses it if you've asked for that. See
[Who made a file](#who-made-a-file-signatures). Files you encrypted to a key without signing can't be
told apart from forgeries, except by their checksum record, so they're held too.

**Holding a file, and restoring it anyway.** A held file is decrypted into the private workspace,
checked, and deleted with the workspace before anyone is asked, so no readable copy waits on a question.
**Restore anyway…** lists each held file with what it showed, and any signing key's full fingerprint,
never its name. Agreeing decrypts them again, and each is restored only if GnuPG's report is the same as
before: the same verdict, about the same keys. A file swapped in between for one signed by another key
is held again. That costs a second decryption, and GnuPG may ask for your key's passphrase again. A bad
or unexpected signature, or one that can't be checked, is never offered: it's refused outright.

**Checksums kept on your computer.** Each file the app encrypts gets its SHA-256 written to
`records.jsonl`, beside the vault, which your provider can't reach. Before anything is decrypted,
the app hashes every download and looks it up. Its row then says whether it **matches your
record**, or is **an older copy** (a newer file was made later in the same place), was **renamed
or swapped** (its contents were saved under another name, or in another collection), or is **not
the copy you made** (its name is known, and its contents aren't). If any download is doubtful, the
app asks before decrypting it: restore it anyway, or leave it out and restore the rest. Leaving it
out is the default, and a file left out is never decrypted.

A name alone can't tell apart two files called `report.pdf.gpg` in different collections. So a
download in a folder named like a collection that has a file of its name has to be that file, and
a match anywhere else names the file it matched, such as `Medical/report.pdf.gpg`, whenever more
than one file made here has that name. Numbers that browsers and this app add to a taken name,
such as "report (1).pdf.gpg", are ignored when names are compared.

The Library's **Save checksums** writes a plain `SHA256SUMS` file, which `sha256sum --check`
reads without this app, and **Tools > Import checksums** adds one on another computer. Its
protection is only as good as where you keep it: a list stored beside the files in the cloud can be
changed along with them.

Its limits:

- **No record, no verdict.** Files made before this feature, on another computer, or with the record
  turned off restore without a verdict, as before.
- **The record can be lost or changed** by anything that can write to your user profile, which
  could already do far more. Losing it means losing the verdicts, not your files.
- **It only knows what it was told.** A rollback is flagged when a newer file was recorded later in
  the same place. A file replaced under a new name, of content never recorded, is just unknown.
- **The names are kept here too.** They're visible to your provider anyway, but the record keeps
  them on your computer. Tools can turn the record off, and forget it.

### Your recipient key ID is visible in public-key mode

Each file records the key ID it is encrypted to, without any encryption. A provider can
link all such files together and, if your key is on a public keyserver, to your identity.
Passphrase mode has no such identifier.

### Passphrase strength is on you

OpenPGP's S2K function is deliberately slow but **not memory-hard**, so it resists
GPU cracking far less than modern functions such as Argon2. A strong passphrase is what
really protects you. A weak passphrase cannot be fixed by any setting.

**Let the computer pick.** Wherever you choose a new passphrase, the app can generate one, using
Python's `secrets` module, which draws on the operating system's cryptographic random numbers:

| Kind | Made of | Strength |
| --- | --- | --- |
| Random words, the default | 7 words from EFF's Long Wordlist of 7,776 | About 90 bits |
| Random letters and digits | 30 from an alphabet of 30, without look-alikes such as 0 and O | About 147 bits |

Only a generated passphrase's strength can be stated exactly, so the app doesn't pretend to measure
one you make up. EFF's list is shipped exactly as EFF publishes it, and the app checks its SHA-256
before using it, so a changed or shortened list is refused rather than quietly weakening anything. No
word is the start of another, so words run together can only be read one way.

**A new passphrase you make up is checked, on this computer only.** Nothing typed is sent anywhere,
logged, or written down. A new passphrase for files, a new vault master passphrase, and a saved
passphrase used to encrypt new files all follow one rule. It's refused if it's shorter than the
minimum (8 characters for files, 12 for the master), or if it's **weak**: one of the passphrases people
use most, or one with a few characters changed or added (`P@ssw0rd2026`), one ordinary word, or a
short word or name, with digits or symbols around it (`Rosa 1987`), two ordinary words, a run of keys
or characters such as `qwertyuiop` or `abcd1234`, a short part repeated, only a few different
characters, or only digits, as in a date or a phone number. Case, accents' encoding, and full-width or styled letters don't hide anything from it.
Anything else is **better**, and is accepted with a reminder that a person chose it. Only a passphrase
the app generated is called **strong**. No number is ever claimed for one you made up.

Why refuse rather than warn: a weak passphrase is the one thing no setting can fix, guessers try exactly
these first, and the app always offers a strong alternative in the same window. The cost is that you
can't make new files with an old weak passphrase, even on purpose. Nothing typed to *open* something is
ever judged, so every file and vault made before this rule existed still opens with what protects it,
and a weak passphrase can still be saved in the vault, with a warning, to open old files. The checks
catch common patterns, not all of them: a passphrase that passes can still be a guessable choice,
which is why only a generated one is called strong.

A generated passphrase is shown in full, and when it's for encrypting or for the vault's master
passphrase, the app won't continue until you tick that you've saved it. Nobody can recover it.

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
- Restoring into a synced folder would upload the plaintext. The app refuses a restore folder it
  recognizes as synced, including through a link, and suggests one on this computer. In advanced
  mode, **Tools > Allow restoring into synced folders** turns the refusal into a warning. Recognizing
  a synced folder has the same limitation as above: an unusual one can go unnoticed.
- A crash or power cut during a restore can leave a hidden `.myob-*.partial` folder holding
  plaintext beside the destination: for an archive, that can be the whole decrypted zip. It stays
  until the app next starts, which then lists it and offers to delete it, as
  [described above](#decrypted-data-on-its-way-to-its-name). Deleting it isn't secure erasure.
- The operating system may keep traces such as thumbnails, search indexes, and recent-file lists.
- Restored files do not carry Windows' Mark-of-the-Web, so SmartScreen will not warn about
  them. Be careful running anything you restored, particularly in public-key mode.
- Restoring still gives GnuPG the encrypted file by its name. A download swapped for another between
  being compared with your saved checksums and being decrypted would be decrypted instead, and its
  row would still say what the comparison found. Who made it is still judged by its own signatures.

### Other limits

- **Malicious compressed input** can expand hugely on restore and fill your disk. It cannot
  overwrite anything, and the partial output is removed. An archive is held to the sizes it
  claims, and those must fit on the disk before anything is unpacked.
- **Quantum computers.** AES-256 is considered comfortable against known quantum attacks,
  so passphrase mode has a good margin. Classical public keys (RSA, ECC) are not safe against
  a future quantum attacker who has saved your ciphertext. GnuPG 2.5 and later can create
  post-quantum Kyber keys (`gpg --quick-generate-key "You <you@example.com>" pqc`), and a test
  runs one through this app whenever GnuPG is new enough. The app's key list names each key's type,
  so you can tell them apart. These keys are still new, and older GnuPG and other OpenPGP tools may
  not be able to read the files they produce.

  **Tools > Post-quantum keys** checks whether the GnuPG in use can make them, which it decides from
  GnuPG's version and its own list of algorithms. It shows which of your keys have a post-quantum
  part, and can create a key, or add a part to one of yours, by running GnuPG's `--quick-generate-key`
  or `--quick-add-key` with `pqc`. GnuPG asks for any passphrase in its own window, so the app never
  sees it, and nothing here reads or exports a private key. New keys and parts last three years.
  Before adding a part, the app warns that files encrypted to that key afterwards will only open
  with GnuPG 2.5 or later, and that anyone who encrypts for you needs your updated public key. Its
  explanations stay general on purpose, because how other OpenPGP apps handle post-quantum keys is
  still changing.
- **Signed files from other tools** will not restore until you import the signer's public
  key, because GnuPG reports the unverifiable signature as an error. The app explains this
  rather than restoring a file whose signature it can't check. Once the key is imported, the file
  restores, and says whether that key is one you've verified.
- **A drive that can't refuse a taken name**, such as some network shares, FUSE file systems, and
  WSL's view of Windows drives, can't be restored to, or written to, by this app. It says so, rather
  than risk replacing something.
- **This is not a backup system.** It has no versioning or scheduling, and it doesn't verify that
  files reached your provider. The check after encrypting ends on your own computer. It is also not a workaround for your organization's data-handling policies.

## The downloads

Running a download means trusting whoever built it, so here is exactly what you're trusting.

**Who builds them.** GitHub Actions builds each one from a tagged commit, on its own system,
using this repository's public workflow. Python packages are checked against hashes, and the
Windows download's GnuPG and installer tool against pinned SHA-256 checksums. A person checks
each release and publishes it. The Linux and macOS downloads don't include GnuPG at all: they
use the computer's own, found as described above.

**They aren't code-signed yet.** Windows and macOS therefore warn about them and can't tell
you who made them. The published checksums show that your file matches the release page, but someone who
took over the GitHub account could change both.

The release workflow is ready to sign, once the keys exist, and only for a version tag: Windows
downloads with Authenticode (SHA-256, with an RFC 3161 timestamp), and the macOS app with a Developer
ID, the hardened runtime, and Apple's notarization. Every signature is then checked with the system's
own verifier, and the build fails if any check does. The checksum list can also carry an OpenPGP
signature, `SHA256SUMS.txt.asc`, made in a job of its own that sees the release key and nothing else,
and checked with only the public key before publishing. None of these keys exist yet, so no download
is signed. The release notes and this section will say when that changes, and
[SECURITY.md](../SECURITY.md#verifying-a-download) will then publish the release key's fingerprint, which is
what a signature should be checked against. Once this repository is public, each file
also gets a [build attestation](https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations),
which ties it to the workflow and commit that produced it:

```bash
gh attestation verify FILE --repo N-Bermparis/mindyourownbytes
```

That still trusts GitHub, and builds aren't reproducible yet, so nobody can yet confirm a
file by building it themselves. Code signing and reproducible builds are on the
[roadmap](ROADMAP.md).

**No network code of their own.** The app opens no connections, so the downloads leave out the
code for them: Qt's network library and the Qt plugins that need it, Python's `socket`, `ssl`,
`http`, `urllib.request`, `ftplib`, `xmlrpc`, and `asyncio` modules, and OpenSSL. The Linux
download also leaves out the Kerberos libraries that Qt's network library would bring. CI fails if
Qt's network library, Python's socket and SSL modules, or OpenSSL turn up in any download, and on
Linux and macOS it also looks for socket and SSL code built into Python itself, as some builds of
Python have. The Linux download does carry GTK and GLib, which PyInstaller copies from the build
system for Qt's GTK theme. GLib can open network connections, though nothing in the app asks it to.
On Linux and macOS, the app uses the computer's own GnuPG, which includes its network tools, and
turns off GnuPG's keyserver lookups on every call.

**The GnuPG in the Windows download.** These are the official Windows files, unmodified, and each one
carries g10 Code's signature, which you can see under its Properties. Files that reach
the network (`dirmngr`, `gpg-wks-client`, `libntbtls`) are left out, as are translations,
and CI fails if any of them reappear. A GnuPG you installed yourself takes priority, unless
it's broken or too old to use. When the app closes, it stops the included GnuPG's background
helpers, which also clears any private key passphrase that gpg-agent had remembered.

**Updates are manual.** The app never connects to anything, so it can't tell you when
there's a new version, and the included GnuPG only updates when the app does. A security
fix in GnuPG leads to a new release, but you have to install it. If you'd rather get
GnuPG updates separately, install Gpg4win, and the app will use it.

**The right-click entry.** Unless you untick it, the installer adds **Encrypt with mindyourownbytes**
to File Explorer's menu for files and folders. It's six registry values under your own account's
`HKEY_CURRENT_USER\Software\Classes`, and uninstalling removes them. Explorer starts the app with the
path of what you clicked, and the app only adds it to the list on the Encrypt screen. Nothing is
encrypted until you click **Encrypt**, and the usual warnings, such as for a synced folder, still apply.

Explorer starts one copy of the app for each file you select. A later copy finds the open window
through a named piece of shared memory that only programs in your own sign-in session can see, hands
it the path in a `WM_COPYDATA` message, and exits. It checks first that the window belongs to the
same program file as itself. Only paths are sent, never file contents or passphrases. The open window
reads nothing but a list of text from such a message, and refuses it while a job is running. Another
program running as you could send it paths too, but all they'd do is appear in the list. As
[your own computer](#your-own-computer) explains, such a program could do far more than that anyway.

**It installs for your account only.** That avoids asking for administrator rights, but
it means that anything running as you could replace the app or its GnuPG. Such a program
could also do much else, as [your own computer](#your-own-computer) explains. Gpg4win in
Program Files can't be changed that way, so it's somewhat better protected.

## Testing

The test suite runs against real GnuPG and covers forged, tampered, truncated, and
garbage input, plus the agent cache via a scripted Pinentry. See `tests/`. It also covers, on the
real file system: publishing beside an existing empty folder, a populated one, a file, and a link to
nothing; names taken by another program in between; a dozen publishers racing for one name; and
restores that end in every way, including a process killed halfway, after which the leftover is found
and removed. Signing is tested with real keys: your own, an uncertified and a certified one, a
revoked and an expired one, a missing public key, an unexpected signer, and a signature broken after
signing. CI is set up to run it on Windows, Linux, and macOS. **Passing tests are not a security
audit.** An independent review is needed before a stable release.
