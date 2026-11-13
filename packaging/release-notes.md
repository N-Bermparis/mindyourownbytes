> [!CAUTION]
> **Alpha software, not independently audited.** Please test with non-sensitive files first,
> and keep other verified backups.

## Download for Windows

**Most people want [`{setup}`]({downloads}/{setup}).** Run it, click **Install**, and you're done. It needs no
administrator rights, and it includes GnuPG {gnupg}, so there's nothing else to install.

**[`{portable}`]({downloads}/{portable})** is the same app without installing. Unzip it and open
`mindyourownbytes.exe`.

Already have an older version? Run the new installer over it. Your files, keys, and saved
passphrases aren't touched, and neither installing nor uninstalling removes them.

### Windows will warn you

These downloads aren't code-signed yet, so Windows doesn't recognize who published them:

- **"Windows protected your PC":** click **More info**, then **Run anyway**, but only after
  checking the file as described below.
- **Smart App Control** blocks unsigned apps with no way to continue. If it's on, wait for
  signed builds, or [run from source]({repository}#run-from-source).

## Download for macOS

**[`{macos}`]({downloads}/{macos})** is for Macs with Apple silicon. Open it, and drag
mindyourownbytes into Applications. It needs GnuPG, from [GPG Suite](https://gpgtools.org/) or
`brew install gnupg`, and the app says how to get it if it's missing.

The app isn't signed by Apple yet, so the first time, macOS won't open it. After checking the file
as described below, open **System Settings > Privacy & Security** and click **Open Anyway** beside
its name. An Intel Mac can [run it from source]({repository}#run-from-source).

## Download for Linux

**[`{linux}`]({downloads}/{linux})** is for 64-bit Intel and AMD processors. Unpack it anywhere
and run `mindyourownbytes` in the folder it makes. `add-to-menu.sh`, in the same folder, adds it to
your applications menu. It needs GnuPG, which most Linux systems already have, or which your package
manager installs as `gnupg`.

## Check your download

Run the line for your system, and compare the result with the list below.

```powershell
Get-FileHash .\{setup}   # Windows, in PowerShell
```

```bash
shasum -a 256 {macos}    # macOS, in Terminal
sha256sum {linux}        # Linux
```

```text
{checksums}
```

A matching checksum shows that your file is the one published here. It can't protect you if
this GitHub account itself were compromised, which is what signing and independent builds are for.

If this release lists `SHA256SUMS.txt.asc`, it's an OpenPGP signature of the checksums. Check it with
`gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt`, and compare the key's fingerprint with the one in
[SECURITY.md]({repository}/blob/main/SECURITY.md#verifying-a-download), never with one found here.

`{gnupg_source}` is the source code of the GnuPG included in the Windows download. You don't need
it to use the app.

## What's in this release

{changes}
