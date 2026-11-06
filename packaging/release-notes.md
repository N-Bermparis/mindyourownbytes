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

### Check your download

In PowerShell, run this and compare the result with the list below:

```powershell
Get-FileHash .\{setup}
```

```text
{checksums}
```

A matching checksum shows that your file is the one published here. It can't protect you if
this GitHub account itself were compromised, which is what signing and independent builds are for.

`{gnupg_source}` is the source code of the included GnuPG. You don't need it to use the app.

## What's in this release

{changes}
