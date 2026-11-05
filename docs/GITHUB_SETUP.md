# GitHub staging setup — private first

Repository: `N-Bermparis/mindyourownbytes`

## Step 1 — Create the private repository

Visit https://github.com/new and choose:

| Setting | Value |
| --- | --- |
| Owner | `N-Bermparis` |
| Repository | `mindyourownbytes` |
| Description | `Your files. Your keys. None of their business. Local GnuPG-encrypted backups for any cloud.` |
| Visibility | **Private** |
| Initialize README | **Yes** (creates an initial `main` branch) |
| .gitignore | None (this project contains its own) |
| License | None for now; decide explicitly before going public |

Send the new repository URL to your assistant to upload the staged source tree,
or clone the new repository and copy the files from this project folder.

## Step 2 — Configure the repository while private

- Keep **Issues** enabled.
- Under **Settings → General → Features**, enable **Discussions**.
- Under **Settings → Security / Code security**, enable private vulnerability
  reporting when available and verify the security policy is visible.
- Add topics: `encryption`, `openpgp`, `gnupg`, `kleopatra`, `privacy`,
  `backup`, `cloud-storage`, `windows`, `pyside6`, `python`.
- After the first CI workflow succeeds, configure a `main` branch ruleset
  requiring a pull request, at least one review, and passing tests. Avoid
  force pushes and branch deletion.
- Keep only trusted maintainers with write/admin access.

## Step 3 — Use the private repository to validate

- Let GitHub Actions run on Windows and Linux.
- Test real encryption and restore on your own Windows machine with dummy files.
- Have at least one outside reviewer inspect GnuPG invocation, path handling,
  accidental plaintext exposure, and failure cleanup.
- Complete [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).
- Choose and add a license (MIT or GPL-3.0-or-later are candidates).

## Step 4 — Public launch (later, only with explicit approval)

Once the checklist is complete, go to **Settings → General → Danger Zone →
Change repository visibility → Public**. Review the consequences carefully:
all repository content and history become publicly accessible. Never switch
visibility before checking that no test credentials, private keys, client
materials, or sensitive file names entered its commit history.

Create the first release as **Pre-release** while the security review is still
in progress. Enable Discussions with welcome and roadmap threads. Do not call
the project audited or production-ready unless that has been established.
