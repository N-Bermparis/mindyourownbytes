# Help test mindyourownbytes on a Mac

Thank you for helping. Nobody has run mindyourownbytes on a Mac yet, so even "it opened" or "it
didn't" is useful. You don't need to know anything about cryptography, and any Mac will do: Apple
silicon or Intel, on whichever macOS version you normally use. It takes about 20 minutes.

**Use only made-up test files.** Never use real documents, passphrases, private keys, or real
encrypted backups, and never post any of them in an issue.

## 1. Install what it needs

With [Homebrew](https://brew.sh/), in Terminal:

```bash
brew install python git gnupg pinentry-mac
```

Any Python from 3.12 up works, including one from [python.org](https://www.python.org/downloads/).
`pinentry-mac` is the window GnuPG uses to ask for a key's passphrase.

## 2. Keep your real keys out of it

The safest place to test is a separate macOS user account made just for this (**System Settings >
Users & Groups**), which you can delete afterwards with everything in it. Use one if you've ever used
mindyourownbytes on this Mac before: in your own account, the app would use your real settings and
saved passphrases.

Either way, testing makes keys you won't want to keep. Give this Terminal window its own empty GnuPG
folder, and tell GnuPG to ask for passphrases in a window:

```bash
export MYOB_TEST_GNUPG="$(mktemp -d)"
export GNUPGHOME="$MYOB_TEST_GNUPG"
echo "pinentry-program $(brew --prefix)/bin/pinentry-mac" > "$GNUPGHOME/gpg-agent.conf"
```

Run every command below in this same window. If you close it, start again from here.

## 3. Get the code, and start the app

```bash
git clone https://github.com/N-Bermparis/mindyourownbytes.git
cd mindyourownbytes
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt
python -m mindyourownbytes
```

If the app doesn't open, copy everything Terminal printed into your report.

## 4. Let it test itself

Quit the app, then run its self-test. It opens the real window, encrypts and restores files in a
throwaway GnuPG folder of its own, and saves what it found, with pictures of the window:

```bash
python -m mindyourownbytes --self-test ~/myob-self-test
echo "exit code: $?"
```

An exit code of 0 means every check passed. Either way, the folder `~/myob-self-test` holds
`self-test.json` and the pictures, which are worth attaching to your report.

## 5. Try it by hand

Make a few test files, then start the app again:

```bash
mkdir -p ~/myob-test/folder
echo "a made-up test file" > ~/myob-test/note.txt
echo "another made-up file" > ~/myob-test/folder/inner.txt
python -m mindyourownbytes
```

- [ ] The window looks right in both light and dark mode (System Settings > Appearance).
- [ ] Encrypt `note.txt` with a passphrase, restore it into another folder, and check that it's the
      same: `diff ~/myob-test/note.txt RESTORED-FILE` prints nothing when they match.
- [ ] Drag a file, and then the folder, onto the Encrypt screen and the Restore screen.
- [ ] Encrypt the folder into one archive, then restore it.
- [ ] Restore the same file twice into one folder. The second copy should be called `note (2).txt`,
      and the first should be left alone.
- [ ] Open a `.gpg` file without the app: `gpg --decrypt FILE.gpg`, typing the passphrase into the
      window that appears.
- [ ] Save a passphrase on the Passphrases screen, lock it, and open it again.
- [ ] Turn on **Tools > Show advanced options**. Make a test key with
      `gpg --quick-generate-key "Test <test@example.invalid>"`, encrypt to it, signing too, and restore.
- [ ] Choose a restore folder inside iCloud Drive. The app should refuse it, and suggest a folder on
      this Mac instead.
- [ ] Cancel an encrypt and a restore partway through, and check that nothing half-finished is left.
- [ ] Note anything that looks wrong, is cut off, or is hard to understand.

## 6. Run the automated tests (optional)

They take about five minutes, and use their own temporary GnuPG folder:

```bash
QT_QPA_PLATFORM=offscreen MYOB_REQUIRE_GPG=1 python -m unittest discover -s tests -t .
```

Copy the last few lines of the output into your report, and the details of anything listed as
`FAIL` or `ERROR`.

## 7. Report what happened

Comment on [issue #6](https://github.com/N-Bermparis/mindyourownbytes/issues/6) with:

- the output of `sw_vers` and `uname -m`, which give your macOS version and processor
- the output of `python3 --version` and `gpg --version | head -1`
- the self-test's exit code, and `self-test.json`
- what worked, what didn't, and the steps that make it happen again
- pictures, if they help, showing test files only

If something looks like a security problem, report it [privately](../SECURITY.md) instead.

## 8. Clean up

If you tested in a separate user account, delete that account, and you're done.

Otherwise, this removes only what the test made: the throwaway GnuPG folder with the test keys, the
test files, and the self-test's results.

```bash
deactivate
if [ -n "$MYOB_TEST_GNUPG" ]; then
  gpgconf --homedir "$MYOB_TEST_GNUPG" --kill gpg-agent
  rm -rf "$MYOB_TEST_GNUPG"
fi
rm -rf ~/myob-test ~/myob-self-test
```

It never touches your own GnuPG folder, even if your settings name one. If you've closed the window
from step 2 since, the throwaway folder is with your temporary files, which macOS clears out by itself.
Then delete the `mindyourownbytes` folder that `git clone` made.

The app also keeps its settings, the checksums of what you encrypted, and any passphrases you saved, in
your account. **If you used mindyourownbytes on this Mac before this test, leave those alone**, because
they'd include your real saved passphrases. If this test was the first time, you can remove them too:

1. In Finder, choose **Go > Go to Folder**, and type `~/Library/Application Support`.
2. Drag the `mindyourownbytes` folder to the Trash, where you can still get it back until you empty it.
3. Clear the app's settings: `defaults delete com.mindyourownbytes.mindyourownbytes`

Thank you!
