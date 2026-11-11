"""The real gpg-agent and Pinentry path, using a scripted stand-in for the dialog.

These tests matter because passing a passphrase over a pipe bypasses gpg-agent
entirely, so they alone can show what the agent remembers afterwards.
"""

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from mindyourownbytes import recovery
from mindyourownbytes.core import SourceItem, encrypt_archive, process_items
from tests.support import GpgTestCase

PASSPHRASE = "correct horse battery staple"

_POSIX_STUB = """#!{python}
import pathlib, sys
here = pathlib.Path(__file__).parent
out = sys.stdout.buffer
def send(line):
    out.write(line + b"\\n"); out.flush()
send(b"OK Pleased to meet you")
repeat = False
for raw in sys.stdin.buffer:
    command = raw.strip().split(b" ", 1)[0].upper()
    if command == b"SETREPEAT":
        repeat = True; send(b"OK")
    elif command == b"GETPIN":
        with open(here / "pinentry.log", "a") as log: log.write("GETPIN\\n")
        pin = here / "pin.txt"
        if not pin.exists():
            send(b"ERR 83886179 Operation cancelled"); continue
        if repeat: send(b"S PIN_REPEATED 1")
        send(b"D " + pin.read_bytes()); send(b"OK"); repeat = False
    elif command == b"BYE":
        send(b"OK closing"); break
    elif command == b"GETINFO":
        send(b"D 1"); send(b"OK")
    else:
        send(b"OK")
"""

_WINDOWS_STUB = """
using System; using System.IO; using System.Text;
class P { static void Main() {
  var dir = AppDomain.CurrentDomain.BaseDirectory;
  var o = Console.OpenStandardOutput();
  var i = new StreamReader(Console.OpenStandardInput(), new UTF8Encoding(false));
  Action<byte[]> raw = b => { o.Write(b,0,b.Length); o.WriteByte(10); o.Flush(); };
  Action<string> w = s => raw(Encoding.ASCII.GetBytes(s));
  w("OK Pleased to meet you");
  bool repeat = false; string l;
  while ((l = i.ReadLine()) != null) {
    var c = l.Split(' ')[0].ToUpperInvariant();
    if (c == "SETREPEAT") { repeat = true; w("OK"); }
    else if (c == "GETPIN") {
      File.AppendAllText(Path.Combine(dir,"pinentry.log"), "GETPIN\\r\\n");
      var file = Path.Combine(dir,"pin.txt");
      if (!File.Exists(file)) { w("ERR 83886179 Operation cancelled"); continue; }
      var pin = File.ReadAllBytes(file);
      if (repeat) w("S PIN_REPEATED 1");
      var d = new byte[pin.Length+2]; d[0]=(byte)'D'; d[1]=(byte)' ';
      Array.Copy(pin,0,d,2,pin.Length); raw(d);
      w("OK"); repeat = false;
    }
    else if (c == "BYE") { w("OK closing"); break; }
    else if (c == "GETINFO") { w("D 1"); w("OK"); }
    else w("OK");
  }
} }
"""


def _windows_compiler() -> Path | None:
    framework = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Microsoft.NET" / "Framework64"
    compilers = sorted(framework.glob("v4*/csc.exe")) if framework.is_dir() else []
    return compilers[-1] if compilers else None


def build_stub(folder: Path) -> Path | None:
    """Write a stand-in Pinentry into ``folder``. gpg-agent needs a real executable."""
    if os.name != "nt":
        stub = folder / "fake-pinentry"
        stub.write_text(_POSIX_STUB.format(python=sys.executable))
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
        return stub
    compiler = _windows_compiler()
    if compiler is None:
        return None
    source = folder / "fake_pinentry.cs"
    source.write_text(_WINDOWS_STUB)
    stub = folder / "fake_pinentry.exe"
    result = subprocess.run([str(compiler), "/nologo", f"/out:{stub}", str(source)],
                            capture_output=True, check=False)
    return stub if result.returncode == 0 and stub.is_file() else None


class PinentryTests(GpgTestCase):
    @classmethod
    def setUpClass(cls):
        cls._stub_folder = Path(tempfile.mkdtemp(prefix="myobpin"))
        cls.addClassCleanup(shutil.rmtree, cls._stub_folder, ignore_errors=True)
        cls.stub = build_stub(cls._stub_folder)

    def setUp(self):
        super().setUp()
        if self.stub is None:
            self.skipTest("no way to build a stand-in Pinentry on this machine")
        (self.home / "gpg-agent.conf").write_text(f"pinentry-program {self.stub}\n")
        self.answer_with(PASSPHRASE)
        self.reset_dialog_count()
        self.progress = []

    def answer_with(self, passphrase: str | None) -> None:
        pin = self._stub_folder / "pin.txt"
        if passphrase is None:
            pin.unlink(missing_ok=True)
        else:
            pin.write_bytes(passphrase.encode())

    def reset_dialog_count(self) -> None:
        (self._stub_folder / "pinentry.log").unlink(missing_ok=True)

    def dialogs(self) -> int:
        log = self._stub_folder / "pinentry.log"
        return log.read_text().count("GETPIN") if log.exists() else 0

    def write(self, name: str, content: bytes = b"private") -> SourceItem:
        path = self.root / name
        path.write_bytes(content)
        return SourceItem(path, Path(name), len(content))

    def job(self, items, out, operation):
        return process_items(self.gpg, items, self.root / out, operation, "password", None,
                             threading.Event(), lambda *args: self.progress.append(args))

    def test_round_trip_through_the_agent(self):
        encrypted = self.job([self.write("a.txt", b"via pinentry")], "exports", "encrypt")
        self.assertEqual((encrypted.succeeded, encrypted.failed), (1, 0), self.progress)
        item = SourceItem(encrypted.outputs[0], Path("a.txt.gpg"), encrypted.outputs[0].stat().st_size)
        restored = self.job([item], "restored", "restore")
        self.assertEqual(restored.outputs[0].read_bytes(), b"via pinentry")

    def test_passphrase_does_not_linger_in_the_agent_after_encrypting(self):
        # Regression: restoring straight after encrypting showed zero prompts,
        # because gpg-agent still held the passphrase. Anyone at the keyboard
        # could read the file for as long as the cache lasted.
        encrypted = self.job([self.write("a.txt")], "exports", "encrypt").outputs[0]
        self.reset_dialog_count()
        item = SourceItem(encrypted, Path("a.txt.gpg"), encrypted.stat().st_size)
        self.job([item], "restored", "restore")
        self.assertEqual(self.dialogs(), 1, "restoring must ask for the passphrase")

    def test_decrypting_twice_asks_twice(self):
        encrypted = self.job([self.write("a.txt")], "exports", "encrypt").outputs[0]
        item = SourceItem(encrypted, Path("a.txt.gpg"), encrypted.stat().st_size)
        self.job([item], "first", "restore")
        self.reset_dialog_count()
        self.job([item], "second", "restore")
        self.assertEqual(self.dialogs(), 1)

    def test_batch_without_a_typed_passphrase_asks_once_per_file(self):
        # Documents why "type once for this batch" exists and is the default.
        self.job([self.write(f"{n}.txt") for n in range(3)], "exports", "encrypt")
        self.assertEqual(self.dialogs(), 3)

    def test_files_gnupg_asked_about_are_not_checked_so_nobody_is_asked_twice(self):
        # Encrypting opens one dialog. A check would have to decrypt, which would open another.
        result = self.job([self.write("a.txt")], "exports", "encrypt")
        self.assertEqual((result.succeeded, result.checked), (1, 0), self.progress)
        self.assertEqual(self.progress[-1][2], "Ready")
        self.assertEqual(self.dialogs(), 1)

    def test_checking_a_file_leaves_no_passphrase_in_the_agent(self):
        # The check decrypts with a passphrase this app holds. That must not let the next person
        # at the keyboard restore the file without being asked.
        encrypted = process_items(self.gpg, [self.write("a.txt")], self.root / "exports", "encrypt", "password",
                                  None, threading.Event(), lambda *args: self.progress.append(args),
                                  passphrases=[PASSPHRASE])
        self.assertEqual((encrypted.succeeded, encrypted.checked), (1, 1), self.progress)
        self.assertEqual(self.dialogs(), 0, "a passphrase in hand never opens a dialog")
        item = SourceItem(encrypted.outputs[0], Path("a.txt.gpg"), encrypted.outputs[0].stat().st_size)
        restored = self.job([item], "restored", "restore")
        self.assertEqual(restored.succeeded, 1, self.progress)
        self.assertEqual(self.dialogs(), 1, "restoring must still ask for the passphrase")

    def test_the_recovery_guides_commands_really_restore_everything(self):
        # Exactly as the guide prints them, with GnuPG asking for the passphrase as it would for a person.
        folder = self.root / "Downloads"
        (folder / "Taxes").mkdir(parents=True)
        made = {"Taxes/return.pdf": b"return", "notes.txt": b"notes"}
        for relative, content in made.items():
            original = self.root / "originals" / relative
            original.parent.mkdir(parents=True, exist_ok=True)
            original.write_bytes(content)
            encrypted = process_items(self.gpg, [SourceItem(original, Path(original.name), len(content))],
                                      (folder / relative).parent, "encrypt", "password", None, threading.Event(),
                                      lambda *args: None, passphrases=[PASSPHRASE])
            self.assertEqual(encrypted.succeeded, 1)
        windows = os.name == "nt"
        command = recovery.steps("windows" if windows else "linux")[3].commands[1]
        shell = (["powershell", "-NoProfile", "-NonInteractive", "-Command", command] if windows
                 else ["sh", "-c", command])
        environment = {**os.environ, "PATH": f"{Path(self.gpg).parent}{os.pathsep}{os.environ.get('PATH', '')}"}
        result = subprocess.run(shell, cwd=folder, env=environment, capture_output=True, timeout=120, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[-500:])
        for relative, content in made.items():
            self.assertEqual((folder / relative).read_bytes(), content, relative)
        self.assertEqual(self.dialogs(), 2, "GnuPG asked once for each file")

    def test_one_batch_can_mix_passphrase_files_and_files_for_a_protected_key(self):
        # Regression: the typed passphrase was also given to GnuPG for the key's file, as if it were the
        # key's own passphrase, so that file failed unless the two happened to be the same.
        fingerprint = self.generate_key("Protected <protected@example.invalid>", passphrase=PASSPHRASE)
        for_key = process_items(self.gpg, [self.write("for-key.txt", b"opened with the key")],
                                self.root / "exports", "encrypt", "public-key", fingerprint, threading.Event(),
                                lambda *args: None).outputs[0]
        typed = "a different passphrase, typed for the batch"
        for_passphrase = process_items(self.gpg, [self.write("typed.txt", b"opened with the passphrase")],
                                       self.root / "exports", "encrypt", "password", None, threading.Event(),
                                       lambda *args: None, passphrases=[typed]).outputs[0]
        self._stop_agent()  # Nothing remembered, as after a restart.
        self.reset_dialog_count()
        items = [SourceItem(path, Path(path.name), path.stat().st_size) for path in (for_key, for_passphrase)]
        restored = process_items(self.gpg, items, self.root / "restored", "restore", "password", None,
                                 threading.Event(), lambda *args: self.progress.append(args), passphrases=[typed])
        self.assertEqual((restored.succeeded, restored.failed), (2, 0), self.progress)
        self.assertEqual((self.root / "restored" / "for-key.txt").read_bytes(), b"opened with the key")
        self.assertEqual((self.root / "restored" / "typed.txt").read_bytes(), b"opened with the passphrase")
        self.assertEqual(self.dialogs(), 1, "GnuPG asked once, for the key's passphrase only")


    def test_an_archive_works_when_gnupg_asks_for_the_passphrase(self):
        # Nothing then goes ahead of the archive on GnuPG's input, so this is a different path.
        items = [self.write("a.txt", b"first"), self.write("b.txt", b"second")]
        made = encrypt_archive(self.gpg, items, self.root / "exports", "Archive", "password", None,
                               threading.Event(), lambda *args: self.progress.append(args))
        self.assertEqual((made.succeeded, made.checked), (2, 0), self.progress)
        self.assertEqual(self.dialogs(), 1, "one archive, so one prompt")
        self.reset_dialog_count()
        restored = self.job([SourceItem(made.outputs[0], Path(made.outputs[0].name), 1)], "restored", "restore")
        self.assertEqual((restored.outputs[0] / "a.txt").read_bytes(), b"first")
        self.assertEqual((restored.outputs[0] / "b.txt").read_bytes(), b"second")
        self.assertEqual(self.dialogs(), 1)

    def test_cancelling_the_prompt_is_reported_as_a_cancel(self):
        self.answer_with(None)
        result = self.job([self.write("a.txt")], "exports", "encrypt")
        self.assertEqual((result.succeeded, result.failed), (0, 1))
        self.assertIn("cancelled", self.progress[-1][2])
        self.assertEqual([p for p in (self.root / "exports").rglob("*") if p.is_file()], [])

    def file_for_protected_key(self) -> SourceItem:
        """A file encrypted to a key whose private half has its own passphrase."""
        fingerprint = self.generate_key("Protected <protected@example.invalid>", passphrase=PASSPHRASE)
        encrypted = process_items(self.gpg, [self.write("a.txt", b"via private key")], self.root / "exports",
                                  "encrypt", "public-key", fingerprint, threading.Event(), lambda *args: None)
        # A new agent has nothing cached, exactly like after a restart.
        self._stop_agent()
        self.reset_dialog_count()
        return SourceItem(encrypted.outputs[0], Path("a.txt.gpg"), encrypted.outputs[0].stat().st_size)

    def test_private_key_passphrase_is_asked_through_pinentry(self):
        item = self.file_for_protected_key()
        result = self.job([item], "restored", "restore")
        self.assertEqual(result.outputs[0].read_bytes(), b"via private key", self.progress)
        self.assertEqual(self.dialogs(), 1)

    def test_wrong_private_key_passphrase_is_not_called_a_missing_key(self):
        item = self.file_for_protected_key()
        self.answer_with("not the right passphrase")
        result = self.job([item], "restored", "restore")
        self.assertEqual((result.succeeded, result.failed), (0, 1))
        self.assertIn("Wrong passphrase", self.progress[-1][2])

    def test_cancelling_the_private_key_prompt(self):
        item = self.file_for_protected_key()
        self.answer_with(None)
        result = self.job([item], "restored", "restore")
        self.assertEqual((result.succeeded, result.failed), (0, 1))
        self.assertIn("cancelled", self.progress[-1][2])

    def test_wrong_passphrase_at_the_prompt(self):
        encrypted = self.job([self.write("a.txt")], "exports", "encrypt").outputs[0]
        self.answer_with("not the right passphrase")
        item = SourceItem(encrypted, Path("a.txt.gpg"), encrypted.stat().st_size)
        result = self.job([item], "restored", "restore")
        self.assertEqual((result.succeeded, result.failed), (0, 1))
        self.assertIn("Wrong passphrase", self.progress[-1][2])


if __name__ == "__main__":
    unittest.main()
