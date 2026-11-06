"""The passphrase vault, against a real GnuPG."""

import json
import subprocess
import threading
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes.core import SourceItem, process_items
from mindyourownbytes.vault import (
    MIN_MASTER_LENGTH,
    Vault,
    VaultEntry,
    VaultError,
    WrongMasterPassphrase,
    generate_passphrase,
)
from tests.support import GpgTestCase

MASTER = "a long master passphrase"
OTHER_MASTER = "another long master passphrase"


class VaultCase(GpgTestCase):
    def setUp(self):
        super().setUp()
        self.path = self.root / "app" / "vault.gpg"
        self.vault = Vault(self.gpg, self.path)

    def reopen(self, master: str = MASTER) -> Vault:
        vault = Vault(self.gpg, self.path)
        vault.unlock(master)
        return vault

    def read_plaintext(self, path: Path, master: str = MASTER) -> dict:
        result = self.run_gpg("--pinentry-mode", "loopback", "--passphrase", master, "--no-symkey-cache",
                              "--output", "-", "--decrypt", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)


class LifecycleTests(VaultCase):
    def test_create_add_lock_and_reopen(self):
        self.vault.create(MASTER)
        self.vault.add("Taxes", "tax passphrase", note="2026 returns")
        self.vault.add("Μέρος ελληνικά", "κωδικός ✓ με κενά ")
        self.vault.lock()
        self.assertFalse(self.vault.unlocked)
        with self.assertRaises(VaultError):
            _ = self.vault.entries
        reopened = self.reopen()
        self.assertEqual([(e.label, e.passphrase, e.note) for e in reopened.entries], [
            ("Taxes", "tax passphrase", "2026 returns"),
            ("Μέρος ελληνικά", "κωδικός ✓ με κενά ", ""),
        ])

    def test_remove_and_rename_persist(self):
        self.vault.create(MASTER)
        first = self.vault.add("One", "passphrase one")
        second = self.vault.add("Two", "passphrase two")
        self.vault.rename(second.id, "Renamed")
        self.vault.remove(first.id)
        self.assertEqual([(e.label, e.passphrase) for e in self.reopen().entries],
                         [("Renamed", "passphrase two")])

    def test_rejects_duplicate_blank_and_truncatable_entries(self):
        self.vault.create(MASTER)
        self.vault.add("Taxes", "first")
        for label, passphrase in (("taxes", "x"), ("  ", "x"), ("New", ""), ("New", "line\nbreak")):
            with self.subTest(label=label, passphrase=passphrase), self.assertRaises((VaultError, ValueError)):
                self.vault.add(label, passphrase)
        self.assertEqual(len(self.reopen().entries), 1)

    def test_create_refuses_to_replace_an_existing_vault(self):
        self.vault.create(MASTER)
        before = self.path.read_bytes()
        with self.assertRaisesRegex(VaultError, "already exists"):
            Vault(self.gpg, self.path).create(OTHER_MASTER)
        self.assertEqual(self.path.read_bytes(), before)

    def test_master_passphrase_has_a_floor(self):
        with self.assertRaisesRegex(VaultError, "at least"):
            self.vault.create("x" * (MIN_MASTER_LENGTH - 1))
        self.assertFalse(self.path.exists())


class SecrecyTests(VaultCase):
    def test_wrong_master_is_rejected_and_stays_locked(self):
        self.vault.create(MASTER)
        self.vault.lock()
        with self.assertRaises(WrongMasterPassphrase):
            self.vault.unlock("definitely not the master")
        self.assertFalse(self.vault.unlocked)

    def test_no_plaintext_reaches_the_disk(self):
        self.vault.create(MASTER)
        self.vault.add("distinctive-label-canary", "distinctive-secret-canary")
        for path in self.path.parent.iterdir():
            content = path.read_bytes()
            self.assertNotIn(b"distinctive", content, path.name)
            self.assertNotIn(b"mindyourownbytes-vault", content, path.name)

    def test_uses_the_pinned_kdf(self):
        self.vault.create(MASTER)
        packets = self.packets(self.path, MASTER)
        self.assertRegex(packets, r"cipher 9\b")
        self.assertRegex(packets, r"s2k 3, hash 10\b")
        self.assertIn("count 65011712", packets)

    def test_secrets_do_not_appear_in_repr(self):
        entry = VaultEntry("Label", "secret-canary")
        self.assertNotIn("secret-canary", repr(entry))
        self.vault.create(MASTER)
        self.assertNotIn(MASTER, repr(self.vault))

    def test_master_is_not_left_cached_in_gpg_agent(self):
        self.vault.create(MASTER)
        # Deliberately without --no-symkey-cache: if the agent still held the
        # master, this probe would use it and succeed with no passphrase given.
        result = self.run_gpg("--pinentry-mode", "error", "--output", "-", "--decrypt", str(self.path))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")

    def test_generated_passphrases_are_long_and_unique(self):
        values = {generate_passphrase() for _ in range(200)}
        self.assertEqual(len(values), 200)
        self.assertTrue(all(len(value) == 35 for value in values))


class HostileFileTests(VaultCase):
    def test_unencrypted_file_cannot_plant_passphrases(self):
        # Without the DECRYPTION_OKAY check this would load with any "master".
        document = {"format": "mindyourownbytes-vault", "version": 1,
                    "entries": [{"label": "Planted", "passphrase": "attacker knows this"}]}
        source = self.root / "plant.json"
        source.write_text(json.dumps(document))
        self.path.parent.mkdir(parents=True)
        self.run_gpg("--store", "--output", str(self.path), str(source))
        with self.assertRaisesRegex(VaultError, "not encrypted"):
            self.vault.unlock("anything at all here")
        self.assertFalse(self.vault.unlocked)

    def test_tampered_vault_is_rejected(self):
        self.vault.create(MASTER)
        self.vault.lock()
        blob = bytearray(self.path.read_bytes())
        blob[-5] ^= 0xFF
        self.path.write_bytes(blob)
        with self.assertRaises(VaultError):
            self.vault.unlock(MASTER)
        self.assertFalse(self.vault.unlocked)

    def test_valid_encryption_of_invalid_content_is_rejected(self):
        for payload in (b"not json", b"[]", b'{"format":"other","version":1,"entries":[]}',
                        b'{"format":"mindyourownbytes-vault","version":1,"entries":[{"label":1}]}'):
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.unlink(missing_ok=True)
            self.run_gpg("--pinentry-mode", "loopback", "--passphrase", MASTER, "--symmetric",
                         "--output", str(self.path), input=payload)
            with self.subTest(payload=payload), self.assertRaisesRegex(VaultError, "not valid"):
                Vault(self.gpg, self.path).unlock(MASTER)

    def test_refuses_a_vault_from_a_newer_version(self):
        payload = json.dumps({"format": "mindyourownbytes-vault", "version": 999, "entries": []}).encode()
        self.path.parent.mkdir(parents=True)
        self.run_gpg("--pinentry-mode", "loopback", "--passphrase", MASTER, "--symmetric",
                     "--output", str(self.path), input=payload)
        with self.assertRaisesRegex(VaultError, "newer version"):
            self.vault.unlock(MASTER)


class DurabilityTests(VaultCase):
    def test_keeps_the_previous_version_as_a_backup(self):
        self.vault.create(MASTER)
        self.vault.add("First", "first passphrase")
        self.vault.add("Second", "second passphrase")
        backup = self.read_plaintext(self.vault.backup_path)
        self.assertEqual([entry["label"] for entry in backup["entries"]], ["First"])

    def test_failed_write_leaves_vault_and_memory_unchanged(self):
        self.vault.create(MASTER)
        self.vault.add("Kept", "kept passphrase")
        before = self.path.read_bytes()
        failing = patch("mindyourownbytes.vault.run_gpg_pipe", return_value=(2, b"", "gpg: disk full\n"))
        with failing, self.assertRaisesRegex(VaultError, "disk full"):
            self.vault.add("Lost", "lost passphrase")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual([entry.label for entry in self.vault.entries], ["Kept"])
        self.assertEqual([p.name for p in self.path.parent.iterdir() if p.suffix == ".tmp"], [])

    def test_gpg_timing_out_is_a_clean_error_and_changes_nothing(self):
        self.vault.create(MASTER)
        before = self.path.read_bytes()
        hung = patch("mindyourownbytes.vault.run_gpg_pipe", side_effect=subprocess.TimeoutExpired("gpg", 120))
        with hung, self.assertRaisesRegex(VaultError, "could not be saved"):
            self.vault.add("New", "new passphrase")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.vault.entries, [])

    def test_write_that_fails_verification_never_replaces_the_vault(self):
        self.vault.create(MASTER)
        before = self.path.read_bytes()
        corrupted = patch.object(Vault, "_decrypt", return_value=b"different bytes")
        with corrupted, self.assertRaisesRegex(VaultError, "verified"):
            self.vault.add("New", "new passphrase")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.vault.entries, [])

    def test_a_change_from_another_window_is_not_silently_lost(self):
        self.vault.create(MASTER)
        first_window = self.reopen()
        second_window = self.reopen()
        first_window.add("From first", "first window passphrase")
        with self.assertRaisesRegex(VaultError, "changed on disk"):
            second_window.add("From second", "second window passphrase")
        self.assertEqual([e.label for e in self.reopen().entries], ["From first"])


class ChangeMasterTests(VaultCase):
    def test_change_master(self):
        self.vault.create(MASTER)
        self.vault.add("Kept", "kept passphrase")
        self.vault.change_master(MASTER, OTHER_MASTER)
        self.assertEqual([e.label for e in self.reopen(OTHER_MASTER).entries], ["Kept"])
        with self.assertRaises(WrongMasterPassphrase):
            self.reopen(MASTER)

    def test_requires_the_current_master(self):
        self.vault.create(MASTER)
        with self.assertRaises(WrongMasterPassphrase):
            self.vault.change_master("this is not the current one", OTHER_MASTER)
        self.reopen(MASTER)

    def test_undeletable_old_backup_is_reported_and_new_master_still_applies(self):
        self.vault.create(MASTER)
        self.vault.add("One", "one passphrase")
        real_unlink = Path.unlink

        def refuse_backup(path, *args, **kwargs):
            if path == self.vault.backup_path:
                raise PermissionError(13, "in use")
            return real_unlink(path, *args, **kwargs)

        with patch("pathlib.Path.unlink", refuse_backup), self.assertRaisesRegex(VaultError, "delete it yourself"):
            self.vault.change_master(MASTER, OTHER_MASTER)
        self.vault.add("Two", "two passphrase")
        self.assertEqual(len(self.reopen(OTHER_MASTER).entries), 2)

    def test_no_copy_under_the_old_master_survives(self):
        self.vault.create(MASTER)
        self.vault.add("One", "one passphrase")
        self.assertTrue(self.vault.backup_path.exists())
        self.vault.change_master(MASTER, OTHER_MASTER)
        self.assertFalse(self.vault.backup_path.exists())


class NoLockInTests(VaultCase):
    def test_plain_gpg_reads_the_vault_without_this_app(self):
        self.vault.create(MASTER)
        self.vault.add("Taxes", "tax passphrase")
        document = self.read_plaintext(self.path)
        self.assertEqual(document["entries"][0]["passphrase"], "tax passphrase")

    def test_saved_passphrase_decrypts_files_and_so_does_plain_gpg(self):
        self.vault.create(MASTER)
        entry = self.vault.add("Taxes", generate_passphrase())
        source = self.root / "a.txt"
        source.write_bytes(b"secret file")
        job = process_items(self.gpg, [SourceItem(source, Path("a.txt"), 11)], self.root / "out", "encrypt",
                            "password", None, threading.Event(), lambda *a: None, passphrases=[entry.passphrase])
        result = self.run_gpg("--pinentry-mode", "loopback", "--passphrase", entry.passphrase, "--no-symkey-cache",
                              "--output", "-", "--decrypt", str(job.outputs[0]))
        self.assertEqual(result.stdout, b"secret file")
