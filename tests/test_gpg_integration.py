"""End-to-end behaviour against a real GnuPG, including hostile input."""

import os
import random
import threading
import time
import unittest
from pathlib import Path

from mindyourownbytes.core import (
    SourceItem,
    collect_files,
    gpg_version,
    list_public_keys,
    peek_protection,
    process_items,
)
from tests.support import GpgTestCase

PASSPHRASE = "correct horse battery staple"


class IntegrationCase(GpgTestCase):
    def setUp(self):
        super().setUp()
        self.progress = []

    def write(self, name: str, content: bytes = b"private test bytes\n") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def item(self, path: Path, relative: Path | None = None) -> SourceItem:
        return SourceItem(path, relative or Path(path.name), path.stat().st_size)

    def job(self, items, out, operation, method="password", fingerprint=None, **kwargs):
        return process_items(self.gpg, items, self.root / out, operation, method, fingerprint,
                             threading.Event(), lambda *args: self.progress.append(args), **kwargs)

    def encrypt(self, path: Path, out: str = "exports", passphrase: str = PASSPHRASE) -> Path:
        result = self.job([self.item(path)], out, "encrypt", passphrases=[passphrase])
        self.assertEqual((result.succeeded, result.failed), (1, 0), self.progress)
        return result.outputs[0]

    def assert_restore_rejected(self, path: Path, out: str, message: str, **kwargs) -> None:
        result = self.job([self.item(path)], out, "restore", **kwargs)
        self.assertEqual((result.succeeded, result.failed), (0, 1))
        self.assertRegex(self.progress[-1][2], message)
        leftovers = [p for p in (self.root / out).rglob("*") if p.is_file()]
        self.assertEqual(leftovers, [], "a rejected file must leave nothing behind")


class PassphraseRoundTripTests(IntegrationCase):
    def test_round_trip_restores_identical_bytes(self):
        content = os.urandom(300_000) + b"\r\n\x00\x1a tail"
        encrypted = self.encrypt(self.write("data.bin", content))
        self.assertNotIn(content[:64], encrypted.read_bytes())
        restored = self.job([self.item(encrypted)], "restored", "restore", passphrases=[PASSPHRASE])
        self.assertEqual(restored.outputs[0].read_bytes(), content)

    def test_empty_file_round_trips(self):
        # Regression: a size check rejected the correct, empty plaintext, so
        # every empty file in a folder backup failed to restore.
        encrypted = self.encrypt(self.write("__init__.py", b""))
        restored = self.job([self.item(encrypted)], "restored", "restore", passphrases=[PASSPHRASE])
        self.assertEqual((restored.succeeded, restored.failed), (1, 0), self.progress)
        self.assertEqual(restored.outputs[0].read_bytes(), b"")

    def test_unicode_names_and_passphrase(self):
        content = "δοκιμή".encode()
        folder = self.root / "Έγγραφα"
        self.write("Έγγραφα/φορολογικά 2026.txt", content)
        found = collect_files([folder], self.root / "exports", "encrypt")
        passphrase = "κωδικός με ελληνικά ✓"
        encrypted = self.job(found.items, "exports", "encrypt", passphrases=[passphrase])
        self.assertEqual(encrypted.outputs[0].name, "φορολογικά 2026.txt.gpg")
        restored = self.job([self.item(encrypted.outputs[0], Path("Έγγραφα") / encrypted.outputs[0].name)],
                            "restored", "restore", passphrases=[passphrase])
        self.assertEqual(restored.outputs[0].relative_to(self.root / "restored"),
                         Path("Έγγραφα/φορολογικά 2026.txt"))
        self.assertEqual(restored.outputs[0].read_bytes(), content)

    def test_long_filename_works_and_does_not_abort_the_batch(self):
        # Regression: the staging name embedded the original name, went over the
        # 255-character limit, and the resulting OSError killed the whole batch.
        try:
            long_name = self.write("L" * 225 + ".txt")
        except OSError:
            self.skipTest("this filesystem has a shorter path limit")
        normal = self.write("normal.txt")
        result = self.job([self.item(long_name), self.item(normal)], "exports", "encrypt",
                          passphrases=[PASSPHRASE])
        self.assertEqual(result.succeeded + result.failed, 2)
        self.assertIn(self.root / "exports" / "normal.txt.gpg", result.outputs)

    def test_second_export_never_overwrites_the_first(self):
        path = self.write("report.pdf")
        first = self.encrypt(path)
        original = first.read_bytes()
        second = self.encrypt(path)
        self.assertEqual(second.name, "report (2).pdf.gpg")
        self.assertEqual(first.read_bytes(), original)

    def test_produces_standard_openpgp_with_the_pinned_kdf(self):
        encrypted = self.encrypt(self.write("a.txt"))
        packets = self.packets(encrypted, PASSPHRASE)
        self.assertRegex(packets, r"cipher 9\b", "expected AES-256")
        self.assertRegex(packets, r"s2k 3, hash 10\b", "expected iterated S2K with SHA-512")
        self.assertIn("count 65011712", packets)
        # Passphrase mode promises the most widely readable format. If a future
        # GnuPG changes its default, this should fail so the promise gets revisited.
        # (Older GnuPG prints "mdc_method: 2" and newer prints "mdc: 2" for the same packet.)
        self.assertIn(":encrypted data packet:", packets, "expected the long-established RFC 4880 format")
        self.assertRegex(packets, r"mdc(_method)?: 2", "expected an MDC integrity check")

    def test_plain_gpg_can_decrypt_with_no_help_from_this_app(self):
        # The project's core promise: no lock-in.
        encrypted = self.encrypt(self.write("a.txt", b"readable forever"))
        out = self.root / "plain.txt"
        result = self.run_gpg("--pinentry-mode", "loopback", "--passphrase", PASSPHRASE,
                              "--output", str(out), "--decrypt", str(encrypted))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(out.read_bytes(), b"readable forever")


class PeekProtectionTests(IntegrationCase):
    """Only used to pre-select an option, but it should read real files correctly."""

    def test_recognizes_a_passphrase_file(self):
        self.assertEqual(peek_protection(self.encrypt(self.write("a.txt"))), "passphrase")

    def test_recognizes_a_public_key_file(self):
        fingerprint = self.generate_key()
        encrypted = self.job([self.item(self.write("a.txt"))], "exports", "encrypt", "public-key", fingerprint)
        self.assertEqual(peek_protection(encrypted.outputs[0]), "key")

    def test_anything_else_is_unknown(self):
        self.assertIsNone(peek_protection(self.write("text.gpg", b"plain text")))
        self.assertIsNone(peek_protection(self.write("empty.gpg", b"")))
        self.assertIsNone(peek_protection(self.root / "missing.gpg"))


class WrongSecretTests(IntegrationCase):
    def test_wrong_passphrase(self):
        encrypted = self.encrypt(self.write("a.txt"))
        self.assert_restore_rejected(encrypted, "r", "Wrong passphrase", passphrases=["nope"])

    def test_tries_each_saved_passphrase(self):
        encrypted = self.encrypt(self.write("a.txt", b"found it"))
        result = self.job([self.item(encrypted)], "r", "restore",
                          passphrases=["first wrong", "second wrong", PASSPHRASE])
        self.assertEqual(result.outputs[0].read_bytes(), b"found it")

    def test_reports_when_no_saved_passphrase_matches(self):
        encrypted = self.encrypt(self.write("a.txt"))
        self.assert_restore_rejected(encrypted, "r", "None of the saved passphrases",
                                     passphrases=["first wrong", "second wrong"])


class HostileInputTests(IntegrationCase):
    def test_unencrypted_replacement_is_not_accepted_as_a_backup(self):
        # Regression: this restored with no key or passphrase and reported
        # success, so whoever holds the storage could plant any content.
        fake = self.write("fake.txt", b"Attacker chosen content")
        forged = self.root / "invoice.pdf.gpg"
        self.assertEqual(self.run_gpg("--store", "--output", str(forged), str(fake)).returncode, 0)
        self.assert_restore_rejected(forged, "r", "not actually encrypted")

    def test_unencrypted_replacement_rejected_even_when_passphrase_supplied(self):
        fake = self.write("fake.txt", b"Attacker chosen content")
        forged = self.root / "invoice.pdf.gpg"
        self.run_gpg("--store", "--output", str(forged), str(fake))
        self.assert_restore_rejected(forged, "r", "not actually encrypted", passphrases=[PASSPHRASE])

    def test_any_damage_is_rejected_with_a_clear_message(self):
        # The same damage surfaces differently depending on where it falls, so
        # both kinds of content and many positions are covered. Seeded, so a
        # failure here can be reproduced exactly.
        chooser = random.Random(20261105)
        for label, content in (("random", chooser.randbytes(50_000)), ("compressible", b"hello world " * 17_000)):
            good = self.encrypt(self.write(f"{label}.bin", content)).read_bytes()
            for trial in range(10):
                blob = bytearray(good)
                if trial % 2:
                    blob = blob[:chooser.randrange(60, len(blob) - 1)]
                else:
                    blob[chooser.randrange(60, len(blob))] ^= chooser.randrange(1, 256)
                bad = self.write(f"{label}{trial}.bin.gpg", bytes(blob))
                with self.subTest(label=label, trial=trial):
                    self.assert_restore_rejected(bad, f"r{label}{trial}", "damaged|altered", passphrases=[PASSPHRASE])

    def test_garbage_is_rejected(self):
        # Random bytes occasionally parse as harmless packets, so the message
        # varies with the content. What must never vary is the rejection itself.
        for seed in range(10):
            garbage = self.write(f"garbage{seed}.pdf.gpg", random.Random(seed).randbytes(4096))
            with self.subTest(seed=seed):
                self.assert_restore_rejected(garbage, f"r{seed}", ".", passphrases=[PASSPHRASE])

    def test_damage_is_named_even_when_trying_several_passphrases(self):
        good = self.encrypt(self.write("a.bin", os.urandom(50_000))).read_bytes()
        blob = bytearray(good)
        blob[len(blob) // 2] ^= 0xFF
        bad = self.write("bad.bin.gpg", bytes(blob))
        self.assert_restore_rejected(bad, "r", "damaged|altered", passphrases=["wrong one", PASSPHRASE, "another"])

    def test_a_bad_file_does_not_stop_the_rest_of_the_batch(self):
        good = self.encrypt(self.write("good.txt", b"fine"))
        bad = self.write("bad.txt.gpg", os.urandom(512))
        result = self.job([self.item(bad), self.item(good)], "r", "restore", passphrases=[PASSPHRASE])
        self.assertEqual((result.succeeded, result.failed), (1, 1))

    def test_embedded_filename_cannot_choose_the_output_path(self):
        source = self.write("a.txt", b"x")
        evil = self.root / "evil.txt.gpg"
        self.run_gpg("--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--symmetric",
                     "--set-filename", "../../escaped.txt", "--output", str(evil), str(source))
        result = self.job([self.item(evil)], "r", "restore", passphrases=[PASSPHRASE])
        self.assertEqual(result.outputs[0], self.root / "r" / "evil.txt")
        self.assertFalse((self.root.parent / "escaped.txt").exists())
        self.assertFalse((self.root / "escaped.txt").exists())


class PublicKeyTests(IntegrationCase):
    def test_round_trip_with_own_key(self):
        fingerprint = self.generate_key()
        keys = list_public_keys(self.gpg)
        self.assertEqual([(key.fingerprint, key.has_secret) for key in keys], [(fingerprint, True)])
        content = b"%PDF-1.4\nprivate test bytes\n"
        path = self.write("document.pdf", content)
        encrypted = self.job([self.item(path)], "exports", "encrypt", "public-key", fingerprint)
        self.assertEqual((encrypted.succeeded, encrypted.failed), (1, 0), self.progress)
        self.assertNotIn(b"private test bytes", encrypted.outputs[0].read_bytes())
        restored = self.job([self.item(encrypted.outputs[0])], "restored", "restore", "public-key")
        self.assertEqual(restored.outputs[0].read_bytes(), content)

    def test_revoked_and_expired_keys_are_not_offered(self):
        keep = self.generate_key("Keep <keep@example.invalid>")
        revoked = self.generate_key("Revoked <revoked@example.invalid>")
        expired = self.generate_key("Expired <expired@example.invalid>", expire="seconds=1")
        certificate = (self.home / "openpgp-revocs.d" / f"{revoked}.rev").read_text(errors="replace")
        (self.root / "rev.asc").write_text(certificate.replace(":-----BEGIN", "-----BEGIN"))
        self.assertEqual(self.run_gpg("--import", str(self.root / "rev.asc")).returncode, 0)
        deadline = time.monotonic() + 10
        offered = [key.fingerprint for key in list_public_keys(self.gpg)]
        while expired in offered and time.monotonic() < deadline:
            time.sleep(0.25)
            offered = [key.fingerprint for key in list_public_keys(self.gpg)]
        self.assertIn(keep, offered)
        self.assertNotIn(revoked, offered)
        self.assertNotIn(expired, offered)

    def test_own_keys_are_listed_first_and_others_are_flagged(self):
        other_home = self.root / "other"
        other_home.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(other_home))
        self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key",
                     "Aaron Colleague <aaron@example.invalid>", "default", "default", "1y", env=env)
        exported = self.run_gpg("--export", env=env).stdout
        self.run_gpg("--import", input=exported)
        own = self.generate_key("Zed Myself <zed@example.invalid>")
        keys = list_public_keys(self.gpg)
        self.assertEqual(keys[0].fingerprint, own)
        self.assertTrue(keys[0].has_secret)
        self.assertFalse(keys[1].has_secret)

    def test_escaped_uid_is_decoded(self):
        self.generate_key("Νίκος: Test <colon@example.invalid>")
        self.assertEqual(list_public_keys(self.gpg)[0].uid, "Νίκος: Test <colon@example.invalid>")

    def test_uncertified_foreign_key_fails_safely_with_a_clear_message(self):
        other_home = self.root / "other"
        other_home.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(other_home))
        self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key",
                     "Colleague <c@example.invalid>", "default", "default", "1y", env=env)
        self.run_gpg("--import", input=self.run_gpg("--export", env=env).stdout)
        foreign = list_public_keys(self.gpg)[0]
        result = self.job([self.item(self.write("a.txt"))], "exports", "encrypt", "public-key", foreign.fingerprint)
        self.assertEqual((result.succeeded, result.failed), (0, 1))
        self.assertIn("refused this key", self.progress[-1][2])

    def test_post_quantum_key_round_trip(self):
        version = gpg_version(self.gpg)
        if version is None or version < (2, 5, 0):
            self.skipTest("Kyber keys need GnuPG 2.5 or later")
        fingerprint = self.generate_key("Quantum <quantum@example.invalid>", algorithm="pqc")
        self.assertEqual([key.fingerprint for key in list_public_keys(self.gpg)], [fingerprint])
        encrypted = self.job([self.item(self.write("a.txt", b"harvest now, decrypt later"))], "exports",
                             "encrypt", "public-key", fingerprint)
        self.assertEqual((encrypted.succeeded, encrypted.failed), (1, 0), self.progress)
        self.assertRegex(self.packets(encrypted.outputs[0]), r"pubkey enc packet: version \d+, algo 8\b",
                         "expected a Kyber recipient")
        restored = self.job([self.item(encrypted.outputs[0])], "restored", "restore", "public-key")
        self.assertEqual(restored.outputs[0].read_bytes(), b"harvest now, decrypt later")

    def signed_by_someone_else(self, tamper: bool = False) -> Path:
        """A file signed by an outside key, like Kleopatra's sign-and-encrypt produces."""
        fingerprint = self.generate_key("Me <me@example.invalid>")
        my_public_key = self.run_gpg("--export", fingerprint).stdout
        sender_home = self.root / "sender"
        sender_home.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(sender_home))
        self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key",
                     "Sender <sender@example.invalid>", "default", "default", "1y", env=env)
        self.run_gpg("--import", input=my_public_key, env=env)
        output = self.root / "signed.txt.gpg"
        self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--trust-model", "always", "--sign",
                     "--encrypt", "--recipient", fingerprint, "--output", str(output),
                     str(self.write("signed.txt")), env=env)
        return output

    def test_unverifiable_signature_is_not_described_as_damage(self):
        self.assert_restore_rejected(self.signed_by_someone_else(), "r", "signed by a key you don't have")

    def test_missing_private_key_gives_a_clear_message(self):
        fingerprint = self.generate_key()
        encrypted = self.job([self.item(self.write("a.txt"))], "exports", "encrypt", "public-key", fingerprint)
        self.run_gpg("--yes", "--delete-secret-keys", fingerprint)
        if any(key.has_secret for key in list_public_keys(self.gpg)):
            self.skipTest("this GnuPG will not delete a secret key in batch mode")
        self.assert_restore_rejected(encrypted.outputs[0], "r", "private key")


class NothingLingersTests(IntegrationCase):
    def test_passphrase_never_appears_in_output_files(self):
        encrypted = self.encrypt(self.write("a.txt"), passphrase="distinctive-canary-passphrase")
        self.assertNotIn(b"distinctive-canary-passphrase", encrypted.read_bytes())

    def test_only_the_final_file_remains_after_success(self):
        self.encrypt(self.write("a.txt"))
        names = [p.name for p in (self.root / "exports").iterdir()]
        self.assertEqual(names, ["a.txt.gpg"])


if __name__ == "__main__":
    unittest.main()
