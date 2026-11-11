"""End-to-end behaviour against a real GnuPG, including hostile input."""

import os
import random
import re
import shutil
import subprocess
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes import archive, core
from mindyourownbytes.core import (
    CHECKED,
    CIPHERS,
    READY,
    UNPACKED,
    SourceItem,
    available_ciphers,
    collect_files,
    encrypt_archive,
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


class AlgorithmChoiceTests(IntegrationCase):
    def offered(self):
        ciphers = available_ciphers(self.gpg)
        if os.environ.get("MYOB_REQUIRE_GPG"):
            # GnuPG's own builds and CI's have them all, so losing one there is a bug worth seeing.
            self.assertEqual(ciphers, CIPHERS)
        return ciphers

    def encrypt_with(self, cipher, content: bytes = b"private test bytes\n") -> Path:
        path = self.write(f"{cipher.name}.bin", content)
        result = self.job([self.item(path)], f"exports-{cipher.name}", "encrypt", passphrases=[PASSPHRASE],
                          cipher=cipher.name)
        self.assertEqual((result.succeeded, result.failed), (1, 0), self.progress)
        return result.outputs[0]

    def test_each_algorithm_keeps_the_same_strong_settings_and_format(self):
        for cipher in self.offered():
            with self.subTest(cipher.label):
                packets = self.packets(self.encrypt_with(cipher), PASSPHRASE)
                self.assertRegex(packets, rf"symkey enc packet: version \d+, cipher {cipher.packet_id}\b")
                self.assertRegex(packets, r"s2k 3, hash 10\b", "expected iterated S2K with SHA-512")
                self.assertIn("count 65011712", packets)
                self.assertIn(":encrypted data packet:", packets, "expected the long-established RFC 4880 format")
                self.assertRegex(packets, r"mdc(_method)?: 2", "expected an MDC integrity check")

    def test_each_algorithm_restores_here_and_with_plain_gpg(self):
        content = os.urandom(300_000)
        for cipher in self.offered():
            with self.subTest(cipher.label):
                encrypted = self.encrypt_with(cipher, content)
                self.assertNotIn(content[:64], encrypted.read_bytes())
                restored = self.job([self.item(encrypted)], f"restored-{cipher.name}", "restore",
                                    passphrases=[PASSPHRASE])
                self.assertEqual(restored.outputs[0].read_bytes(), content)
                plain = self.root / f"plain-{cipher.name}.bin"
                result = self.run_gpg("--pinentry-mode", "loopback", "--passphrase", PASSPHRASE,
                                      "--output", str(plain), "--decrypt", str(encrypted))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(plain.read_bytes(), content)

    def test_each_algorithm_refuses_a_wrong_passphrase_and_damage(self):
        for cipher in self.offered():
            with self.subTest(cipher.label):
                encrypted = self.encrypt_with(cipher, os.urandom(50_000))
                self.assert_restore_rejected(encrypted, f"wrong-{cipher.name}", "Wrong passphrase",
                                             passphrases=["nope"])
                blob = bytearray(encrypted.read_bytes())
                blob[len(blob) // 2] ^= 0xFF
                bad = self.write(f"bad-{cipher.name}.bin.gpg", bytes(blob))
                self.assert_restore_rejected(bad, f"bad-{cipher.name}", "damaged|altered", passphrases=[PASSPHRASE])

    def test_the_list_agrees_with_what_gnupg_says_about_itself(self):
        # Read another way, in case the list has a bug that makes it quietly offer less.
        version = self.run_gpg("--version").stdout.decode(errors="replace")
        expected = [cipher for cipher in CIPHERS if re.search(rf"\b{cipher.name}\b", version)]
        self.assertEqual(available_ciphers(self.gpg), tuple(expected))

    def test_a_cipher_disabled_in_gpg_conf_is_not_offered(self):
        (self.home / "gpg.conf").write_text("disable-cipher-algo TWOFISH\n", encoding="utf-8")
        self.assertNotIn("TWOFISH", [cipher.name for cipher in available_ciphers(self.gpg)])


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
        keys = list_public_keys(self.gpg)
        self.assertEqual([key.fingerprint for key in keys], [fingerprint])
        self.assertEqual(keys[0].algorithm, "Kyber-768 (post-quantum)")
        encrypted = self.job([self.item(self.write("a.txt", b"harvest now, decrypt later"))], "exports",
                             "encrypt", "public-key", fingerprint)
        self.assertEqual((encrypted.succeeded, encrypted.failed), (1, 0), self.progress)
        self.assertRegex(self.packets(encrypted.outputs[0]), r"pubkey enc packet: version \d+, algo 8\b",
                         "expected a Kyber recipient")
        restored = self.job([self.item(encrypted.outputs[0])], "restored", "restore", "public-key")
        self.assertEqual(restored.outputs[0].read_bytes(), b"harvest now, decrypt later")

    def test_key_list_names_the_kind_of_key_files_really_get_encrypted_to(self):
        fingerprint = self.generate_key()
        algorithm = list_public_keys(self.gpg)[0].algorithm
        # GnuPG 2.4 and later make Curve25519 keys by default, and older versions RSA.
        self.assertRegex(algorithm, r"^(Curve25519|RSA-\d+)$")
        encrypted = self.job([self.item(self.write("a.txt"))], "exports", "encrypt", "public-key", fingerprint)
        expected = "1" if algorithm.startswith("RSA") else "18"
        self.assertRegex(self.packets(encrypted.outputs[0]), rf"pubkey enc packet: version \d+, algo {expected}\b")

    def test_key_list_follows_a_post_quantum_subkey_added_to_an_older_key(self):
        version = gpg_version(self.gpg)
        if version is None or version < (2, 5, 0):
            self.skipTest("Kyber keys need GnuPG 2.5 or later")
        fingerprint = self.generate_key()
        time.sleep(1.1)  # Timestamps are in seconds, and a tie would keep the older subkey.
        added = self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-add-key",
                             fingerprint, "pqc", "encr", "1y")
        self.assertEqual(added.returncode, 0, added.stderr)
        self.assertEqual(list_public_keys(self.gpg)[0].algorithm, "Kyber-768 (post-quantum)")
        encrypted = self.job([self.item(self.write("a.txt"))], "exports", "encrypt", "public-key", fingerprint)
        self.assertRegex(self.packets(encrypted.outputs[0]), r"pubkey enc packet: version \d+, algo 8\b")

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


class CheckAfterEncryptingTests(IntegrationCase):
    """People may delete an original once its copy is reported as encrypted, so that has to be true.

    ``on_checking`` runs after a file is encrypted and before it is checked, which is exactly
    where a faulty disk or another program would have to interfere.
    """

    def encrypt_job(self, path: Path, out: str = "exports", cancel: threading.Event | None = None, **options):
        options.setdefault("passphrases", [PASSPHRASE])
        return process_items(self.gpg, [self.item(path)], self.root / out, "encrypt", "password", None,
                             cancel or threading.Event(), lambda *args: self.progress.append(args), **options)

    def staged(self, out: str = "exports") -> Path:
        return next((self.root / out).glob(".myob-*.partial"))

    def assert_refused(self, result, out: str, message: str) -> None:
        self.assertEqual((result.succeeded, result.failed, result.checked, result.outputs), (0, 1, 0, ()),
                         self.progress)
        self.assertRegex(self.progress[-1][2], message)
        left = [p for p in (self.root / out).rglob("*") if p.is_file()]
        self.assertEqual(left, [], "a copy that fails its check must leave nothing behind")

    def refused_after(self, spoil, message: str, content: bytes = b"private test bytes\n" * 500) -> None:
        """Encrypt, spoil the new file just before its check, and expect the check to refuse it."""
        source = self.write("a.bin", content)
        result = self.encrypt_job(source, on_checking=lambda _index: spoil(self.staged()))
        self.assert_refused(result, "exports", message)
        self.assertEqual(source.read_bytes(), content, "the original must never be touched")

    def test_a_good_file_is_checked_and_says_so(self):
        seen = []
        result = self.encrypt_job(self.write("a.txt"), on_checking=seen.append)
        self.assertEqual((result.succeeded, result.failed, result.checked), (1, 0, 1), self.progress)
        self.assertEqual(seen, [0])
        self.assertEqual(self.progress[-1][2], CHECKED)
        self.assertEqual([p.name for p in (self.root / "exports").iterdir()], ["a.txt.gpg"])

    def test_every_algorithm_is_checked(self):
        content = os.urandom(100_000)
        for cipher in available_ciphers(self.gpg):
            with self.subTest(cipher.label):
                result = self.encrypt_job(self.write(f"{cipher.name}.bin", content), f"exports-{cipher.name}",
                                          cipher=cipher.name)
                self.assertEqual((result.succeeded, result.checked), (1, 1), self.progress)

    def test_empty_unicode_and_larger_files_are_checked_and_still_restore(self):
        cases = (("empty.txt", b""), ("Έγγραφα/φορολογικά 2026 résumé.txt", "δοκιμή".encode()),
                 ("larger.bin", os.urandom(20_000_000) + b"\r\n\x00\x1a tail\n"))
        for name, content in cases:
            with self.subTest(name):
                source = self.write(name, content)
                result = self.encrypt_job(source, f"exports-{len(content)}")
                self.assertEqual((result.succeeded, result.checked), (1, 1), self.progress)
                restored = self.job([self.item(result.outputs[0])], f"restored-{len(content)}", "restore",
                                    passphrases=[PASSPHRASE])
                self.assertEqual(restored.outputs[0].read_bytes(), content)

    def test_turned_off_nothing_is_checked(self):
        seen = []
        result = self.encrypt_job(self.write("a.txt"), verify=False, on_checking=seen.append)
        self.assertEqual((result.succeeded, result.checked, seen), (1, 0, []))
        self.assertEqual(self.progress[-1][2], READY)

    def test_files_for_a_key_are_encrypted_but_not_checked(self):
        fingerprint = self.generate_key()
        seen = []
        with patch("mindyourownbytes.core.run_gpg_hashed") as check:
            result = process_items(self.gpg, [self.item(self.write("a.txt"))], self.root / "exports", "encrypt",
                                   "public-key", fingerprint, threading.Event(),
                                   lambda *args: self.progress.append(args), on_checking=seen.append)
        self.assertEqual((result.succeeded, result.checked, seen), (1, 0, []), self.progress)
        self.assertEqual(self.progress[-1][2], READY)
        check.assert_not_called()

    def test_a_restore_is_never_checked_this_way(self):
        encrypted = self.encrypt(self.write("a.txt"))
        with patch("mindyourownbytes.core.run_gpg_hashed") as check:
            restored = self.job([self.item(encrypted)], "restored", "restore", passphrases=[PASSPHRASE])
        self.assertEqual((restored.succeeded, restored.checked), (1, 0))
        check.assert_not_called()

    def test_a_copy_damaged_before_its_check_is_refused(self):
        def flip_the_middle(staged: Path) -> None:
            blob = bytearray(staged.read_bytes())
            blob[len(blob) // 2] ^= 0xFF
            staged.write_bytes(bytes(blob))

        self.refused_after(flip_the_middle, "^Check failed: GnuPG couldn't decrypt", os.urandom(50_000))

    def test_damage_that_leaves_the_content_readable_is_still_refused(self):
        # Only the integrity check at the very end is hit. GnuPG still writes every byte of the
        # original before it objects, so comparing content alone would accept this file.
        def flip_the_end(staged: Path) -> None:
            blob = bytearray(staged.read_bytes())
            blob[-1] ^= 0xFF
            staged.write_bytes(bytes(blob))

        self.refused_after(flip_the_end, "^Check failed: GnuPG couldn't decrypt", os.urandom(50_000))

    def test_a_valid_copy_of_something_else_is_refused(self):
        # GnuPG is entirely happy with this file. Only comparing it with the original can tell.
        other = self.encrypt(self.write("other.txt", b"not the original"), out="elsewhere")
        self.refused_after(lambda staged: shutil.copyfile(other, staged), "didn't give back the original")

    def test_a_copy_that_is_not_encrypted_is_refused_even_with_the_right_content(self):
        content = b"private test bytes\n" * 500
        plain = self.write("plain.bin", content)
        stored = self.root / "stored.gpg"
        self.assertEqual(self.run_gpg("--store", "--output", str(stored), str(plain)).returncode, 0)
        self.refused_after(lambda staged: shutil.copyfile(stored, staged), "isn't actually encrypted", content)

    def test_a_copy_gnupg_complains_about_is_refused_even_if_it_decrypts(self):
        # GnuPG decrypts this, says DECRYPTION_OKAY, writes the right bytes, and then fails on what follows.
        content = b"tiny file\n"
        good = self.encrypt(self.write("tiny.txt", content), out="elsewhere")
        junk = self.write("junk/tiny.txt.gpg", good.read_bytes() + bytes(64))
        if self.job([self.item(junk)], "calibrate", "restore", passphrases=[PASSPHRASE]).succeeded:
            self.skipTest("this GnuPG ignores bytes after the end of a file")

        def append_zeros(staged: Path) -> None:
            with staged.open("ab") as file:
                file.write(bytes(64))

        self.refused_after(append_zeros, "^Check failed: GnuPG couldn't decrypt", content)

    def test_an_original_that_changes_meanwhile_is_reported_as_changed_not_damaged(self):
        source = self.write("a.txt", b"first version")
        result = self.encrypt_job(source, on_checking=lambda _index: source.write_bytes(b"second version, longer"))
        self.assert_refused(result, "exports", "^The original changed")
        self.assertNotRegex(self.progress[-1][2], "damaged|Check failed")

    def test_an_original_deleted_meanwhile_is_reported_as_gone(self):
        source = self.write("a.txt", b"soon gone")
        result = self.encrypt_job(source, on_checking=lambda _index: source.unlink())
        self.assert_refused(result, "exports", "^The original is gone")

    def test_a_change_that_hides_its_traces_is_still_refused(self):
        # Same size and same time, so nothing says the file changed. Its content still decides.
        source = self.write("a.txt", b"first version")

        def rewrite_quietly(_index: int) -> None:
            status = source.stat()
            with source.open("r+b") as file:
                file.write(b"FIRST")
            os.utime(source, ns=(status.st_atime_ns, status.st_mtime_ns))

        result = self.encrypt_job(source, on_checking=rewrite_quietly)
        self.assert_refused(result, "exports", "didn't give back the original")

    def test_a_refused_file_does_not_stop_the_rest_and_can_be_tried_again(self):
        first, second = self.write("first.txt", b"one"), self.write("second.txt", b"two")

        def spoil_only_the_first(index: int) -> None:
            if index == 0:
                self.staged().write_bytes(b"not an OpenPGP file")

        items = [self.item(first), self.item(second)]
        result = self.job(items, "exports", "encrypt", passphrases=[PASSPHRASE], on_checking=spoil_only_the_first)
        self.assertEqual((result.succeeded, result.failed, result.checked), (1, 1, 1), self.progress)
        self.assertEqual([p.name for p in (self.root / "exports").iterdir()], ["second.txt.gpg"])
        again = self.job(items[:1], "exports", "encrypt", passphrases=[PASSPHRASE])
        self.assertEqual((again.succeeded, again.checked), (1, 1), self.progress)
        self.assertEqual(again.outputs[0].name, "first.txt.gpg")

    def test_cancelling_as_the_check_starts_stops_it_and_keeps_nothing(self):
        cancel = threading.Event()
        result = self.encrypt_job(self.write("a.bin", os.urandom(1_000_000)), cancel=cancel,
                                  on_checking=lambda _index: cancel.set())
        self.assertEqual((result.succeeded, result.failed, result.cancelled, result.outputs), (0, 0, True, ()))
        self.assertEqual(self.progress[-1][2], "Cancelled")
        self.assertEqual([p for p in (self.root / "exports").rglob("*") if p.is_file()], [])

    def test_cancelling_while_the_original_is_read_again_stops_it(self):
        cancel = threading.Event()
        real = core.run_gpg_hashed

        def decrypt_then_cancel(*args):
            answer = real(*args)
            cancel.set()
            return answer

        with patch("mindyourownbytes.core.run_gpg_hashed", side_effect=decrypt_then_cancel):
            result = self.encrypt_job(self.write("a.bin", os.urandom(1_000_000)), cancel=cancel)
        self.assertEqual((result.succeeded, result.cancelled, result.outputs), (0, True, ()))
        self.assertEqual([p for p in (self.root / "exports").rglob("*") if p.is_file()], [])

    def test_the_passphrase_never_reaches_a_command_line_and_no_readable_copy_is_written(self):
        commands = []
        real = subprocess.Popen

        def recording(argv, *args, **kwargs):
            commands.append([str(part) for part in argv])
            return real(argv, *args, **kwargs)

        canary = "distinctive-canary-passphrase"
        content = b"distinctive-canary-content " * 4000
        source = self.write("originals/a.txt", content)
        with patch("mindyourownbytes.core.subprocess.Popen", side_effect=recording):
            result = self.encrypt_job(source, passphrases=[canary])
        self.assertEqual((result.succeeded, result.checked), (1, 1), self.progress)
        decrypting = [argv for argv in commands if "--decrypt" in argv]
        self.assertEqual(len(decrypting), 1, "the check should decrypt exactly once")
        self.assertEqual(decrypting[0][decrypting[0].index("--output") + 1], "-", "never to a file")
        self.assertIn("--no-symkey-cache", decrypting[0])
        for argv in commands:
            self.assertNotIn(canary, " ".join(argv))
        holding_content = [path for path in self.root.rglob("*") if path.is_file() and self.home not in path.parents
                           and path != source and b"distinctive-canary-content" in path.read_bytes()]
        self.assertEqual(holding_content, [])
        self.assertEqual(list(self.root.rglob("*.partial")), [])

    def test_a_gnupg_setting_that_changes_line_endings_is_caught(self):
        # With "textmode" in gpg.conf, GnuPG encrypts and decrypts without complaint, but the file
        # that comes back differs: a real way to get a copy that isn't the original.
        (self.home / "gpg.conf").write_text("textmode\n", encoding="utf-8")
        content = b"one\ntwo\r\nthree\n"
        source = self.write("notes.txt", content)
        result = self.encrypt_job(source)
        self.assert_refused(result, "exports", "didn't give back the original")
        unchecked = self.encrypt_job(source, "unchecked", verify=False)
        restored = self.job([self.item(unchecked.outputs[0])], "restored", "restore", passphrases=[PASSPHRASE])
        self.assertNotEqual(restored.outputs[0].read_bytes(), content, "the check was right to refuse it")

    def test_a_newer_file_format_passes_the_check(self):
        # OCB files have no separate integrity status, so the check must not wait for one.
        version = gpg_version(self.gpg)
        if version is None or version < (2, 4, 0):
            self.skipTest("force-ocb needs GnuPG 2.4 or later")
        (self.home / "gpg.conf").write_text("force-ocb\n", encoding="utf-8")
        result = self.encrypt_job(self.write("a.bin", os.urandom(50_000)))
        self.assertEqual((result.succeeded, result.checked), (1, 1), self.progress)
        self.assertIn("aead", self.packets(result.outputs[0], PASSPHRASE))


class ArchiveTests(IntegrationCase):
    """A whole folder in one encrypted archive, which hides the names inside."""

    FILES = {
        "divorce-settlement.pdf": b"%PDF-1.4 " + bytes(range(256)) * 400,
        "receipts/Τεστ résumé.txt": "δοκιμή\r\n".encode(),
        "receipts/empty.txt": b"",
    }

    def folder(self, name: str = "Taxes 2026") -> Path:
        for relative, content in self.FILES.items():
            self.write(f"{name}/{relative}", content)
        return self.root / name

    def pack(self, sources, out="exports", name="Archive 2026-11-10", method="password", fingerprint=None,
             cancel=None, **options):
        if method == "password":
            options.setdefault("passphrases", [PASSPHRASE])
        items = collect_files(sources, self.root / out, "encrypt").items
        return encrypt_archive(self.gpg, items, self.root / out, name, method, fingerprint,
                               cancel or threading.Event(), lambda *args: self.progress.append(args), **options)

    def restore(self, encrypted: Path, out="restored", **options):
        options.setdefault("passphrases", [PASSPHRASE])
        return self.job([self.item(encrypted)], out, "restore", **options)

    def contents(self, folder: Path) -> dict[str, bytes]:
        return {p.relative_to(folder).as_posix(): p.read_bytes() for p in folder.rglob("*") if p.is_file()}

    def assert_nothing_kept(self, result, out="exports"):
        self.assertEqual((result.succeeded, result.outputs, result.checked), (0, (), 0), self.progress)
        left = list((self.root / out).rglob("*")) if (self.root / out).exists() else []
        self.assertEqual(left, [], "a failed archive must leave nothing behind")

    def test_a_file_and_a_folder_with_the_same_name_both_come_back(self):
        # Regression: a file called "docs" and a folder called "docs", from different places, went in
        # under clashing names. Both were reported as packed and checked, but restoring the archive failed,
        # because one name in it was both a file and a folder.
        file = self.write("one place/docs", b"a file called docs")
        self.write("another place/docs/inside.txt", b"inside the folder")
        folder = self.root / "another place" / "docs"
        for number, (sources, expected) in enumerate((
            ([file, folder], {"docs": b"a file called docs", "docs (2)/inside.txt": b"inside the folder"}),
            ([folder, file], {"docs/inside.txt": b"inside the folder", "docs (2)": b"a file called docs"}),
        )):
            with self.subTest(list(expected)):
                made = self.pack(sources, out=f"exports {number}")
                self.assertEqual((made.succeeded, made.failed, made.checked), (2, 0, 2), self.progress)
                restored = self.restore(made.outputs[0], out=f"restored {number}")
                self.assertEqual(restored.succeeded, 1, self.progress)
                self.assertEqual(self.contents(restored.outputs[0]), expected)

    def test_a_folder_goes_into_one_file_that_hides_its_names_and_comes_back_whole(self):
        made = self.pack([self.folder()])
        self.assertEqual((made.succeeded, made.failed, made.checked), (3, 0, 3), self.progress)
        self.assertEqual([p.name for p in (self.root / "exports").iterdir()], ["Archive 2026-11-10.zip.gpg"])
        self.assertEqual([entry[2] for entry in self.progress], [CHECKED] * 3)
        ciphertext = made.outputs[0].read_bytes()
        for hidden in ("divorce", "receipts", "Taxes", "résumé", "Τεστ", "empty.txt"):
            self.assertNotIn(hidden.encode(), ciphertext)
        self.progress = []
        restored = self.restore(made.outputs[0])
        self.assertEqual((restored.succeeded, restored.failed), (1, 0), self.progress)
        self.assertEqual(self.progress[-1][2], UNPACKED)
        self.assertEqual(restored.outputs[0], self.root / "restored" / "Archive 2026-11-10")
        self.assertEqual(self.contents(restored.outputs[0] / "Taxes 2026"), self.FILES)
        self.assertEqual([p.name for p in (self.root / "restored").iterdir()], ["Archive 2026-11-10"],
                         "the decrypted zip must not be left behind")

    def test_every_algorithm_makes_a_working_archive(self):
        folder = self.folder()
        for cipher in available_ciphers(self.gpg):
            with self.subTest(cipher.label):
                made = self.pack([folder], f"exports-{cipher.name}", cipher=cipher.name)
                self.assertEqual(made.checked, 3, self.progress)
                self.assertRegex(self.packets(made.outputs[0], PASSPHRASE),
                                 rf"symkey enc packet: version \d+, cipher {cipher.packet_id}\b")
                restored = self.restore(made.outputs[0], f"restored-{cipher.name}")
                self.assertEqual(self.contents(restored.outputs[0] / "Taxes 2026"), self.FILES)

    def test_keeps_the_same_strong_settings(self):
        packets = self.packets(self.pack([self.folder()]).outputs[0], PASSPHRASE)
        self.assertRegex(packets, r"s2k 3, hash 10\b")
        self.assertIn("count 65011712", packets)
        self.assertRegex(packets, r"mdc(_method)?: 2")

    def test_plain_gpg_and_any_zip_tool_open_it_without_this_app(self):
        made = self.pack([self.folder()])
        plain = self.root / "plain.zip"
        result = self.run_gpg("--pinentry-mode", "loopback", "--passphrase", PASSPHRASE,
                              "--output", str(plain), "--decrypt", str(made.outputs[0]))
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(plain) as opened:
            self.assertEqual({name.removeprefix("Taxes 2026/"): opened.read(name) for name in opened.namelist()},
                             self.FILES)
        if os.name == "nt":
            # Explorer's own zip support, which is what a double-click uses.
            out = self.root / "explorer"
            out.mkdir()
            shell = ("$s = New-Object -ComObject Shell.Application; "
                     f"$s.NameSpace('{out}').CopyHere($s.NameSpace('{plain}').Items(), 1556)")
            subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", shell],
                           capture_output=True, timeout=120, check=False)
            deadline = time.monotonic() + 20
            while len(self.contents(out)) < len(self.FILES) and time.monotonic() < deadline:
                time.sleep(0.2)
            self.assertEqual(self.contents(out / "Taxes 2026"), self.FILES)

    def test_files_from_several_places_go_in_with_their_folders(self):
        self.folder("One/Docs")
        self.folder("Two/Docs")
        single = self.write("loose.txt", b"loose")
        made = self.pack([self.root / "One" / "Docs", self.root / "Two" / "Docs", single])
        self.assertEqual(made.succeeded, 7, self.progress)
        restored = self.restore(made.outputs[0]).outputs[0]
        names = sorted(self.contents(restored))
        self.assertIn("loose.txt", names)
        self.assertIn("Docs/divorce-settlement.pdf", names)
        self.assertIn("Docs/divorce-settlement (2).pdf", names, "two folders with one name mustn't collide")

    def test_a_second_archive_or_restore_never_overwrites_the_first(self):
        folder = self.folder()
        first = self.pack([folder]).outputs[0]
        second = self.pack([folder]).outputs[0]
        self.assertEqual(second.name, "Archive 2026-11-10 (2).zip.gpg")
        once = self.restore(first).outputs[0]
        twice = self.restore(first).outputs[0]
        self.assertEqual((once.name, twice.name), ("Archive 2026-11-10", "Archive 2026-11-10 (2)"))

    def test_a_key_works_too_but_is_not_checked(self):
        fingerprint = self.generate_key()
        made = self.pack([self.folder()], method="public-key", fingerprint=fingerprint)
        self.assertEqual((made.succeeded, made.checked), (3, 0), self.progress)
        self.assertEqual(self.progress[-1][2], READY)
        restored = self.restore(made.outputs[0], method="public-key", passphrases=[])
        self.assertEqual(self.contents(restored.outputs[0] / "Taxes 2026"), self.FILES)

    def test_with_the_check_off_nothing_is_checked(self):
        made = self.pack([self.folder()], verify=False)
        self.assertEqual((made.succeeded, made.checked), (3, 0))

    def test_an_archive_damaged_before_its_check_is_not_kept(self):
        def spoil() -> None:
            staged = next((self.root / "exports").glob(".myob-*.partial"))
            data = bytearray(staged.read_bytes())
            data[len(data) // 2] ^= 0xFF
            staged.write_bytes(bytes(data))

        result = self.pack([self.folder()], on_checking=spoil)
        self.assert_nothing_kept(result)
        self.assertEqual(result.failed, 3)
        self.assertRegex(self.progress[-1][2], "^Check failed: GnuPG couldn't decrypt the archive")

    def test_a_valid_archive_of_something_else_is_not_kept(self):
        other = self.pack([self.write("other.txt", b"something else")], out="elsewhere").outputs[0]

        def swap() -> None:
            shutil.copyfile(other, next((self.root / "exports").glob(".myob-*.partial")))

        self.progress = []
        result = self.pack([self.folder()], on_checking=swap)
        self.assert_nothing_kept(result)
        self.assertRegex(self.progress[-1][2], "didn't give back what was packed")

    def test_an_original_that_changes_while_packing_is_reported_as_changed(self):
        folder = self.folder()
        changing = folder / "divorce-settlement.pdf"

        def change_the_first(index: int) -> None:
            if index == 1:
                changing.write_bytes(b"a newer version, saved meanwhile")

        result = self.pack([folder], on_packing=change_the_first)
        self.assert_nothing_kept(result)
        self.assertRegex(self.progress[-1][2], "^The original changed: something wrote to Taxes 2026/divorce")

    def test_an_original_that_vanishes_while_packing_is_reported_as_gone(self):
        folder = self.folder()
        doomed = folder / "receipts" / "empty.txt"
        result = self.pack([folder], on_packing=lambda index: index == 0 and doomed.unlink())
        self.assert_nothing_kept(result)
        self.assertRegex(self.progress[-1][2], "^The original is gone")

    def test_cancelling_while_packing_or_checking_keeps_nothing(self):
        for moment in ("packing", "checking"):
            with self.subTest(moment):
                cancel = threading.Event()
                hooks = ({"on_packing": lambda index, stop=cancel: index == 1 and stop.set()} if moment == "packing"
                         else {"on_checking": cancel.set})
                self.progress = []
                result = self.pack([self.folder()], out=f"exports-{moment}", cancel=cancel, **hooks)
                self.assertTrue(result.cancelled)
                self.assertEqual(self.progress[-1][2], "Cancelled")
                self.assert_nothing_kept(result, f"exports-{moment}")

    def test_the_passphrase_never_reaches_a_command_line(self):
        commands = []
        real = subprocess.Popen

        def recording(argv, *args, **kwargs):
            commands.append(" ".join(str(part) for part in argv))
            return real(argv, *args, **kwargs)

        with patch("mindyourownbytes.core.subprocess.Popen", side_effect=recording):
            made = self.pack([self.folder()], passphrases=["distinctive-canary-passphrase"])
        self.assertEqual(made.checked, 3, self.progress)
        for command in commands:
            self.assertNotIn("distinctive-canary-passphrase", command)
        working = [command for command in commands if "--output" in command]
        self.assertEqual(len(working), 2, "one to encrypt, and one to check")
        self.assertIn("--compress-algo none", working[0])
        self.assertIn("--output -", working[1], "the check never writes the archive's contents to disk")

    def test_a_wrong_passphrase_restores_nothing(self):
        made = self.pack([self.folder()])
        self.assert_restore_rejected(made.outputs[0], "restored", "Wrong passphrase", passphrases=["nope"])

    def forged(self, entries) -> Path:
        """An archive made outside this app, with a passphrase, holding whatever names it likes."""
        plain = self.root / "forged.zip"
        with zipfile.ZipFile(plain, "w") as made:
            for name, content in entries:
                made.writestr(name, content)
            made.comment = archive.MARKER
        forged = self.root / "forged.zip.gpg"
        result = self.run_gpg("--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--symmetric",
                              "--output", str(forged), str(plain))
        self.assertEqual(result.returncode, 0, result.stderr)
        plain.unlink()
        return forged

    def test_an_archive_with_names_that_escape_unpacks_nothing_anywhere(self):
        forged = self.forged([("fine.txt", b"x"), ("../../escaped.txt", b"evil")])
        self.assert_restore_rejected(forged, "restored", "can't be used safely", passphrases=[PASSPHRASE])
        self.assertFalse((self.root / "escaped.txt").exists())
        self.assertFalse((self.root.parent / "escaped.txt").exists())

    def test_a_zip_someone_encrypted_as_a_file_restores_as_that_zip(self):
        own = self.root / "photos.zip"
        with zipfile.ZipFile(own, "w") as made:
            made.writestr("a.jpg", b"jpeg")
        encrypted = self.encrypt(own)
        restored = self.restore(encrypted)
        self.assertEqual(self.progress[-1][2], READY)
        self.assertEqual(restored.outputs[0].name, "photos.zip")
        self.assertEqual(restored.outputs[0].read_bytes(), own.read_bytes())

    def test_names_that_cannot_be_used_are_refused_before_any_work(self):
        for name in ("", "../escape", "CON", "a/b"):
            with self.subTest(name), self.assertRaises(ValueError):
                self.pack([self.folder()], name=name)
        self.assertFalse((self.root / "exports").exists())


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
