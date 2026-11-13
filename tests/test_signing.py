"""Sign-and-encrypt, and what a restore says about who made a file, against a real GnuPG.

Encrypting to a public key says nothing about who did it: anyone with the public key can. These tests
make files signed by verified, unverified, revoked, and unexpected keys, and with a broken signature, and
check that each is reported, or refused, for what it is. Standard GnuPG must agree with no help from the app.
"""

import os
import subprocess
import threading
import time
from pathlib import Path

from mindyourownbytes.core import encrypt_archive, list_signing_keys
from tests.test_gpg_integration import PASSPHRASE, IntegrationCase


class SigningCase(IntegrationCase):
    def setUp(self):
        super().setUp()
        self.me = self.generate_key("Me <me@example.invalid>")
        self.verdicts = []

    def restore(self, path: Path, out: str = "restored", **options):
        return self.job([self.item(path)], out, "restore",
                        on_signature=lambda index, verification: self.verdicts.append(verification), **options)

    def encrypt_to_me(self, name: str = "a.txt", content: bytes = b"made by me", **options) -> Path:
        result = self.job([self.item(self.write(name, content))], "exports", "encrypt", "public-key", self.me,
                          **options)
        self.assertEqual((result.succeeded, result.failed), (1, 0), self.progress)
        return result.outputs[0]

    def from_someone_else(self, content: bytes = b"made by someone else") -> tuple[str, Path]:
        """A file another person signed and encrypted to me, with their own keyring and plain GnuPG."""
        home = self.root / "sender"
        home.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(home))
        gpgconf = Path(self.gpg).with_name("gpgconf.exe" if os.name == "nt" else "gpgconf")
        if gpgconf.is_file():
            self.addCleanup(subprocess.run, [str(gpgconf), "--homedir", str(home), "--kill", "all"],
                            capture_output=True, check=False)
        self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key",
                     "Other <other@example.invalid>", "default", "default", "1y", env=env)
        listing = self.run_gpg("--with-colons", "--fingerprint", "--list-keys", env=env).stdout.decode()
        other = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        self.run_gpg("--import", input=self.run_gpg("--export", self.me).stdout, env=env)
        output = self.root / "from-other.txt.gpg"
        made = self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--trust-model", "always",
                            "--sign", "--local-user", other, "--encrypt", "--recipient", self.me,
                            "--output", str(output), str(self.write("from-other.txt", content)), env=env)
        self.assertEqual(made.returncode, 0, made.stderr)
        self.run_gpg("--import", input=self.run_gpg("--export", other, env=env).stdout)
        return other, output

    def assert_refused(self, result, out: str, message: str) -> None:
        self.assertEqual((result.succeeded, result.failed), (0, 1), self.progress)
        self.assertRegex(self.progress[-1][2], message)
        left = list((self.root / out).rglob("*")) if (self.root / out).exists() else []
        self.assertEqual(left, [], "a refused file leaves nothing behind, not even its workspace")


class SignAndEncryptTests(SigningCase):
    def test_your_own_signature_restores_as_verified_and_plain_gnupg_agrees(self):
        encrypted = self.encrypt_to_me(sign_with=self.me)
        self.assertRegex(self.packets(encrypted), r":signature packet:", "the signature is inside, encrypted")
        restored = self.restore(encrypted)
        self.assertEqual(restored.outputs[0].read_bytes(), b"made by me")
        verification = restored.verifications[0]
        self.assertEqual((verification.status, verification.encrypted_to_key), ("verified", True))
        self.assertEqual(verification.signer.primary_fingerprint, self.me)
        self.assertEqual(self.verdicts, [verification])
        # No lock-in: plain GnuPG decrypts it and checks the same signature.
        plain = self.run_gpg("--status-fd", "2", "--output", str(self.root / "by-hand.txt"), "--decrypt",
                             str(encrypted))
        self.assertEqual(plain.returncode, 0, plain.stderr)
        self.assertIn(f"VALIDSIG {self.me}".encode(), plain.stderr)
        self.assertEqual((self.root / "by-hand.txt").read_bytes(), b"made by me")

    def test_a_signed_archive_comes_back_whole_and_verified(self):
        for name in ("a.txt", "inner/b.txt"):
            self.write(f"Taxes/{name}", name.encode())
        items = [self.item(self.root / "Taxes" / name, Path("Taxes") / name) for name in ("a.txt", "inner/b.txt")]
        made = encrypt_archive(self.gpg, items, self.root / "exports", "Archive", "public-key", self.me,
                               threading.Event(), lambda *args: self.progress.append(args), sign_with=self.me)
        self.assertEqual(made.succeeded, 2, self.progress)
        restored = self.restore(made.outputs[0])
        folder = restored.outputs[0]
        self.assertEqual((folder / "Taxes" / "inner" / "b.txt").read_bytes(), b"inner/b.txt")
        self.assertEqual(restored.verifications[0].status, "verified")

    def test_a_legacy_unsigned_file_still_restores_and_says_it_isnt_signed(self):
        encrypted = self.encrypt_to_me()
        restored = self.restore(encrypted)
        self.assertEqual(restored.outputs[0].read_bytes(), b"made by me")
        self.assertEqual((restored.verifications[0].status, restored.verifications[0].encrypted_to_key),
                         ("unsigned", True))

    def test_requiring_a_verified_signature_refuses_an_unsigned_file_for_a_key(self):
        self.assert_refused(self.restore(self.encrypt_to_me(), require_signature=True), "restored", "isn't signed")

    def test_requiring_a_signature_never_affects_passphrase_files(self):
        encrypted = self.encrypt(self.write("p.txt", b"by passphrase"))
        restored = self.restore(encrypted, passphrases=[PASSPHRASE], require_signature=True)
        self.assertEqual(restored.outputs[0].read_bytes(), b"by passphrase")
        self.assertEqual((restored.verifications[0].status, restored.verifications[0].encrypted_to_key),
                         ("unsigned", False))

    def test_signing_only_goes_with_a_key(self):
        with self.assertRaisesRegex(ValueError, "Only files encrypted to a key"):
            self.job([self.item(self.write("a.txt"))], "exports", "encrypt", passphrases=[PASSPHRASE],
                     sign_with=self.me)
        with self.assertRaisesRegex(ValueError, "signing key"):
            self.job([self.item(self.write("a.txt"))], "exports", "encrypt", "public-key", self.me, sign_with="me")

    def test_signing_with_a_key_whose_private_part_isnt_here_fails_clearly(self):
        other, _ = self.from_someone_else()
        result = self.job([self.item(self.write("a.txt"))], "exports", "encrypt", "public-key", self.me,
                          sign_with=other)
        self.assertEqual((result.succeeded, result.failed), (0, 1))
        self.assertIn("couldn't sign with this key", self.progress[-1][2])
        self.assertIn("private key isn't on this computer", self.progress[-1][2])
        self.assertEqual([p for p in (self.root / "exports").rglob("*") if p.is_file()], [])

    def test_only_your_keys_that_can_sign_are_offered(self):
        self.from_someone_else()  # Its public key is here now, but not its private key.
        self.assertEqual([key.fingerprint for key in list_signing_keys(self.gpg)], [self.me])


class SomeoneElsesSignatureTests(SigningCase):
    def test_a_key_you_never_verified_signs_validly_but_proves_nothing_about_who(self):
        other, encrypted = self.from_someone_else()
        restored = self.restore(encrypted)
        self.assertEqual(restored.outputs[0].read_bytes(), b"made by someone else")
        verification = restored.verifications[0]
        self.assertEqual(verification.status, "unverified")
        self.assertEqual(verification.signer.primary_fingerprint, other)
        self.assertEqual(verification.signer.user_id, "Other <other@example.invalid>")

    def test_requiring_a_verified_signature_refuses_it(self):
        _, encrypted = self.from_someone_else()
        self.assert_refused(self.restore(encrypted, require_signature=True), "restored", "haven't verified")

    def test_once_you_certify_the_key_it_is_verified(self):
        other, encrypted = self.from_someone_else()
        certified = self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-lsign-key", other)
        self.assertEqual(certified.returncode, 0, certified.stderr)
        restored = self.restore(encrypted, require_signature=True)
        self.assertEqual(restored.verifications[0].status, "verified")

    def test_an_expected_signer_is_matched_by_fingerprint(self):
        other, encrypted = self.from_someone_else()
        self.assertEqual(self.restore(encrypted, out="a", expected_signers=[other]).verifications[0].status,
                         "verified")
        self.assert_refused(self.restore(encrypted, out="b", expected_signers=[self.me]), "b",
                            "not by a key you expected")

    def test_a_signer_whose_public_key_you_dont_have_is_refused(self):
        other, encrypted = self.from_someone_else()
        self.run_gpg("--yes", "--delete-keys", other)
        self.assert_refused(self.restore(encrypted), "restored", "signed by a key you don't have")


class BrokenSignatureTests(SigningCase):
    def tampered(self) -> Path:
        """Signed, then altered, then encrypted to me: it decrypts perfectly, but its signature is bad.

        ``--no-literal`` makes GnuPG encrypt the signed packets as they are, the way sign-and-encrypt
        nests them, so that decrypting also checks the signature.
        """
        signed = self.root / "signed.bin"
        made = self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--compress-algo", "none", "--sign",
                            "--local-user", self.me, "--output", str(signed), str(self.write("t.txt", b"pay 100\n")))
        self.assertEqual(made.returncode, 0, made.stderr)
        data = bytearray(signed.read_bytes())
        data[data.index(b"pay 100")] = ord("P")
        signed.write_bytes(bytes(data))
        output = self.root / "tampered.txt.gpg"
        encrypted = self.run_gpg("--no-literal", "--compress-algo", "none", "--trust-model", "always", "--encrypt",
                                 "--recipient", self.me, "--output", str(output), str(signed))
        self.assertEqual(encrypted.returncode, 0, encrypted.stderr)
        return output

    def test_an_invalid_signature_fails_closed_and_leaves_nothing(self):
        self.assert_refused(self.restore(self.tampered()), "restored", "signature is invalid")

    def test_a_key_that_has_expired_since_is_reported_and_refused_when_required(self):
        encrypted = self.encrypt_to_me(sign_with=self.me)  # The key lasts a year.
        # Three years on, as far as GnuPG can tell. gpg.conf applies to every call the app makes.
        (self.home / "gpg.conf").write_text(f"faked-system-time {int(time.time()) + 3 * 365 * 86400}\n")
        restored = self.restore(encrypted)
        self.assertEqual(restored.outputs[0].read_bytes(), b"made by me")
        self.assertEqual(restored.verifications[0].status, "expired")
        self.assert_refused(self.restore(encrypted, out="strict", require_signature=True), "strict",
                            "has expired")

    def test_a_revoked_signing_key_is_reported_and_refused_when_required(self):
        encrypted = self.encrypt_to_me(sign_with=self.me)
        certificate = self.home / "openpgp-revocs.d" / f"{self.me}.rev"
        if not certificate.is_file():
            self.skipTest("this GnuPG didn't keep a revocation certificate")
        # GnuPG protects it from accidental import with a colon at the start of the armor line.
        text = certificate.read_text(encoding="utf-8").replace(":-----BEGIN PGP PUBLIC KEY BLOCK-----",
                                                                "-----BEGIN PGP PUBLIC KEY BLOCK-----")
        imported = self.run_gpg("--import", input=text.encode())
        self.assertEqual(imported.returncode, 0, imported.stderr)
        restored = self.restore(encrypted)
        self.assertEqual(restored.verifications[0].status, "revoked")
        self.assert_refused(self.restore(encrypted, out="strict", require_signature=True), "strict", "revoked")
