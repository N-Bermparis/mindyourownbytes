"""Reading signatures from GnuPG's status lines. tests/test_gpg_integration.py makes real signed files.

The transcripts are what GnuPG 2.5.18 and 2.2.27 really printed while decrypting, shortened to the lines
that matter. Every judgement uses status tokens, never GnuPG's translated text.
"""

import unittest

from mindyourownbytes import signatures

MINE = "140B1F7D279CB98203E2458DFD8BBFED68E6BC9F"
OTHER = "E0B87BF7302EDB96D1A9A5E3D43535C3ABF5DDB7"

DECRYPTED_WITH_KEY = """\
[GNUPG:] ENC_TO 86B06E232E6A9527 18 0
[GNUPG:] DECRYPTION_KEY FCC9071ECB96CDB71E77D35D86B06E232E6A9527 140B1F7D279CB98203E2458DFD8BBFED68E6BC9F u
[GNUPG:] BEGIN_DECRYPTION
[GNUPG:] DECRYPTION_INFO 0 9 2 0
[GNUPG:] PLAINTEXT 62 1794575944 plain.txt
"""
DONE = "[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC\n[GNUPG:] END_DECRYPTION\n"


def signed_by(fingerprint: str, name: str, trust: str | None, result: str = "GOODSIG") -> str:
    lines = ["[GNUPG:] NEWSIG", f"[GNUPG:] {result} {fingerprint[-16:]} {name}",
             f"[GNUPG:] VALIDSIG {fingerprint} 2026-11-13 1794575944 0 4 0 22 10 00 {fingerprint}"]
    if trust:
        lines.append(f"[GNUPG:] {trust} 0 pgp")
    return "\n".join(lines) + "\n"


SELF_SIGNED = DECRYPTED_WITH_KEY + signed_by(MINE, "Me <me@example.invalid>", "TRUST_ULTIMATE") + DONE
UNCERTIFIED = DECRYPTED_WITH_KEY + signed_by(OTHER, "Other <other@example.invalid>", "TRUST_UNDEFINED") + DONE
CERTIFIED = DECRYPTED_WITH_KEY + signed_by(OTHER, "Other <other@example.invalid>", "TRUST_FULLY") + DONE
UNSIGNED_FOR_KEY = DECRYPTED_WITH_KEY + DONE
UNSIGNED_PASSPHRASE = ("[GNUPG:] NEED_PASSPHRASE_SYM 9 3 10\n[GNUPG:] BEGIN_DECRYPTION\n"
                       "[GNUPG:] PLAINTEXT 62 0 a.txt\n") + DONE
BAD = DECRYPTED_WITH_KEY + "[GNUPG:] NEWSIG\n[GNUPG:] BADSIG 04E3BC43C7FE53E3 Me <me@example.invalid>\n" + DONE
MISSING_KEY = DECRYPTED_WITH_KEY + (
    "[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG D43535C3ABF5DDB7 22 10 00 1794575945 9 E0B87BF7302EDB96D1A9A5E3D43535C3ABF5DDB7\n"
    "[GNUPG:] NO_PUBKEY D43535C3ABF5DDB7\n") + DONE
#: GnuPG 2.2.27 adds compliance lines, and reports RSA (1) rather than EdDSA (22).
OLDER_GNUPG = (
    "[GNUPG:] ENC_TO FFCA0CFD6D4AE547 1 0\n"
    "[GNUPG:] DECRYPTION_KEY 262B490D42A4172D61F88741FFCA0CFD6D4AE547 B84CCB8247C1CEC7B19B3644320604DEDC8B3F62 u\n"
    "[GNUPG:] BEGIN_DECRYPTION\n[GNUPG:] DECRYPTION_COMPLIANCE_MODE 23\n[GNUPG:] DECRYPTION_INFO 2 9 0\n"
    "[GNUPG:] PLAINTEXT 62 1794576004 plain.txt\n[GNUPG:] PLAINTEXT_LENGTH 6\n[GNUPG:] NEWSIG\n"
    "[GNUPG:] SIG_ID wmyXvQa93alXz/B3GF+nMBvog74 2026-11-13 1794576004\n"
    "[GNUPG:] GOODSIG 320604DEDC8B3F62 Me <me@example.invalid>\n"
    "[GNUPG:] VALIDSIG B84CCB8247C1CEC7B19B3644320604DEDC8B3F62 2026-11-13 1794576004 0 4 0 1 10 00 "
    "B84CCB8247C1CEC7B19B3644320604DEDC8B3F62\n"
    "[GNUPG:] TRUST_ULTIMATE 0 pgp\n[GNUPG:] VERIFICATION_COMPLIANCE_MODE 23\n") + DONE


class ReadingTests(unittest.TestCase):
    def test_own_key(self):
        verification = signatures.read(SELF_SIGNED)
        self.assertEqual(verification.status, "verified")
        self.assertTrue(verification.encrypted_to_key)
        self.assertEqual(verification.signer.primary_fingerprint, MINE)
        self.assertEqual(verification.signer.user_id, "Me <me@example.invalid>")
        self.assertEqual(signatures.headline(verification), "signed by Me")
        self.assertIn("140B 1F7D", signatures.explanation(verification))

    def test_older_gnupg_says_the_same(self):
        verification = signatures.read(OLDER_GNUPG)
        self.assertEqual(verification.status, "verified")
        self.assertEqual(verification.signer.fingerprint, "B84CCB8247C1CEC7B19B3644320604DEDC8B3F62")

    def test_a_correct_signature_from_a_key_nobody_verified_is_not_proof_of_who(self):
        verification = signatures.read(UNCERTIFIED)
        self.assertEqual(verification.status, "unverified")
        self.assertFalse(verification.authenticated)
        self.assertTrue(verification.signer.valid, "the signature itself is mathematically correct")
        self.assertEqual(signatures.headline(verification), "signed with a key you haven't verified")
        self.assertNotIn("Other", signatures.headline(verification), "an unverified name is never a headline")
        self.assertIn("anyone can make a key with any name", signatures.explanation(verification))

    def test_a_certified_key_is_verified(self):
        self.assertEqual(signatures.read(CERTIFIED).status, "verified")
        self.assertEqual(signatures.headline(signatures.read(CERTIFIED)), "signed by Other")

    def test_marginal_and_never_are_not_verified(self):
        for trust in ("TRUST_MARGINAL", "TRUST_NEVER", None):
            with self.subTest(trust):
                text = DECRYPTED_WITH_KEY + signed_by(OTHER, "Other", trust) + DONE
                self.assertEqual(signatures.read(text).status, "unverified")

    def test_unsigned(self):
        for_key = signatures.read(UNSIGNED_FOR_KEY)
        self.assertEqual((for_key.status, for_key.encrypted_to_key), ("unsigned", True))
        self.assertEqual(signatures.headline(for_key), "not signed")
        self.assertIn("anyone who has your public key", signatures.explanation(for_key))
        for_passphrase = signatures.read(UNSIGNED_PASSPHRASE)
        self.assertEqual((for_passphrase.status, for_passphrase.encrypted_to_key), ("unsigned", False))
        self.assertEqual(signatures.headline(for_passphrase), "", "nothing new to say about a passphrase file")
        self.assertIn("knew the passphrase", signatures.explanation(for_passphrase))

    def test_bad_and_missing_key(self):
        self.assertEqual(signatures.read(BAD).status, "bad")
        missing = signatures.read(MISSING_KEY)
        self.assertEqual(missing.status, "unverifiable")
        self.assertTrue(missing.signer.missing_key)

    def test_revoked_and_expired(self):
        revoked = signatures.read(DECRYPTED_WITH_KEY + signed_by(MINE, "Me", "TRUST_ULTIMATE", "REVKEYSIG") + DONE)
        self.assertEqual(revoked.status, "revoked")
        self.assertIn("revoked", signatures.explanation(revoked))
        # What GnuPG 2.5.18 really says once the signing key has expired: EXPKEYSIG and VALIDSIG, and no trust.
        expired_key = signatures.read(DECRYPTED_WITH_KEY + signed_by(MINE, "Me", None, "EXPKEYSIG") + DONE)
        self.assertEqual(expired_key.status, "expired")
        self.assertEqual(signatures.headline(expired_key), "signed with a key that has expired")
        self.assertIn("extend its expiry date", signatures.explanation(expired_key))
        self.assertIsNone(signatures.refusal(expired_key), "legacy-friendly by default")
        self.assertIn("expired", signatures.refusal(expired_key, require_verified=True))
        # A key named by fingerprint is relied on as named, even after it expires.
        self.assertEqual(signatures.read(DECRYPTED_WITH_KEY + signed_by(MINE, "Me", None, "EXPKEYSIG") + DONE,
                                         expected=[MINE]).status, "verified")
        expired_signature = signatures.read(DECRYPTED_WITH_KEY + signed_by(MINE, "Me", "TRUST_ULTIMATE", "EXPSIG")
                                            + DONE)
        self.assertEqual(expired_signature.status, "unverified")

    def test_user_ids_are_unescaped(self):
        text = DECRYPTED_WITH_KEY + signed_by(MINE, "J%C3%BCrgen%20%25 <j@example.invalid>", "TRUST_ULTIMATE") + DONE
        self.assertEqual(signatures.read(text).signer.user_id, "Jürgen % <j@example.invalid>")


class UnreliableReportTests(unittest.TestCase):
    """GOODSIG is never enough by itself, and a report that contradicts itself is refused."""

    def test_goodsig_without_validsig(self):
        goodsig_alone = f"[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG {MINE[-16:]} Me\n[GNUPG:] TRUST_ULTIMATE\n"
        self.assertEqual(signatures.read(DECRYPTED_WITH_KEY + goodsig_alone + DONE).status, "incomplete")

    def test_an_extra_trust_line(self):
        # As if text pretending to be a status line had got in: two verdicts for one signature.
        report = signed_by(OTHER, "Other", "TRUST_UNDEFINED") + "[GNUPG:] TRUST_ULTIMATE 0 pgp\n"
        verification = signatures.read(DECRYPTED_WITH_KEY + report + DONE)
        self.assertEqual(verification.status, "incomplete")
        self.assertIn("contradictory", signatures.refusal(verification))

    def test_a_second_result_or_validsig_for_one_signature(self):
        doubled = signed_by(OTHER, "Other", "TRUST_UNDEFINED").replace(
            "[GNUPG:] NEWSIG\n", "[GNUPG:] NEWSIG\n" + f"[GNUPG:] GOODSIG {MINE[-16:]} Me\n")
        self.assertEqual(signatures.read(DECRYPTED_WITH_KEY + doubled + DONE).status, "incomplete")
        validsig_twice = signed_by(OTHER, "Other", None) + \
            f"[GNUPG:] VALIDSIG {MINE} 2026-11-13 1 0 4 0 22 10 00 {MINE}\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n"
        self.assertEqual(signatures.read(DECRYPTED_WITH_KEY + validsig_twice + DONE).status, "incomplete")

    def test_validsig_for_a_different_key_than_goodsig(self):
        text = DECRYPTED_WITH_KEY + (
            f"[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG {OTHER[-16:]} Other\n"
            f"[GNUPG:] VALIDSIG {MINE} 2026-11-13 1 0 4 0 22 10 00 {MINE}\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n") + DONE
        self.assertEqual(signatures.read(text).status, "incomplete")

    def test_a_result_without_newsig(self):
        text = DECRYPTED_WITH_KEY + signed_by(MINE, "Me", "TRUST_ULTIMATE").replace("[GNUPG:] NEWSIG\n", "") + DONE
        self.assertEqual(signatures.read(text).status, "incomplete")

    def test_a_signature_without_a_result(self):
        self.assertEqual(signatures.read(DECRYPTED_WITH_KEY + "[GNUPG:] NEWSIG\n" + DONE).status, "incomplete")

    def test_text_that_only_looks_like_a_status_line_is_ignored(self):
        # GnuPG's own messages start with "gpg: ". Only lines that start with the status prefix count.
        text = UNSIGNED_FOR_KEY + 'gpg: Good signature from "x [GNUPG:] GOODSIG ..."\n  [GNUPG:] TRUST_ULTIMATE\n'
        self.assertEqual(signatures.read(text).status, "unsigned")

    def test_several_signatures_one_bad_is_bad(self):
        text = DECRYPTED_WITH_KEY + signed_by(MINE, "Me", "TRUST_ULTIMATE") + \
            "[GNUPG:] NEWSIG\n[GNUPG:] BADSIG D43535C3ABF5DDB7 Other\n" + DONE
        self.assertEqual(signatures.read(text).status, "bad")

    def test_several_good_signatures_one_verified_is_verified(self):
        text = DECRYPTED_WITH_KEY + signed_by(OTHER, "Other", "TRUST_UNDEFINED") + \
            signed_by(MINE, "Me", "TRUST_ULTIMATE") + DONE
        verification = signatures.read(text)
        self.assertEqual(verification.status, "verified")
        self.assertEqual(verification.signer.primary_fingerprint, MINE)


class ExpectedSignerTests(unittest.TestCase):
    """A named fingerprint is the strongest statement of who should have signed. Names never count."""

    def test_a_named_fingerprint_verifies_an_otherwise_unverified_key(self):
        verification = signatures.read(UNCERTIFIED, expected=[OTHER.lower()])
        self.assertEqual(verification.status, "verified")
        self.assertIn("you named it", signatures.explanation(verification))

    def test_a_valid_signature_by_anyone_else_is_refused(self):
        verification = signatures.read(SELF_SIGNED, expected=[OTHER])
        self.assertEqual(verification.status, "unexpected")
        self.assertIn("140B 1F7D", signatures.refusal(verification))

    def test_a_matching_name_with_another_key_is_still_refused(self):
        impostor = DECRYPTED_WITH_KEY + signed_by(OTHER, "Me <me@example.invalid>", "TRUST_FULLY") + DONE
        self.assertEqual(signatures.read(impostor, expected=[MINE]).status, "unexpected")

    def test_a_revoked_expected_key_is_refused(self):
        text = DECRYPTED_WITH_KEY + signed_by(MINE, "Me", "TRUST_ULTIMATE", "REVKEYSIG") + DONE
        self.assertEqual(signatures.read(text, expected=[MINE]).status, "unexpected")

    def test_fingerprints_are_checked(self):
        for bad in ("me@example.invalid", "DFD8BBFED68E6BC9F", MINE + "0"):
            with self.subTest(bad), self.assertRaises(ValueError):
                signatures.read(SELF_SIGNED, expected=[bad])
        self.assertEqual(signatures.normalize_fingerprint(" ".join([MINE[:20], MINE[20:]]).lower()), MINE)


class RefusalTests(unittest.TestCase):
    def refusal(self, text: str, require: bool = False) -> str | None:
        return signatures.refusal(signatures.read(text), require_verified=require)

    def test_always_refused(self):
        self.assertIn("invalid", self.refusal(BAD))
        self.assertIn("key you don't have", self.refusal(MISSING_KEY))
        errsig = MISSING_KEY.replace(" 9 E0B8", " 4 E0B8").replace("[GNUPG:] NO_PUBKEY D43535C3ABF5DDB7\n", "")
        self.assertIn("error 4", self.refusal(errsig))

    def test_by_default_legacy_and_unverified_files_still_restore(self):
        for text in (UNSIGNED_FOR_KEY, UNSIGNED_PASSPHRASE, UNCERTIFIED, SELF_SIGNED):
            with self.subTest(text[-120:]):
                self.assertIsNone(self.refusal(text))

    def test_requiring_a_verified_signature(self):
        self.assertIsNone(self.refusal(SELF_SIGNED, require=True))
        self.assertIsNone(self.refusal(CERTIFIED, require=True))
        self.assertIn("isn't signed", self.refusal(UNSIGNED_FOR_KEY, require=True))
        self.assertIn("haven't verified", self.refusal(UNCERTIFIED, require=True))
        revoked = DECRYPTED_WITH_KEY + signed_by(MINE, "Me", "TRUST_ULTIMATE", "REVKEYSIG") + DONE
        self.assertIn("revoked", self.refusal(revoked, require=True))

    def test_passphrase_files_never_need_a_signature(self):
        # Only someone who knew the passphrase could have made one.
        self.assertIsNone(self.refusal(UNSIGNED_PASSPHRASE, require=True))


class SameReportTests(unittest.TestCase):
    """Agreeing to restore a file covers what you were shown about it, and nothing else."""

    def same(self, first: str, second: str) -> bool:
        return signatures.same_report(signatures.read(first), signatures.read(second))

    def test_the_same_report_again(self):
        for text in (UNSIGNED_FOR_KEY, UNCERTIFIED, SELF_SIGNED, OLDER_GNUPG):
            with self.subTest(text[-80:]):
                self.assertTrue(self.same(text, text))

    def test_anything_else_is_a_different_report(self):
        other_key = DECRYPTED_WITH_KEY + signed_by(MINE, "Other <other@example.invalid>", "TRUST_UNDEFINED") + DONE
        self.assertEqual(signatures.read(other_key).status, signatures.read(UNCERTIFIED).status, "same verdict")
        revoked =DECRYPTED_WITH_KEY + signed_by(OTHER, "Other", "TRUST_UNDEFINED", "REVKEYSIG") + DONE
        twice = DECRYPTED_WITH_KEY + signed_by(OTHER, "Other", "TRUST_UNDEFINED") + signed_by(
            MINE, "Me", "TRUST_UNDEFINED") + DONE
        for first, second in ((UNSIGNED_FOR_KEY, UNCERTIFIED), (UNCERTIFIED, other_key), (UNCERTIFIED, revoked),
                              (UNCERTIFIED, twice), (UNSIGNED_FOR_KEY, UNSIGNED_PASSPHRASE)):
            with self.subTest(first=first[-60:], second=second[-60:]):
                self.assertFalse(self.same(first, second))
                self.assertFalse(self.same(second, first))

    def test_a_name_is_not_part_of_it_but_the_key_is(self):
        renamed = UNCERTIFIED.replace("Other <other@example.invalid>", "Someone Trustworthy")
        self.assertTrue(self.same(UNCERTIFIED, renamed), "the same key, whatever it calls itself")


if __name__ == "__main__":
    unittest.main()
