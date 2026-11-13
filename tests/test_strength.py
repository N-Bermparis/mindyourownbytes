"""Judging new passphrases: common and patterned ones are refused, nothing claims a number, old ones still open."""

import threading
import unicodedata
import unittest
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes import generator, strength
from mindyourownbytes.vault import MIN_MASTER_LENGTH, Vault, VaultError, check_new_master
from tests.support import GpgTestCase


def level(passphrase: str, **options) -> str:
    return strength.assess(passphrase, **options).level


class WeakTests(unittest.TestCase):
    def assert_weak(self, passphrases, why: str, **options) -> None:
        for passphrase in passphrases:
            with self.subTest(passphrase):
                result = strength.assess(passphrase, **options)
                self.assertEqual(result.level, "weak")
                self.assertFalse(result.acceptable)
                self.assertIn(why, result.message)
                self.assertNotIn(passphrase, result.message, "the passphrase never appears in a message")

    def test_common_passwords(self):
        self.assert_weak(["password", "PASSWORD", "12345678", "qwertyuiop", "iloveyou", "Correct Horse Battery Staple",
                          "correct-horse-battery-staple", "ＰＡＳＳＷＯＲＤ", "Tr0ub4dor&3"],
                         "people use most")

    def test_common_passwords_dressed_up(self):
        self.assert_weak(["Password123!", "p@ssw0rd2026", "!!qwerty123!!", "M0nk3y!!2026", "123iloveyou456"],
                         "common password")

    def test_one_ordinary_word_with_decoration(self):
        self.assert_weak(["Elephant2024!", "3l3phant!!", "battery#1234", "umbrella2026", "family123"],
                         "one ordinary word")

    def test_a_short_word_or_name_with_a_year(self):
        # Names aren't in any word list here, so this is caught by its shape instead.
        self.assert_weak(["Rosa 1987", "Zorgh!2026", "#kiki#0412#"], "one short word or name")

    def test_two_ordinary_words(self):
        self.assert_weak(["correct horse", "battery-staple", "Happy Family"], "two ordinary words")

    def test_repeated_characters_and_parts(self):
        self.assert_weak(["aaaaaaaaaaaa", "abababababab", "zzzz1111zzzz"], "only a few different characters")
        self.assert_weak(["xkcd7xkcd7xkcd7", "Q9!pQ9!pQ9!pQ9!p"], "repeats a short part")

    def test_runs_of_keys_or_characters(self):
        self.assert_weak(["abcdefghijkl", "zyxwvutsrq98", "ghjkl6789", "rtzuiop98765", "lkjhgfdsa9876"],
                         "in order")

    def test_only_digits(self):
        self.assert_weak(["19870412", "0612 345 678", "31/12/1999", "4915112345678"], "only digits")

    def test_too_short(self):
        self.assert_weak(["k#9Lw!2"], "at least 8")
        self.assert_weak(["k#9Lw!2pQ"], "at least 12", min_length=12)

    def test_empty_and_unusable_characters(self):
        self.assertEqual(strength.assess("").level, "weak")
        self.assert_weak(["two\nlines here", "nul\0in the middle"], "line breaks or NUL")
        self.assert_weak(["escape\x1b[0mcode here"], "control character")


class AcceptedTests(unittest.TestCase):
    def test_long_unusual_phrases_are_better_but_never_strong(self):
        for passphrase in ("my grandmother's red bicycle rusted in 1987", "Wolkenkratzer am Rhein, bei Nacht!",
                           "seven taxis argue softly about pianos"):
            with self.subTest(passphrase):
                result = strength.assess(passphrase)
                self.assertEqual(result.level, "fair")
                self.assertTrue(result.acceptable)
                self.assertTrue(result.message.startswith("Better"))
                self.assertNotRegex(result.message, r"\d+ bits|10[⁰¹²³⁴⁵⁶⁷⁸⁹]", "no number is claimed for a choice")

    def test_a_short_acceptable_one_is_warned_about(self):
        self.assertIn("short enough to be guessed", strength.assess("k#9Lw!2pQ").message)

    def test_only_a_generated_passphrase_is_strong(self):
        for kind in ("words", "characters"):
            with self.subTest(kind):
                passphrase = generator.generate(kind)
                self.assertEqual(level(passphrase, generated=True), "strong")
                self.assertEqual(level(passphrase), "fair", "the same text, typed, is only a person's choice")

    def test_generated_passphrases_never_trip_the_checks(self):
        for _ in range(200):
            for kind in ("words", "characters"):
                passphrase = generator.generate(kind)
                self.assertTrue(strength.assess(passphrase, min_length=MIN_MASTER_LENGTH).acceptable, passphrase)

    def test_unicode_is_judged_by_meaning_and_counted_by_character(self):
        self.assertEqual(level("Ζωή στο νησί, με καφέ και θάλασσα"), "fair")
        self.assertEqual(level("ΠΑΣΣΓΟΥΟΡΝΤ ΚΑΙ ΚΛΕΙΔΙΑ"), "fair")
        self.assertEqual(level("𝐏𝐚𝐬𝐬𝐰𝐨𝐫𝐝"), "weak", "styled letters fold to plain ones")
        self.assertEqual(level("ü" * 2 + "naïve café ½ crème brûlée"), "fair")

    def test_text_that_can_be_typed_two_ways_is_mentioned(self):
        decomposed = unicodedata.normalize("NFD", "crème brûlée, île flottante")
        self.assertIn("more than one way", strength.assess(decomposed).message)
        self.assertNotIn("more than one way", strength.assess(unicodedata.normalize("NFC", decomposed)).message)

    def test_spaces_inside_are_fine(self):
        self.assertEqual(level("  a long quiet walk to the old mill  "), "fair")

    def test_check_new_explains_a_refusal(self):
        with self.assertRaisesRegex(strength.WeakPassphrase, "people use most"):
            strength.check_new("password1234", min_length=8)
        strength.check_new("seven taxis argue softly about pianos", min_length=12)

    def test_nothing_leaves_the_computer(self):
        # The check is pure computation: no socket, subprocess, or file is touched.
        strength._words()  # The app's own word list is read once, and kept.
        with patch("socket.socket", side_effect=AssertionError("network")), \
                patch("subprocess.Popen", side_effect=AssertionError("process")), \
                patch("builtins.open", side_effect=AssertionError("file")):
            for passphrase in ("seven taxis argue softly about pianos", "password1", "Elephant2024!"):
                strength.assess(passphrase)


class VaultMasterTests(GpgTestCase):
    """The master passphrase guards every other one, so a weak new master is refused by the vault itself."""

    def setUp(self):
        super().setUp()
        self.vault = Vault(self.gpg, self.root / "vault.gpg")

    def test_a_weak_new_master_is_refused_and_nothing_is_written(self):
        for master in ("password1234", "qwertyuiop123", "aaaaaaaaaaaaaaa", "Elephant2024!!", "19870412195503"):
            with self.subTest(master), self.assertRaisesRegex(VaultError, "Choose a different master"):
                self.vault.create(master)
        self.assertFalse((self.root / "vault.gpg").exists())
        self.vault.create("seven taxis argue softly about pianos")

    def test_changing_to_a_weak_master_is_refused_and_the_old_one_still_works(self):
        self.vault.create("seven taxis argue softly about pianos")
        with self.assertRaisesRegex(VaultError, "Choose a different master"):
            self.vault.change_master("seven taxis argue softly about pianos", "password1234")
        self.vault.lock()
        self.vault.unlock("seven taxis argue softly about pianos")

    def test_an_existing_vault_with_a_weak_master_still_unlocks(self):
        # Made before this check existed: the same file, written by plain GnuPG.
        with patch("mindyourownbytes.vault.strength.check_new"):
            self.vault.create("password1234")
        self.vault.lock()
        self.vault.unlock("password1234")
        self.assertTrue(self.vault.unlocked)

    def test_the_rule_is_the_one_for_new_passphrases(self):
        with self.assertRaisesRegex(VaultError, "at least"):
            check_new_master("short")
        with self.assertRaisesRegex(VaultError, "people use most"):
            check_new_master("correct horse battery staple")


class OldFilesStillOpenTests(GpgTestCase):
    """A weak passphrase from before stays usable for restoring: the rule is only for new ones."""

    def test_a_file_protected_by_a_weak_passphrase_still_restores(self):
        from mindyourownbytes.core import SourceItem, process_items
        original = self.root / "old.txt"
        original.write_bytes(b"from long ago")
        encrypted = self.root / "old.txt.gpg"
        made = self.run_gpg("--pinentry-mode", "loopback", "--passphrase", "password", "--symmetric",
                            "--output", str(encrypted), str(original))
        self.assertEqual(made.returncode, 0, made.stderr)
        result = process_items(self.gpg, [SourceItem(encrypted, Path("old.txt.gpg"), 1)], self.root / "restored",
                               "restore", "password", None, threading.Event(), lambda *args: None,
                               passphrases=["password"])
        self.assertEqual(result.outputs[0].read_bytes(), b"from long ago")


if __name__ == "__main__":
    unittest.main()
