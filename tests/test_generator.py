"""Generated passphrases: the word list, the randomness, and the strength that's claimed for them."""

import hashlib
import itertools
import math
import shutil
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes import generator
from mindyourownbytes.vault import generate_passphrase


class WordListTests(unittest.TestCase):
    def test_is_exactly_the_list_eff_publishes(self):
        data = generator.WORD_LIST.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), generator.WORD_LIST_SHA256)
        self.assertEqual(len(data), 108_800)
        self.assertNotIn(b"\r", data, "a checkout that changed its line endings would break the check")

    def test_holds_7776_different_words_numbered_by_five_dice(self):
        lines = generator.WORD_LIST.read_text(encoding="ascii").splitlines()
        rolls = [line.split("\t")[0] for line in lines]
        self.assertEqual(rolls, ["".join(roll) for roll in itertools.product("123456", repeat=5)])
        words = generator.words()
        self.assertEqual((len(words), len(set(words))), (7776, 7776))
        self.assertTrue(all(word.replace("-", "").isalpha() and word.islower() for word in words))

    def test_no_word_is_the_start_of_another(self):
        # So that words run together can't be read two ways, which would lower the strength claimed.
        words = sorted(generator.words())
        self.assertFalse([first for first, second in itertools.pairwise(words) if second.startswith(first)])

    def test_a_changed_list_is_refused_rather_than_used(self):
        with tempfile.TemporaryDirectory() as folder:
            shortened = Path(folder) / "eff_large_wordlist.txt"
            shutil.copyfile(generator.WORD_LIST, shortened)
            with shortened.open("ab") as file:
                file.write(b"66667\textra\n")
            generator.words.cache_clear()
            self.addCleanup(generator.words.cache_clear)
            with patch.object(generator, "WORD_LIST", shortened), self.assertRaisesRegex(RuntimeError, "isn't the one"):
                generator.word_passphrase()


class GenerationTests(unittest.TestCase):
    def test_word_passphrases_use_the_list_and_the_secure_random_generator(self):
        picked = []
        real = generator.secrets.choice

        def recording(population):
            choice = real(population)
            picked.append(choice)
            return choice

        with patch.object(generator.secrets, "choice", side_effect=recording):
            phrase = generator.word_passphrase()
        self.assertEqual(len(picked), generator.DEFAULT_WORDS)
        self.assertEqual(phrase, "-".join(picked))
        self.assertTrue(set(picked) <= set(generator.words()))

    def test_character_passphrases_avoid_letters_that_look_alike(self):
        phrase = generator.character_passphrase()
        groups = phrase.split("-")
        self.assertEqual([len(group) for group in groups], [5] * 6)
        self.assertTrue(set("".join(groups)) <= set(generator.ALPHABET))
        self.assertFalse(set("0O1IL") & set(generator.ALPHABET))
        self.assertEqual(generate_passphrase().count("-"), 5, "the vault's generator is the same one")

    def test_they_differ_every_time(self):
        for kind in ("words", "characters"):
            with self.subTest(kind):
                self.assertEqual(len({generator.generate(kind) for _ in range(300)}), 300)

    def test_every_word_turns_up_about_as_often(self):
        counts = Counter(generator.secrets.choice(generator.words()) for _ in range(77_760))
        # Ten draws expected for each word. A biased pick would leave many out, or pile some up.
        self.assertGreater(len(counts), 7700)
        self.assertLess(max(counts.values()), 35)

    def test_nothing_shorter_than_one_word_or_group(self):
        for call in (lambda: generator.word_passphrase(0), lambda: generator.character_passphrase(0)):
            with self.assertRaises(ValueError):
                call()


class StrengthTests(unittest.TestCase):
    def test_the_bits_are_what_the_numbers_give(self):
        self.assertAlmostEqual(generator.bits("words"), 7 * math.log2(7776))
        self.assertAlmostEqual(generator.bits("words", 6), 77.5489, places=3)
        self.assertAlmostEqual(generator.bits("characters"), 30 * math.log2(30))

    def test_the_description_says_how_strong_and_why_in_plain_words(self):
        words = generator.describe("words")
        self.assertIn("7 random words", words)
        self.assertIn("about 90 bits", words)
        self.assertIn("10²⁷ possible passphrases", words)
        self.assertIn("Easy to type", words)
        characters = generator.describe("characters")
        self.assertIn("30 random letters and digits", characters)
        self.assertIn("about 147 bits", characters)
        self.assertIn("10⁴⁴", characters)


if __name__ == "__main__":
    unittest.main()
