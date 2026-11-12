"""Where to get GnuPG and make a key, in each system's own words."""

import unittest

from mindyourownbytes.gui import gnupg_help


class GnuPGHelpTests(unittest.TestCase):
    def test_each_system_is_pointed_at_its_own_tools(self):
        expected = {
            "win32": ("Gpg4win", "Kleopatra", "gpg4win.org"),
            "darwin": ("GPG Suite", "GPG Keychain", "gpgtools.org"),
            "linux": ("package manager", "gpg --full-generate-key", "gnupg.org"),
        }
        for platform, (installer, key_maker, site) in expected.items():
            with self.subTest(platform):
                words = gnupg_help.for_this_system(platform)
                for text in (words.banner, words.required, words.vault):
                    self.assertIn(installer, text)
                self.assertIn(key_maker, words.no_keys)
                self.assertIn(key_maker, words.make_key)
                self.assertIn(site, words.url)
                self.assertIn("{minimum}", words.banner)

    def test_no_system_is_told_to_get_another_systems_tools(self):
        for platform in ("darwin", "linux"):
            words = " ".join(gnupg_help.for_this_system(platform))
            self.assertNotIn("Gpg4win", words)
            self.assertNotIn("gpg.exe", words)
        windows = " ".join(gnupg_help.for_this_system("win32"))
        for other in ("brew", "apt install", "GPG Suite"):
            self.assertNotIn(other, windows)

    def test_other_unix_systems_get_the_linux_words(self):
        self.assertEqual(gnupg_help.for_this_system("freebsd14"), gnupg_help.for_this_system("linux"))


if __name__ == "__main__":
    unittest.main()
