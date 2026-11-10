"""The steps for restoring on another computer. tests/test_pinentry.py runs their commands for real."""

import unittest

from mindyourownbytes import recovery


class GuideTests(unittest.TestCase):
    def test_each_system_gets_the_same_five_steps(self):
        for platform in recovery.PLATFORMS:
            with self.subTest(platform):
                titles = [step.title for step in recovery.steps(platform)]
                self.assertEqual(titles, ["Gather what you need", "Set up the other computer",
                                          "Bring the secret that opens them", "Restore the files", "Afterwards"])

    def test_each_system_gets_commands_for_its_own_shell(self):
        windows = recovery.as_text("windows")
        self.assertIn("Get-ChildItem -Recurse -Filter *.gpg", windows)
        self.assertIn("PowerShell", windows)
        self.assertIn("/releases", windows)
        for platform in ("macos", "linux"):
            text = recovery.as_text(platform)
            self.assertIn("find . -name '*.gpg'", text)
            self.assertNotIn("Get-ChildItem", text)
        self.assertIn("brew install gnupg", recovery.as_text("macos"))
        self.assertIn("sudo apt install gnupg", recovery.as_text("linux"))

    def test_says_where_the_vault_goes_on_each_system(self):
        self.assertIn(r"%APPDATA%\mindyourownbytes\vault.gpg", recovery.as_text("windows"))
        self.assertIn("~/Library/Application Support/mindyourownbytes/vault.gpg", recovery.as_text("macos"))
        self.assertIn("~/.config/mindyourownbytes/vault.gpg", recovery.as_text("linux"))

    def test_the_plain_gpg_command_for_one_file_is_the_one_the_readme_gives(self):
        for platform in recovery.PLATFORMS:
            self.assertIn("gpg --output report.pdf --decrypt report.pdf.gpg", recovery.as_text(platform))

    def test_covers_every_kind_of_secret_and_what_to_do_afterwards(self):
        text = recovery.as_text("windows")
        for phrase in ("passphrase", "master passphrase", "private key", "gpg --import", "Nobody can recover",
                       "gpg --delete-secret-keys", "cloud service syncs"):
            self.assertIn(phrase, text)

    def test_as_text_numbers_the_steps_and_indents_commands(self):
        text = recovery.as_text("linux")
        self.assertTrue(text.startswith("How to restore files encrypted with mindyourownbytes, on Linux\n"))
        for number in range(1, 6):
            self.assertIn(f"\n{number}. ", text)
        self.assertIn("\n       gpg --import my-private-key.asc\n", text)
        self.assertTrue(text.endswith("\n"))
        self.assertNotIn("MYOB", text)


if __name__ == "__main__":
    unittest.main()
