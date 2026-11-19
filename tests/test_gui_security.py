"""The window's side of signing, signature verdicts, new passphrases, and leftover cleanup, with a real GnuPG."""

import os
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes import signatures, workspace
from tests.test_gui import HAS_QT, MASTER, GuiCase, app

if HAS_QT:
    from PySide6.QtWidgets import QDialogButtonBox, QMessageBox

    from mindyourownbytes.gui import main_window
    from mindyourownbytes.gui.dialogs import PassphraseDialog, VaultEntryDialog
    from mindyourownbytes.gui.main_window import MainWindow


class SigningCase(GuiCase):
    def setUp(self):
        super().setUp()
        self.me = self.generate_key("Alex Example <alex@example.invalid>")
        self.window.refresh_keys()

    def finish(self):
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)

    def encrypt_to_me(self, name: str = "a.txt", sign: bool = False) -> Path:
        self.window.set_operation("encrypt")
        self.window.add_paths([str(self.write(name, b"made here"))])
        self.select_method("public-key")
        self.window.key_combo.setCurrentIndex(self.window.key_combo.findData(self.me))
        self.window.sign_box.setChecked(sign)
        self.window.start()
        self.finish()
        return self.root / "exports" / f"{name}.gpg"

    def restore(self, *paths: Path):
        self.window.clear_files()
        self.window.set_operation("restore")
        self.window.add_paths([str(path) for path in paths])
        self.window.start()
        self.finish()

    def row(self, index: int = 0):
        return self.window.table.item(index, 3)

    def forge(self, name: str = "invoice.pdf", content: bytes = b"pay mallory") -> tuple[Path, str]:
        """A file for my key, signed by someone else's, whose public key I have but never verified."""
        home = self.root / "sender"
        if not home.exists():
            home.mkdir(mode=0o700)
            gpgconf = Path(self.gpg).with_name("gpgconf.exe" if os.name == "nt" else "gpgconf")
            self.addCleanup(subprocess.run, [str(gpgconf), "--homedir", str(home), "--kill", "all"],
                            capture_output=True, check=False)
        env = dict(os.environ, GNUPGHOME=str(home))
        self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key",
                     "Mallory <mallory@example.invalid>", "default", "default", "1y", env=env)
        listing = self.run_gpg("--with-colons", "--fingerprint", "--list-keys", "Mallory", env=env).stdout.decode()
        mallory = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        self.run_gpg("--import", input=self.run_gpg("--export", self.me).stdout, env=env)
        forged = self.root / "Downloads" / f"{name}.gpg"
        forged.parent.mkdir(exist_ok=True)
        self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--trust-model", "always", "--sign",
                     "--encrypt", "--recipient", self.me, "--output", str(forged),
                     str(self.write(name, content)), env=env)
        self.run_gpg("--import", input=self.run_gpg("--export", mallory, env=env).stdout)
        return forged, mallory

    def restore_anyway(self, answer=None):
        """Click "Restore anyway…" below the list, and answer the question it asks."""
        button = next(button for button in self.window.result_bar._actions
                      if button.text() == main_window.HELD_COPY["action"])
        self.message_boxes["warning"].reset_mock()
        self.message_boxes["warning"].return_value = answer or QMessageBox.StandardButton.Yes
        button.click()
        self.finish()
        self.message_boxes["warning"].return_value = QMessageBox.StandardButton.Yes

    def actions(self) -> list[str]:
        return [button.text() for button in self.window.result_bar._actions]

    def policy(self, name: str):
        return next(action for action in self.window.signature_group.actions() if action.data() == name)


class SigningControlTests(SigningCase):
    def test_signing_is_offered_only_when_encrypting_to_a_key(self):
        self.select_method("public-key")
        self.assertFalse(self.window.sign_box.isHidden())
        self.assertEqual(self.window.signer_combo.currentData(), self.me)
        tooltip = self.window.signer_combo.itemData(0, main_window.Qt.ItemDataRole.ToolTipRole)
        self.assertIn(signatures.spaced(self.me), tooltip, "the full fingerprint, since names prove nothing")
        self.assertEqual(self.window.signer_combo.accessibleName(), "Your key to sign with")
        self.select_method("once")
        self.assertTrue(self.window.sign_box.isHidden())
        self.window.set_operation("restore")
        self.assertTrue(self.window.sign_box.isHidden())

    def test_the_choice_is_remembered(self):
        self.select_method("public-key")
        self.window.sign_box.setChecked(False)
        self.assertEqual(self.settings.value("sign_files"), "false")
        self.window.sign_box.setChecked(True)
        self.assertEqual(self.settings.value("sign_files"), "true")
        self.assertEqual(self.settings.value("sign_with"), self.me)

    def test_files_for_a_key_are_signed_unless_someone_chose_otherwise(self):
        self.select_method("public-key")
        self.assertTrue(self.window.sign_box.isChecked(), "on whenever there's a key to sign with")
        self.assertIsNone(self.settings.value("sign_files"), "a default, not a choice anyone made")
        self.window.add_paths([str(self.write("a.txt"))])
        self.window.key_combo.setCurrentIndex(self.window.key_combo.findData(self.me))
        self.window.start()
        self.finish()
        self.assertEqual(self.row().text(), "Signed and encrypted, not checked")
        self.restore(self.root / "exports" / "a.txt.gpg")
        self.assertEqual(self.row().text(), "Restored, signed by Alex Example, matches your record")

    def test_a_choice_not_to_sign_is_kept(self):
        self.settings.setValue("sign_files", "false")
        window = MainWindow(self.settings, self.root / "app" / "other-vault.gpg")
        self.addCleanup(window.close)
        window.set_method("public-key")
        self.assertFalse(window.sign_box.isChecked())

    def test_without_a_key_that_can_sign_signing_is_off_and_encrypting_still_works(self):
        self.run_gpg("--yes", "--delete-secret-keys", self.me)
        self.window.refresh_keys()
        if self.window.signer_combo.currentData():
            self.skipTest("this GnuPG will not delete a secret key in batch mode")
        self.select_method("public-key")
        self.assertFalse(self.window.sign_box.isChecked())
        self.window.add_paths([str(self.write("a.txt"))])
        self.window.key_combo.setCurrentIndex(self.window.key_combo.findData(self.me))
        with patch.object(self.window, "_confirm_recipient", return_value=True):
            self.window.start()
        self.finish()
        self.assertTrue((self.root / "exports" / "a.txt.gpg").exists())

    def test_without_a_key_that_can_sign_nothing_starts(self):
        self.run_gpg("--yes", "--delete-secret-keys", self.me)
        self.window.refresh_keys()
        if self.window.signer_combo.currentData():
            self.skipTest("this GnuPG will not delete a secret key in batch mode")
        self.settings.setValue("sign_files", "true")
        self.window.sign_box.setChecked(True)
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("public-key")
        self.assertFalse(self.window.sign_box.isEnabled())
        with patch.object(self.window, "_confirm_recipient", return_value=True):
            self.window.start()
        self.assertFalse(self.window.running)
        self.assertIn("no key that can sign", self.message_boxes["warning"].call_args.args[2])
        self.assertFalse((self.root / "exports").exists())


class SignedRoundTripTests(SigningCase):
    def test_a_signed_file_says_so_when_made_and_when_restored(self):
        encrypted = self.encrypt_to_me(sign=True)
        self.assertEqual(self.row().text(), "Signed and encrypted, not checked")
        self.assertIn(signatures.spaced(self.me), self.row().toolTip())
        self.assertIn("signed and encrypted", self.window.result_bar.title_label.text())
        self.restore(encrypted)
        self.assertEqual((self.root / "restored" / "a.txt").read_bytes(), b"made here")
        self.assertEqual(self.row().text(), "Restored, signed by Alex Example, matches your record")
        self.assertIn(signatures.spaced(self.me), self.row().toolTip())
        self.assertEqual(self.window.result_bar.property("kind"), "success")
        self.assertIn("1 signed by a key you've verified", self.window.result_bar.text())

    def test_an_unsigned_file_for_a_key_waits_until_you_say_to_restore_it(self):
        self.restore(self.encrypt_to_me())
        self.assertEqual(list((self.root / "restored").rglob("*")), [], "decrypted, then deleted again")
        self.assertEqual(self.row().text(), "Not restored yet, not signed")
        self.assertIn("anyone who has your public key", self.row().toolTip())
        self.assertEqual(self.window.result_bar.property("kind"), "warning")
        self.assertIn("nothing shows who made it", self.window.result_bar.text())
        self.assertIn("0 failed · 1 not restored yet", self.window.status_text.text())
        self.assertIn("Restore anyway…", self.actions())
        self.restore_anyway()
        question = self.message_boxes["warning"].call_args.args
        self.assertEqual(question[1], "Restore this file anyway?")
        self.assertIn("• a.txt.gpg: not signed", question[2])
        self.assertEqual((self.root / "restored" / "a.txt").read_bytes(), b"made here")
        self.assertEqual(self.row().text(), "Restored, not signed, matches your record")
        self.assertIn("1 not signed", self.window.result_bar.text())
        self.assertNotIn("verified secure", self.window.result_bar.text().casefold())

    def test_saying_no_restores_nothing(self):
        self.restore(self.encrypt_to_me())
        self.restore_anyway(QMessageBox.StandardButton.No)
        self.assertEqual(list((self.root / "restored").rglob("*")), [])
        self.assertEqual(self.row().text(), "Not restored yet, not signed")
        self.assertIn("Restore anyway…", self.actions(), "still on offer")

    def test_never_restoring_them_refuses_without_asking(self):
        encrypted = self.encrypt_to_me()
        self.window.signature_action.setChecked(True)
        self.assertEqual(self.settings.value("signature_policy"), "refuse")
        self.restore(encrypted)
        self.assertFalse((self.root / "restored" / "a.txt").exists())
        self.assertEqual(self.window.result_bar.property("kind"), "error")
        self.assertIn("isn't signed", self.row().toolTip())
        self.assertNotIn("Restore anyway…", self.actions())
        self.assertEqual(list((self.root / "restored").rglob("*")), [], "nothing left, not even a workspace")

    def test_a_file_signed_with_a_key_you_havent_verified_waits_and_shows_the_fingerprint(self):
        forged, mallory = self.forge()
        self.restore(forged)
        self.assertEqual(self.row().text(), "Not restored yet, signed with a key you haven't verified")
        self.assertIn("anyone can make a key with any name", self.row().toolTip())
        self.assertNotIn("Mallory", self.row().text(), "an unverified name is never presented as the signer")
        self.assertFalse((self.root / "restored" / "invoice.pdf").exists())
        self.restore_anyway()
        question = self.message_boxes["warning"].call_args.args[2]
        self.assertIn(f"• invoice.pdf.gpg: signed with a key you haven't verified, {signatures.spaced(mallory)}",
                      question)
        self.assertNotIn("Mallory", question)
        self.assertEqual((self.root / "restored" / "invoice.pdf").read_bytes(), b"pay mallory")
        self.assertEqual(self.row().text(), "Restored, signed with a key you haven't verified")
        self.assertEqual(self.window.result_bar.property("kind"), "warning")

    def test_a_file_that_shows_something_else_when_decrypted_again_isnt_restored(self):
        encrypted = self.encrypt_to_me()
        self.restore(encrypted)
        # Swapped, after you were asked about an unsigned file, for one that someone else signed.
        forged, _mallory = self.forge("a.txt", b"pay mallory")
        shutil.copyfile(forged, encrypted)
        self.restore_anyway()
        self.assertEqual(list((self.root / "restored").rglob("*")), [], "not what you agreed to")
        self.assertEqual(self.row().text(), "Not restored yet, signed with a key you haven't verified")

    def test_restoring_them_and_saying_so_is_only_for_advanced_mode(self):
        encrypted = self.encrypt_to_me()
        self.policy("allow").setChecked(True)
        self.assertEqual(self.settings.value("signature_policy"), "allow")
        self.restore(encrypted)
        self.assertEqual(self.row().text(), "Restored, not signed, matches your record")
        self.assertNotIn("Restore anyway…", self.actions())
        self.window.advanced_action.setChecked(False)
        self.assertEqual(self.window.signature_policy(), "ask", "simple mode never restores them without asking")
        self.assertFalse(self.window.signature_menu.menuAction().isVisible())

    def test_never_still_applies_in_simple_mode(self):
        self.window.signature_action.setChecked(True)
        self.window.advanced_action.setChecked(False)
        self.assertEqual(self.window.signature_policy(), "refuse")

    def test_the_earlier_switch_carries_over_as_never(self):
        self.settings.remove("signature_policy")
        self.settings.setValue("require_signature", "true")
        window = MainWindow(self.settings, self.root / "app" / "other-vault.gpg")
        self.addCleanup(window.close)
        self.assertEqual(window.signature_policy(), "refuse")
        self.assertTrue(window.signature_action.isChecked())

    def test_passphrase_files_are_never_held(self):
        self.window.set_operation("encrypt")
        self.window.add_paths([str(self.write("typed.txt", b"by passphrase"))])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.window.clear_files()
        self.window.set_operation("restore")
        self.window.add_paths([str(self.root / "exports" / "typed.txt.gpg")])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.assertEqual((self.root / "restored" / "typed.txt").read_bytes(), b"by passphrase")
        self.assertNotIn("Restore anyway…", self.actions())


class SavedPassphraseTests(GuiCase):
    def test_a_weak_saved_passphrase_cant_protect_new_files_but_still_opens_old_ones(self):
        self.window.vault.create(MASTER)
        entry = self.window.vault.add("Old", "password1")
        self.window.vault_page.changed.emit()
        old = self.root / "old.txt.gpg"
        self.run_gpg("--pinentry-mode", "loopback", "--passphrase", "password1", "--symmetric", "--output", str(old),
                     str(self.write("old.txt", b"from before")))
        self.window.add_paths([str(self.write("new.txt"))])
        self.select_method("saved")
        self.window.saved_combo.setCurrentIndex(self.window.saved_combo.findData(entry.id))
        self.window.start()
        self.assertFalse(self.window.running)
        self.assertIn("too easy to guess to protect new files", self.message_boxes["warning"].call_args.args[2])
        self.assertFalse((self.root / "exports").exists())
        self.window.set_operation("restore")
        self.window.add_paths([str(old)])
        self.select_method("saved")
        self.window.saved_combo.setCurrentIndex(self.window.saved_combo.findData(entry.id))
        self.window.start()
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)
        self.assertEqual((self.root / "restored" / "old.txt").read_bytes(), b"from before")


class LeftoverCleanupTests(GuiCase):
    def left_by_a_crash(self) -> Path:
        """A workspace with readable data, noted by a copy of the app that has since stopped."""
        other = workspace.Journal(self.root / "app" / "unfinished")
        restored = self.root / "restored"
        restored.mkdir(exist_ok=True)
        space = workspace.create(restored, other)
        (space.path / "decrypted-0").write_bytes(b"readable")
        other.close()
        return space.path

    def test_the_next_start_offers_to_delete_what_a_crash_left(self):
        left = self.left_by_a_crash()
        window = MainWindow(self.settings, self.root / "app" / "vault.gpg")
        self.addCleanup(window.close)
        self.wait_until(lambda: not left.exists(), timeout=10)
        question = next(call for call in self.message_boxes["warning"].call_args_list
                        if call.args[1] == "An earlier restore didn't finish")
        self.assertIn(str(left), question.args[2])
        self.assertIn("doesn't securely erase", question.args[2])

    def test_saying_no_keeps_them_for_next_time(self):
        left = self.left_by_a_crash()
        self.message_boxes["warning"].return_value = QMessageBox.StandardButton.No
        self.window.offer_cleanup(True)
        self.assertTrue(left.exists())
        self.assertEqual([leftover.path for leftover in self.window.journal.leftovers()], [left])

    def test_asking_with_nothing_left_says_so(self):
        self.window.offer_cleanup(True)
        self.assertEqual(self.message_boxes["information"].call_args.args[1], "Nothing to clean up")

    def test_a_folder_that_isnt_provably_the_apps_is_listed_and_never_touched(self):
        left = self.left_by_a_crash()
        (left / workspace.MARKER).write_bytes(b"0" * 32)  # Not the token that was noted.
        self.window.offer_cleanup(True)
        self.assertTrue((left / "decrypted-0").exists())
        report = self.message_boxes["warning"].call_args.args
        self.assertEqual(report[1], "Some folders are still there")
        self.assertIn("couldn't confirm it made them", report[2])


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class NewPassphraseDialogTests(unittest.TestCase):
    def setUp(self):
        app()

    def dialog(self, **options):
        from shiboken6 import delete
        dialog = PassphraseDialog(None, "t", "m", confirm=True, min_length=8, **options)
        self.addCleanup(delete, dialog)
        return dialog

    def ok(self, dialog) -> bool:
        return dialog.buttons.button(QDialogButtonBox.StandardButton.Ok).isEnabled()

    def type_twice(self, dialog, passphrase: str) -> None:
        dialog.first.setText(passphrase)
        dialog.second.setText(passphrase)

    def test_a_common_passphrase_is_refused_with_the_reason(self):
        dialog = self.dialog()
        self.type_twice(dialog, "Password123!")
        self.assertFalse(self.ok(dialog))
        self.assertTrue(dialog.hint.text().startswith("Weak"))
        self.assertEqual(dialog.first.accessibleDescription(), dialog.hint.text(), "screen readers hear it too")

    def test_the_rating_shows_before_the_passphrase_is_repeated(self):
        dialog = self.dialog()
        dialog.first.setText("seven taxis argue softly about pianos")
        self.assertFalse(self.ok(dialog))
        self.assertTrue(dialog.hint.text().startswith("Better"))

    def test_a_good_choice_is_accepted_as_better_never_strong(self):
        dialog = self.dialog()
        self.type_twice(dialog, "seven taxis argue softly about pianos")
        self.assertTrue(self.ok(dialog))
        self.assertTrue(dialog.hint.text().startswith("Better"))

    def test_typing_an_existing_passphrase_is_never_judged(self):
        from shiboken6 import delete
        dialog = PassphraseDialog(None, "Enter the passphrase", "m")
        self.addCleanup(delete, dialog)
        dialog.first.setText("password")
        self.assertTrue(self.ok(dialog), "old files must still open")
        self.assertEqual(dialog.hint.text(), "")

    def test_a_vault_entry_says_a_weak_passphrase_cant_protect_new_files_but_can_be_saved(self):
        from shiboken6 import delete
        dialog = VaultEntryDialog(None)
        self.addCleanup(delete, dialog)
        dialog.label.setText("Old files")
        dialog.passphrase_field.setText("letmein")
        self.assertIn("can't protect new files", dialog.hint.text())
        self.assertTrue(dialog.buttons.button(QDialogButtonBox.StandardButton.Save).isEnabled())
        dialog.generator.generate()
        self.assertTrue(dialog.hint.isHidden(), "a generated one's strength is shown by the generator")


if __name__ == "__main__":
    unittest.main()
