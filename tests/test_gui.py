"""Drive the real window headlessly, with a real GnuPG behind it."""

import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tests.support import GpgTestCase

HAS_QT = importlib.util.find_spec("PySide6") is not None

if HAS_QT:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QEventLoop, QSettings
    from PySide6.QtWidgets import QApplication, QInputDialog, QLabel, QMessageBox, QWidget

    from mindyourownbytes.gui import main_window
    from mindyourownbytes.gui.dialogs import PassphraseDialog
    from mindyourownbytes.gui.main_window import MainWindow

PASSPHRASE = "a perfectly good test passphrase"
MASTER = "a long master passphrase"


def app() -> "QApplication":
    return QApplication.instance() or QApplication([])


def isolated_settings(folder: Path) -> "QSettings":
    settings = QSettings(str(folder / "settings.ini"), QSettings.Format.IniFormat)
    settings.setValue("output_encrypt", str(folder / "exports"))
    settings.setValue("output_restore", str(folder / "restored"))
    return settings


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class WithoutGnuPGTests(unittest.TestCase):
    """The window must open, and explain itself, on a machine with no GnuPG."""

    def setUp(self):
        app()
        temp = tempfile.TemporaryDirectory(prefix="myobtest", ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.settings = isolated_settings(self.folder)
        patcher = patch.object(main_window, "find_gpg", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_opens_and_navigates(self):
        window = MainWindow(self.settings, self.folder / "vault.gpg")
        self.addCleanup(window.close)
        self.assertEqual(window.windowTitle(), "mindyourownbytes")
        self.assertIn("not found", window.gpg_status.text())
        for action, page in ((window.show_library, window.library_page), (window.show_vault, window.vault_page)):
            action()
            self.assertIs(window.pages.currentWidget(), page)
        window.set_operation("restore")
        self.assertEqual(window.operation, "restore")
        self.assertIs(window.pages.currentWidget(), window.transfer_page)

    def test_stale_saved_gnupg_path_falls_back_to_detection(self):
        self.settings.setValue("gpg_path", str(self.folder / "uninstalled" / "gpg.exe"))
        with patch.object(main_window, "find_gpg", return_value="detected") as detect, patch.object(
            main_window, "is_valid_gpg", return_value=False
        ):
            window = MainWindow(self.settings, self.folder / "vault.gpg")
            self.addCleanup(window.close)
        detect.assert_called()
        self.assertEqual(window.gpg, "detected")

    def test_vault_explains_when_gnupg_is_missing(self):
        window = MainWindow(self.settings, self.folder / "vault.gpg")
        self.addCleanup(window.close)
        with patch.object(QMessageBox, "warning") as warning:
            window.vault_page.create_vault()
        self.assertIn("GnuPG", warning.call_args.args[1])
        self.assertFalse((self.folder / "vault.gpg").exists())

    def test_window_is_not_inflated_and_fits_a_small_laptop(self):
        # Regression: widgets hidden during setup still counted towards the size
        # at first show, so the window opened about 250 pixels too wide.
        window = MainWindow(self.settings, self.folder / "vault.gpg")
        self.addCleanup(window.close)
        window.show()
        QApplication.processEvents()
        self.assertLessEqual(window.width(), max(1100, window.minimumSizeHint().width()))
        self.assertLessEqual(window.minimumSizeHint().height(), 640)

    def test_ui_never_uses_the_abbreviated_name(self):
        # "MYOB" is the name of an unrelated accounting software company.
        window = MainWindow(self.settings, self.folder / "vault.gpg")
        self.addCleanup(window.close)
        self.assertFalse([label.text() for label in window.findChildren(QLabel) if "MYOB" in label.text()])


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class GuiCase(GpgTestCase):
    def setUp(self):
        super().setUp()
        app()
        self.settings = isolated_settings(self.root)
        self.message_boxes = {}
        for name in ("information", "warning", "critical"):
            patcher = patch.object(QMessageBox, name, return_value=QMessageBox.StandardButton.Yes)
            self.message_boxes[name] = patcher.start()
            self.addCleanup(patcher.stop)
        self.window = MainWindow(self.settings, self.root / "app" / "vault.gpg")
        self.addCleanup(self.close_window)

    def close_window(self):
        self.wait_until(lambda: self.window._thread is None)
        self.window.close()

    def wait_until(self, predicate, timeout=60):
        deadline = time.monotonic() + timeout
        while not predicate():
            if time.monotonic() > deadline:
                self.fail("timed out waiting for the background job")
            QApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)

    def write(self, name: str, content: bytes = b"private") -> Path:
        path = self.root / "input" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def select_method(self, data: str):
        self.window.method_combo.setCurrentIndex(self.window.method_combo.findData(data))

    def run_with_typed_passphrase(self, passphrase: str = PASSPHRASE):
        dialog = MagicMock()
        dialog.exec.return_value = True
        dialog.passphrase.return_value = passphrase
        with patch.object(main_window, "PassphraseDialog", return_value=dialog):
            self.window.start()
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)


class TransferFlowTests(GuiCase):
    def test_full_encrypt_then_restore_with_one_passphrase_for_the_batch(self):
        for name in ("a.txt", "b.txt", "c.txt"):
            self.write(name, name.encode())
        self.window.add_paths([str(self.root / "input")])
        self.assertEqual(len(self.window.items), 3)
        self.select_method("once")
        self.window.collection_combo.setCurrentText("Taxes")
        self.run_with_typed_passphrase()
        exports = sorted((self.root / "exports" / "Taxes" / "input").iterdir())
        self.assertEqual([path.name for path in exports], ["a.txt.gpg", "b.txt.gpg", "c.txt.gpg"])
        self.assertEqual(self.window.table.item(0, 3).text(), "✓ Ready")
        self.message_boxes["information"].assert_called()

        self.window.set_operation("restore")
        self.window.add_paths([str(self.root / "exports")])
        self.select_method("once")
        self.run_with_typed_passphrase()
        restored = self.root / "restored" / "exports" / "Taxes" / "input" / "b.txt"
        self.assertEqual(restored.read_bytes(), b"b.txt")

    def test_wrong_passphrase_is_reported_not_hidden_behind_a_success_message(self):
        encrypted_source = self.write("a.txt")
        self.window.add_paths([str(encrypted_source)])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.message_boxes["information"].reset_mock()
        self.window.set_operation("restore")
        self.window.add_paths([str(self.root / "exports" / "a.txt.gpg")])
        self.select_method("once")
        self.run_with_typed_passphrase("not the right one")
        self.message_boxes["information"].assert_not_called()
        self.assertIn("failed", self.message_boxes["warning"].call_args.args[1].lower())
        self.assertIn("Wrong passphrase", self.message_boxes["warning"].call_args.args[2])
        self.assertEqual(self.window.table.item(0, 3).text(), "✕ Error")

    def test_cancel_button_works_again_on_the_next_job(self):
        # Regression: it was disabled on first use and never enabled again.
        self.window.running = True
        self.window.worker = MagicMock()
        self.window._set_busy(True)
        self.window.cancel()
        self.assertFalse(self.window.cancel_button.isEnabled())
        self.window.worker = None
        self.window.running = False
        self.window._set_busy(False)
        self.window._set_busy(True)
        self.assertTrue(self.window.cancel_button.isEnabled())
        self.window._set_busy(False)

    def test_cancelling_a_job_stops_it_and_leaves_no_partial_files(self):
        for index in range(30):
            self.write(f"f{index}.txt")
        self.window.add_paths([str(self.root / "input")])
        self.select_method("once")
        dialog = MagicMock()
        dialog.exec.return_value = True
        dialog.passphrase.return_value = PASSPHRASE
        with patch.object(main_window, "PassphraseDialog", return_value=dialog):
            self.window.start()
        self.window.cancel()
        self.wait_until(lambda: not self.window.running)
        self.assertIn("cancelled", self.window.status_text.text())
        self.assertLess(len(list((self.root / "exports").rglob("*.gpg"))), 30)
        self.assertFalse(list((self.root / "exports").rglob("*.partial")))

    def test_invalid_collection_name_stops_before_any_work(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        self.window.collection_combo.setCurrentText("../../escape")
        self.window.start()
        self.assertFalse(self.window.running)
        self.message_boxes["warning"].assert_called()
        self.assertFalse((self.root / "escape").exists())

    def test_warns_when_originals_are_already_in_a_synced_folder(self):
        source = self.write("OneDrive/a.txt")
        self.window.add_paths([str(source)])
        self.select_method("once")
        self.message_boxes["warning"].return_value = QMessageBox.StandardButton.No
        self.window.start()
        self.assertFalse(self.window.running)
        self.assertIn("already", self.message_boxes["warning"].call_args.args[1])

    def test_warns_before_restoring_plaintext_into_a_synced_folder(self):
        self.settings.setValue("output_restore", str(self.root / "Dropbox" / "restored"))
        self.window.set_operation("restore")
        path = self.root / "input" / "a.txt.gpg"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"x")
        self.window.add_paths([str(path)])
        self.message_boxes["warning"].return_value = QMessageBox.StandardButton.No
        self.window.start()
        self.assertFalse(self.window.running)
        self.assertIn("synced", self.message_boxes["warning"].call_args.args[1])

    def test_warns_before_encrypting_to_a_key_you_cannot_decrypt_with(self):
        other = self.root / "other"
        other.mkdir(mode=0o700)
        env = dict(os.environ, GNUPGHOME=str(other))
        self.run_gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-generate-key",
                     "Colleague <c@example.invalid>", "default", "default", "1y", env=env)
        self.run_gpg("--import", input=self.run_gpg("--export", env=env).stdout)
        self.window.refresh_keys()
        self.assertIn("someone else's key", self.window.key_combo.itemText(0))
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("public-key")
        self.message_boxes["warning"].return_value = QMessageBox.StandardButton.No
        self.window.start()
        self.assertFalse(self.window.running)
        self.assertIn("won't be able to restore", self.message_boxes["warning"].call_args.args[1])

    def test_own_key_encrypts_without_a_warning(self):
        self.generate_key("Me <me@example.invalid>")
        self.window.refresh_keys()
        self.assertIn("your key", self.window.key_combo.itemText(0))
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("public-key")
        self.window.start()
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)
        self.message_boxes["warning"].assert_not_called()
        self.assertTrue((self.root / "exports" / "a.txt.gpg").exists())

    def test_unreadable_folder_produces_a_visible_warning(self):
        real_walk = os.walk

        def walk_with_denied_folder(top, **kwargs):
            kwargs["onerror"](PermissionError(13, "denied", str(Path(top) / "locked")))
            yield from real_walk(top, **kwargs)

        self.write("a.txt")
        with patch("mindyourownbytes.core.os.walk", walk_with_denied_folder):
            self.window.add_paths([str(self.root / "input")])
        self.assertIn("could not be read", self.message_boxes["warning"].call_args.args[1])
        self.assertIn("locked", self.message_boxes["warning"].call_args.args[2])


class VaultFlowTests(GuiCase):
    def create_vault(self):
        self.window.vault.create(MASTER)
        self.window.vault_page.refresh()
        self.window.vault_page.changed.emit()

    def test_locked_vault_never_silently_picks_a_passphrase(self):
        self.create_vault()
        self.window.vault.add("Taxes", "tax passphrase here")
        self.window.vault_page.lock()
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("saved")
        self.assertTrue(self.window.vault_button.isVisible() or not self.window.isVisible())

        def unlock():
            self.window.vault.unlock(MASTER)
            self.window.vault_page.changed.emit()
            return True

        with patch.object(self.window.vault_page, "request_unlock", side_effect=unlock):
            self.window.start()
        self.assertFalse(self.window.running)
        self.assertIn("Choose a saved passphrase", self.window.status_text.text())
        self.assertFalse((self.root / "exports").exists())

    def test_encrypt_with_saved_passphrase_then_restore_by_trying_all(self):
        self.create_vault()
        self.window.vault.add("Other", "some other passphrase")
        entry = self.window.vault.add("Taxes", "tax passphrase here")
        self.window.vault_page.changed.emit()
        self.window.add_paths([str(self.write("a.txt", b"via saved"))])
        self.select_method("saved")
        self.window.saved_combo.setCurrentIndex(self.window.saved_combo.findData(entry.id))
        self.window.start()
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)
        encrypted = self.root / "exports" / "a.txt.gpg"
        direct = self.run_gpg("--pinentry-mode", "loopback", "--passphrase", "tax passphrase here",
                              "--no-symkey-cache", "--output", "-", "--decrypt", str(encrypted))
        self.assertEqual(direct.stdout, b"via saved")

        self.window.set_operation("restore")
        self.window.add_paths([str(encrypted)])
        self.select_method("saved")
        self.assertEqual(self.window.saved_combo.itemText(0), "Try every saved passphrase")
        self.window.start()
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)
        self.assertEqual((self.root / "restored" / "a.txt").read_bytes(), b"via saved")

    def test_page_tracks_setup_locked_and_unlocked_states(self):
        page = self.window.vault_page
        self.assertIs(page.stack.currentWidget(), page.setup_panel)
        self.create_vault()
        self.assertIs(page.stack.currentWidget(), page.unlocked_panel)
        self.window.vault.add("Taxes", "tax passphrase here", note="2026")
        page.refresh()
        self.assertEqual(page.table.rowCount(), 1)
        self.assertEqual(page.table.item(0, 0).text(), "Taxes")
        self.assertNotIn("tax passphrase here", [page.table.item(0, c).text() for c in range(3)])
        page.lock()
        self.assertIs(page.stack.currentWidget(), page.locked_panel)
        self.assertEqual(page.table.rowCount(), 0)
        self.assertFalse(self.window.vault.unlocked)

    def test_copy_then_clear_keeps_secret_only_briefly(self):
        self.create_vault()
        self.window.vault.add("Taxes", "tax passphrase here")
        page = self.window.vault_page
        page.refresh()
        page.table.selectRow(0)
        page.copy_selected()
        clipboard = QApplication.clipboard()
        if clipboard.text() != "tax passphrase here":
            self.skipTest("this platform has no clipboard to test against")
        page.clipboard.clear()
        self.assertEqual(clipboard.text(), "")

    def test_clearing_does_not_erase_something_the_user_copied_since(self):
        self.create_vault()
        self.window.vault.add("Taxes", "tax passphrase here")
        page = self.window.vault_page
        page.refresh()
        page.table.selectRow(0)
        page.copy_selected()
        clipboard = QApplication.clipboard()
        clipboard.setText("the user's own text")
        if clipboard.text() != "the user's own text":
            self.skipTest("this platform has no clipboard to test against")
        page.clipboard.clear()
        self.assertEqual(clipboard.text(), "the user's own text")

    def test_auto_lock_fires_and_drops_the_secrets(self):
        self.create_vault()
        self.window.vault_page.touch()
        self.assertTrue(self.window.vault_page._lock_timer.isActive())
        self.window.vault_page._lock_timer.timeout.emit()
        self.assertFalse(self.window.vault.unlocked)
        self.assertEqual(self.window.saved_combo.count(), 0)

    def test_closing_the_window_locks_the_vault(self):
        self.create_vault()
        self.window.close()
        self.assertFalse(self.window.vault.unlocked)


class LibraryFlowTests(GuiCase):
    def export(self, relative: str) -> Path:
        path = self.root / "exports" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"ciphertext")
        return path

    def test_lists_filters_and_searches(self):
        self.export("Taxes/return.pdf.gpg")
        self.export("Medical/scan.png.gpg")
        self.export("loose.txt.gpg")
        self.window.show_library()
        page = self.window.library_page
        self.assertEqual(page.table.rowCount(), 3)
        page.collection_filter.setCurrentIndex(page.collection_filter.findData("Taxes"))
        self.assertEqual([e.display_name for e in page.visible], ["return.pdf"])
        page.collection_filter.setCurrentIndex(page.collection_filter.findData(""))
        self.assertEqual([e.display_name for e in page.visible], ["loose.txt"])
        page.collection_filter.setCurrentIndex(0)
        page.search.setText("SCAN")
        self.assertEqual([e.display_name for e in page.visible], ["scan.png"])

    def test_restore_selected_queues_them_keeping_their_folders(self):
        self.export("Taxes/2026/return.pdf.gpg")
        self.window.show_library()
        page = self.window.library_page
        page.table.selectRow(0)
        page.restore_selected()
        self.assertIs(self.window.pages.currentWidget(), self.window.transfer_page)
        self.assertEqual(self.window.operation, "restore")
        self.assertEqual(self.window.items[0].relative, Path("Taxes/2026/return.pdf.gpg"))

    def test_move_selected_to_a_collection(self):
        path = self.export("loose.txt.gpg")
        self.window.show_library()
        page = self.window.library_page
        page.table.selectRow(0)
        with patch("mindyourownbytes.gui.library_page.QInputDialog.getItem", return_value=("Archive", True)):
            page.move_selected()
        self.assertFalse(path.exists())
        self.assertTrue((self.root / "exports" / "Archive" / "loose.txt.gpg").exists())
        self.assertEqual(page.visible[0].collection, "Archive")

    def test_new_collection_appears_in_both_screens(self):
        self.window.show_library()
        with patch("mindyourownbytes.gui.library_page.QInputDialog.getText", return_value=("Taxes", True)):
            self.window.library_page.new_collection()
        self.assertGreaterEqual(self.window.library_page.collection_filter.findData("Taxes"), 0)
        self.window.set_operation("encrypt")
        self.assertGreaterEqual(self.window.collection_combo.findText("Taxes"), 0)


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class DialogReadabilityTests(unittest.TestCase):
    """Regression: dialogs inherited light text on a light background, which made
    every warning in the app, including the security ones, effectively invisible."""

    def setUp(self):
        app()
        self.parent = QWidget()
        self.parent.setStyleSheet(main_window.STYLESHEET.read_text(encoding="utf-8"))

    def assert_dark_surface(self, widget) -> None:
        widget.resize(420, 200)
        widget.ensurePolished()
        image = widget.grab().toImage()
        self.assertLess(image.pixelColor(2, 2).lightness(), 90)
        widget.close()

    def test_message_box(self):
        box = QMessageBox(self.parent)
        box.setText("A warning the user must be able to read")
        self.assert_dark_surface(box)

    def test_passphrase_dialog(self):
        self.assert_dark_surface(PassphraseDialog(self.parent, "t", "m"))

    def test_input_dialog(self):
        self.assert_dark_surface(QInputDialog(self.parent))


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class PassphraseDialogTests(unittest.TestCase):
    def setUp(self):
        app()

    def ok_enabled(self, dialog) -> bool:
        from PySide6.QtWidgets import QDialogButtonBox
        return dialog.buttons.button(QDialogButtonBox.StandardButton.Ok).isEnabled()

    def test_confirm_mode_requires_matching_entries_and_minimum_length(self):
        dialog = PassphraseDialog(None, "t", "m", confirm=True, min_length=12)
        self.assertFalse(self.ok_enabled(dialog))
        dialog.first.setText("short")
        self.assertFalse(self.ok_enabled(dialog))
        dialog.first.setText("long enough passphrase")
        self.assertFalse(self.ok_enabled(dialog))
        dialog.second.setText("different passphrase!")
        self.assertFalse(self.ok_enabled(dialog))
        dialog.second.setText("long enough passphrase")
        self.assertTrue(self.ok_enabled(dialog))

    def test_warns_but_allows_short_passphrases_above_the_floor(self):
        dialog = PassphraseDialog(None, "t", "m", confirm=True, min_length=8)
        dialog.first.setText("eightchr")
        dialog.second.setText("eightchr")
        self.assertTrue(self.ok_enabled(dialog))
        self.assertIn("guessed", dialog.hint.text())

    def test_flags_accidental_spaces(self):
        dialog = PassphraseDialog(None, "t", "m")
        dialog.first.setText("pasted with a trailing space ")
        self.assertTrue(self.ok_enabled(dialog))
        self.assertIn("space", dialog.hint.text())

    def test_input_is_masked_by_default(self):
        from PySide6.QtWidgets import QLineEdit
        dialog = PassphraseDialog(None, "t", "m")
        self.assertEqual(dialog.first.echoMode(), QLineEdit.EchoMode.Password)
        dialog.show_box.setChecked(True)
        self.assertEqual(dialog.first.echoMode(), QLineEdit.EchoMode.Normal)


if __name__ == "__main__":
    unittest.main()
