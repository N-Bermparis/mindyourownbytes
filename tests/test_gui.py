"""Drive the real window headlessly, with a real GnuPG behind it."""

import importlib.util
import os
import runpy
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mindyourownbytes import records
from mindyourownbytes.core import (
    CIPHERS,
    READY,
    JobResult,
    SourceItem,
    available_ciphers,
    list_public_keys,
    process_items,
)
from tests.support import GpgTestCase

HAS_QT = importlib.util.find_spec("PySide6") is not None

if HAS_QT:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QEventLoop, QPoint, QPointF, QSettings, Qt, QUrl
    from PySide6.QtGui import QAction, QColor, QWheelEvent
    from PySide6.QtWidgets import QApplication, QInputDialog, QLabel, QMessageBox, QWidget

    from mindyourownbytes.gui import icons, library_page, main_window, theme
    from mindyourownbytes.gui.dialogs import PassphraseDialog, ProtectionDialog
    from mindyourownbytes.gui.main_window import MainWindow
    from mindyourownbytes.gui.widgets import SteadyComboBox

PASSPHRASE = "a perfectly good test passphrase"
MASTER = "a long master passphrase"


def app() -> "QApplication":
    return QApplication.instance() or QApplication([])


def isolated_settings(folder: Path, advanced: bool = True) -> "QSettings":
    """Advanced by default, because most of these tests are about what only advanced mode offers."""
    settings = QSettings(str(folder / "settings.ini"), QSettings.Format.IniFormat)
    settings.setValue("output_encrypt", str(folder / "exports"))
    settings.setValue("output_restore", str(folder / "restored"))
    if advanced:
        settings.setValue("advanced", "true")
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

    def test_closing_the_window_stops_the_included_gnupg(self):
        window = MainWindow(self.settings, self.folder / "vault.gpg")
        window.gpg = "included-gpg"
        with patch.object(main_window, "stop_bundled_gnupg") as stop:
            window.close()
        stop.assert_called_once_with("included-gpg")

    def test_about_says_when_gnupg_came_with_the_app(self):
        window = MainWindow(self.settings, self.folder / "vault.gpg")
        self.addCleanup(window.close)
        window.gpg = "included-gpg"
        with patch.object(main_window, "gpg_version", return_value=(2, 5, 24)), patch.object(
            main_window.QMessageBox, "about"
        ) as about:
            with patch.object(main_window, "bundled_gpg", return_value="included-gpg"):
                window.show_about()
            self.assertIn("GnuPG 2.5.24 (included with this app)", about.call_args.args[2])
            with patch.object(main_window, "bundled_gpg", return_value=None):
                window.show_about()
            self.assertNotIn("included", about.call_args.args[2])

    def test_stale_saved_gnupg_path_falls_back_to_detection(self):
        self.settings.setValue("gpg_path", str(self.folder / "uninstalled" / "gpg.exe"))
        with patch.object(main_window, "find_gpg", return_value="detected") as detect, patch.object(
            main_window, "is_valid_gpg", return_value=False
        ):
            window = MainWindow(self.settings, self.folder / "vault.gpg")
            self.addCleanup(window.close)
        detect.assert_called()
        self.assertEqual(window.gpg, "detected")

    def test_old_python_gets_a_clear_message_instead_of_a_crash_later(self):
        # Regression: on Linux, Python 3.11 with PySide6 6.12.0 aborts during normal
        # use. A source checkout never runs pip's requires-python check.
        with patch.object(sys, "version_info", (3, 11, 9)), self.assertRaises(SystemExit) as caught:
            runpy.run_module("mindyourownbytes", run_name="__main__")
        self.assertIn("3.12", str(caught.exception))

    def test_missing_gnupg_is_explained_on_the_page_with_a_way_forward(self):
        window = MainWindow(self.settings, self.folder / "vault.gpg")
        self.addCleanup(window.close)
        self.assertIn("needs GnuPG", window.gpg_bar.text())
        self.assertFalse(window.gpg_bar.isHidden())
        self.assertFalse(window.gpg_bar.dismiss_button.isVisibleTo(window.gpg_bar))

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

    def test_ui_has_no_leftover_stylesheet_tokens(self):
        self.assertNotIn("@", theme.stylesheet())

    def test_early_version_notice_stays_dismissed(self):
        window = MainWindow(self.settings, self.folder / "vault.gpg")
        self.addCleanup(window.close)
        self.assertFalse(window.notice_bar.isHidden())
        window.notice_bar.dismiss()
        again = MainWindow(self.settings, self.folder / "vault.gpg")
        self.addCleanup(again.close)
        self.assertTrue(again.notice_bar.isHidden())

    def test_every_menu_item_has_a_real_action(self):
        window = MainWindow(self.settings, self.folder / "vault.gpg")
        self.addCleanup(window.close)
        titles = [action.text().replace("&", "") for action in window.findChildren(QAction)]
        for expected in ("Add files…", "Locate GnuPG…", "What this protects", "Report a problem"):
            self.assertIn(expected, titles)

    def test_without_gnupg_the_only_choice_is_the_default(self):
        window = MainWindow(self.settings, self.folder / "vault.gpg")
        self.addCleanup(window.close)
        self.assertEqual(window.algorithm_combo.count(), 1)
        self.assertEqual(window.chosen_cipher(), "AES256")

    def test_protection_summary_states_the_main_limits_plainly(self):
        dialog = ProtectionDialog(None)
        text = " ".join(child.text() for child in dialog.findChildren(QLabel))
        for phrase in ("names", "synced folder", "malware", "independently audited"):
            self.assertIn(phrase, text)


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
            time.sleep(0.005)

    def write(self, name: str, content: bytes = b"private") -> Path:
        path = self.root / "input" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def select_method(self, data: str):
        self.window.set_method(data)

    def run_with_typed_passphrase(self, passphrase: str = PASSPHRASE, action=None):
        dialog = MagicMock()
        dialog.exec.return_value = True
        dialog.passphrase.return_value = passphrase
        with patch.object(main_window, "PassphraseDialog", return_value=dialog):
            (action or self.window.start)()
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
        self.assertEqual(self.window.table.item(0, 3).text(), "Encrypted and checked")
        self.assertIn("3 files encrypted", self.window.result_bar.text())

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
        self.window.set_operation("restore")
        self.window.add_paths([str(self.root / "exports" / "a.txt.gpg")])
        self.select_method("once")
        self.run_with_typed_passphrase("not the right one")
        self.assertEqual(self.window.result_bar.property("kind"), "error")
        self.assertIn("failed", self.window.result_bar.text())
        self.assertIn("Wrong passphrase", self.window.result_bar.text())
        self.assertEqual(self.window.table.item(0, 3).text(), "Wrong passphrase")
        self.assertIn("different secret", self.window.table.item(0, 3).toolTip())
        self.assertFalse((self.root / "restored" / "a.txt").exists())

    def encrypted_file(self, name: str = "a.txt", content: bytes = b"content") -> Path:
        """Encrypt one file through the window, leaving the screen ready for the next thing."""
        self.window.set_operation("encrypt")
        self.window.add_paths([str(self.write(name, content))])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.window.clear_files()
        return self.root / "exports" / f"{name}.gpg"

    def test_main_button_says_what_it_will_do(self):
        self.assertFalse(self.window.start_button.isEnabled())
        self.assertEqual(self.window.start_button.text(), "Encrypt files")
        self.window.add_paths([str(self.write("a.txt"))])
        self.assertEqual(self.window.start_button.text(), "Encrypt 1 file")
        self.window.add_paths([str(self.write("b.txt"))])
        self.assertEqual(self.window.start_button.text(), "Encrypt 2 files")
        self.assertTrue(self.window.start_button.isEnabled())
        self.window.set_operation("restore")
        self.assertEqual(self.window.start_button.text(), "Restore files")

    def test_empty_list_offers_the_drop_area(self):
        self.assertIs(self.window.queue_stack.currentWidget(), self.window.drop_zone)
        self.window.add_paths([str(self.write("a.txt"))])
        self.assertIs(self.window.queue_stack.currentWidget(), self.window.queue_card)
        self.window.clear_files()
        self.assertIs(self.window.queue_stack.currentWidget(), self.window.drop_zone)

    def test_dropping_anywhere_on_the_screen_adds_the_files(self):
        self.window.drop_area.paths_dropped.emit([str(self.write("a.txt"))])
        self.assertEqual(len(self.window.items), 1)

    def test_success_becomes_a_results_view_and_start_over_clears_it(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.assertTrue(self.window.method_card.isHidden())
        self.assertTrue(self.window.save_card.isHidden())
        self.assertEqual(self.window.start_button.text(), "Start over")
        self.window._primary_clicked()
        self.assertEqual(self.window.items, [])
        self.assertFalse(self.window.method_card.isHidden())
        self.assertTrue(self.window.result_bar.isHidden())

    def test_starting_over_never_encrypts_the_same_files_twice(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.window._primary_clicked()
        self.assertEqual([p.name for p in (self.root / "exports").iterdir()], ["a.txt.gpg"])

    def test_adding_files_after_a_finished_job_starts_a_new_batch(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.window.add_paths([str(self.write("b.txt"))])
        self.assertEqual([item.source.name for item in self.window.items], ["b.txt"])
        self.assertTrue(self.window.result_bar.isHidden())

    def test_retry_runs_only_what_failed(self):
        good = self.encrypted_file("good.txt", b"good")
        bad = self.root / "bad.txt.gpg"
        bad.write_bytes(os.urandom(256))
        self.window.set_operation("restore")
        self.window.add_paths([str(bad), str(good)])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.assertEqual(self.window.start_button.text(), "Try these again")
        self.assertIn("1 of 2 files failed", self.window.result_bar.text())
        self.assertFalse(self.window.method_card.isHidden())
        self.run_with_typed_passphrase(action=self.window._primary_clicked)
        self.assertEqual([item.source.name for item in self.window.items], ["bad.txt.gpg"])
        self.assertEqual([p.name for p in (self.root / "restored").rglob("*") if p.is_file()], ["good.txt"])

    def test_wrong_passphrase_can_simply_be_tried_again(self):
        encrypted = self.encrypted_file("a.txt", b"second try")
        self.window.set_operation("restore")
        self.window.add_paths([str(encrypted)])
        self.select_method("once")
        self.run_with_typed_passphrase("not the right one")
        self.run_with_typed_passphrase(action=self.window._primary_clicked)
        self.assertEqual((self.root / "restored" / "a.txt").read_bytes(), b"second try")

    def test_open_folder_opens_where_the_files_actually_went(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        self.window.collection_combo.setCurrentText("Taxes")
        self.run_with_typed_passphrase()
        with patch.object(main_window.QDesktopServices, "openUrl") as opened:
            self.window.open_output()
        self.assertEqual(opened.call_args.args[0], QUrl.fromLocalFile(str(self.root / "exports" / "Taxes")))

    def test_restore_preselects_how_the_files_were_protected(self):
        encrypted = self.encrypted_file()
        self.window.set_operation("restore")
        self.window.add_paths([str(encrypted)])
        self.assertEqual(self.window.method(), "once")

        fingerprint = self.generate_key("Me <me@example.invalid>")
        self.window.refresh_keys()
        self.window.set_operation("encrypt")
        self.window.add_paths([str(self.write("k.txt"))])
        self.window.set_method("public-key")
        self.window.key_combo.setCurrentIndex(self.window.key_combo.findData(fingerprint))
        self.window.start()
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)
        self.window.clear_files()
        self.window.set_operation("restore")
        self.window.add_paths([str(self.root / "exports" / "k.txt.gpg")])
        self.assertTrue(self.window.key_radio.isChecked())
        self.assertEqual(self.window.method(), "pinentry")

    def test_a_mix_of_passphrase_and_key_files_preselects_the_passphrase_and_says_what_happens(self):
        encrypted = self.encrypted_file("typed.txt", b"typed")
        fingerprint = self.generate_key("Me <me@example.invalid>")
        self.window.refresh_keys()
        self.window.add_paths([str(self.write("k.txt", b"for the key"))])
        self.window.set_method("public-key")
        self.window.key_combo.setCurrentIndex(self.window.key_combo.findData(fingerprint))
        self.window.start()
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)
        self.window.clear_files()
        self.window.set_operation("restore")
        self.window.add_paths([str(encrypted), str(self.root / "exports" / "k.txt.gpg")])
        self.assertEqual(self.window.method(), "once", "the passphrase opens the rest")
        self.assertIn("One of them is for your key", self.window.passphrase_help.text())
        self.run_with_typed_passphrase()
        self.assertEqual((self.root / "restored" / "typed.txt").read_bytes(), b"typed")
        self.assertEqual((self.root / "restored" / "k.txt").read_bytes(), b"for the key")
        self.window.clear_files()
        self.window.add_paths([str(self.root / "exports" / "k.txt.gpg")])
        self.assertTrue(self.window.key_radio.isChecked(), "only files for a key need the key")
        self.assertNotIn("for your key", self.window.passphrase_help.text())

    def test_preselection_never_overrides_the_users_own_choice(self):
        encrypted = self.encrypted_file()
        self.window.set_operation("restore")
        self.window.saved_radio.click()
        self.window.add_paths([str(encrypted)])
        self.assertEqual(self.window.method(), "saved")

    def test_gnupg_prompt_preference_is_remembered(self):
        self.assertEqual(self.window.method(), "once")
        self.window.pinentry_action.setChecked(True)
        self.assertEqual(self.window.method(), "pinentry")
        self.assertIn("once for each file", self.window.passphrase_help.text())
        again = MainWindow(self.settings, self.root / "app" / "vault.gpg")
        self.addCleanup(again.close)
        self.assertTrue(again.pinentry_action.isChecked())

    def test_switching_light_or_dark_keeps_finished_results(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.window._apply_theme()
        self.assertEqual(self.window.table.item(0, 3).text(), "Encrypted and checked")
        self.assertFalse(self.window.grab().isNull())

    def test_selecting_a_row_renders_without_error(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.window.table.selectRow(0)
        self.window.resize(900, 700)
        self.assertFalse(self.window.grab().isNull())

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
        self.wait_until(lambda: self.window._thread is None)
        self.assertIn("cancelled", self.window.status_text.text())
        self.assertLess(len(list((self.root / "exports").rglob("*.gpg"))), 30)
        self.assertFalse(list((self.root / "exports").rglob("*.partial")))
        self.assertEqual(self.window.start_button.text(), "Try these again")

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

    def restore_into_dropbox(self):
        self.settings.setValue("output_restore", str(self.root / "Dropbox" / "restored"))
        self.window.set_operation("restore")
        path = self.root / "input" / "a.txt.gpg"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x")
        self.window.add_paths([str(path)])
        self.message_boxes["warning"].reset_mock()
        self.window.start()
        self.assertFalse(self.window.running)
        self.assertFalse((self.root / "Dropbox").exists(), "not even the folder is made")
        return self.message_boxes["warning"].call_args.args

    def test_refuses_to_restore_plaintext_into_a_synced_folder(self):
        # Every question in these tests is answered yes, so only a refusal stops this.
        _parent, title, text = self.restore_into_dropbox()
        self.assertEqual(title, "Choose a folder that isn't synced")
        self.assertIn("“Dropbox”", text)
        self.assertIn("Restored Files", text, "suggests a folder on this computer")

    def test_with_the_switch_on_it_warns_and_asks_instead(self):
        self.window.synced_restore_action.setChecked(True)
        self.assertEqual(self.settings.value("allow_synced_restore"), "true")
        self.message_boxes["warning"].return_value = QMessageBox.StandardButton.No
        _parent, title, _text = self.restore_into_dropbox()[:3]
        self.assertEqual(title, "Restoring into a synced folder?")

    def test_simple_mode_refuses_even_with_the_switch_on(self):
        self.window.synced_restore_action.setChecked(True)
        self.window.advanced_action.setChecked(False)
        self.assertFalse(self.window.synced_restore_action.isVisible())
        self.assertEqual(self.restore_into_dropbox()[1], "Choose a folder that isn't synced")

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


class PostQuantumAssistantTests(GuiCase):
    def keys(self):
        from mindyourownbytes.core import PublicKey
        return [PublicKey("A" * 40, "Classic <c@example.invalid>", True, "Curve25519"),
                PublicKey("B" * 40, "Quantum <q@example.invalid>", True, "Kyber-768 (post-quantum)"),
                PublicKey("C" * 40, "Someone else <s@example.invalid>", False, "RSA-3072")]

    def dialog(self, supported=True):
        from mindyourownbytes.gui import post_quantum
        patches = (patch.object(post_quantum, "supports_post_quantum", return_value=supported),
                   patch.object(post_quantum, "list_public_keys", return_value=self.keys()))
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)
        dialog = post_quantum.PostQuantumDialog(self.window, self.gpg)
        self.addCleanup(dialog.close)
        return post_quantum, dialog

    def test_says_what_this_gnupg_can_do_and_lists_only_your_own_keys(self):
        _, dialog = self.dialog()
        self.assertIn("can make post-quantum keys", dialog.status.text())
        self.assertEqual(dialog.table.rowCount(), 2)
        self.assertEqual([dialog.table.item(row, 2).text() for row in range(2)], ["No", "Yes"])
        text = " ".join(child.text() for child in dialog.findChildren(QLabel))
        for phrase in ("GnuPG 2.5 or later", "Back it up", "AES-256", "other OpenPGP apps"):
            self.assertIn(phrase, text)

    def test_without_support_it_explains_and_offers_nothing_to_click(self):
        _, dialog = self.dialog(supported=False)
        self.assertIn("can't make post-quantum keys", dialog.status.text())
        dialog.table.selectRow(0)
        self.assertFalse(dialog.create_button.isEnabled())
        self.assertFalse(dialog.add_button.isEnabled())

    def test_only_a_key_without_a_post_quantum_part_can_get_one(self):
        _, dialog = self.dialog()
        self.assertFalse(dialog.add_button.isEnabled())
        dialog.table.selectRow(1)
        self.assertFalse(dialog.add_button.isEnabled())
        dialog.table.selectRow(0)
        self.assertTrue(dialog.add_button.isEnabled())

    def finish(self, dialog):
        self.wait_until(lambda: dialog._job is None, timeout=20)

    def test_adding_a_part_warns_first_then_asks_gnupg(self):
        module, dialog = self.dialog()
        dialog.table.selectRow(0)
        changed = []
        dialog.keys_changed.connect(lambda: changed.append(True))
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.No), patch.object(
            module, "add_post_quantum_subkey"
        ) as add:
            dialog.add_to_selected()
        add.assert_not_called()
        with patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes) as question, \
                patch.object(module, "add_post_quantum_subkey", return_value="D" * 64) as add:
            dialog.add_to_selected()
            self.finish(dialog)
        self.assertIn("only open with GnuPG 2.5 or later", question.call_args.args[2])
        add.assert_called_once_with(self.gpg, "A" * 40)
        self.assertEqual(changed, [True])
        self.assertIn("Back up the key again", self.message_boxes["information"].call_args.args[2])

    def test_creating_a_key_asks_for_a_name_and_says_to_back_it_up(self):
        module, dialog = self.dialog()
        form = MagicMock()
        form.exec.return_value = True
        form.uid.return_value = "Alex Example <alex@example.invalid>"
        with patch.object(module, "NewKeyDialog", return_value=form), patch.object(
            module, "create_post_quantum_key", return_value="E" * 40
        ) as create:
            dialog.create_key()
            self.finish(dialog)
        create.assert_called_once_with(self.gpg, "Alex Example <alex@example.invalid>")
        self.assertIn("Back it up in Kleopatra", self.message_boxes["information"].call_args.args[2])

    def test_a_failure_is_shown_and_changes_nothing(self):
        module, dialog = self.dialog()
        form = MagicMock()
        form.exec.return_value = True
        form.uid.return_value = "Alex"
        changed = []
        dialog.keys_changed.connect(lambda: changed.append(True))
        with patch.object(module, "NewKeyDialog", return_value=form), patch.object(
            module, "create_post_quantum_key", side_effect=module.GpgFailure("The passphrase prompt was cancelled.")
        ):
            dialog.create_key()
            self.finish(dialog)
        self.assertEqual(changed, [])
        self.assertIn("cancelled", self.message_boxes["warning"].call_args.args[2])

    def test_the_new_key_form_checks_what_is_typed(self):
        from PySide6.QtWidgets import QDialogButtonBox

        from mindyourownbytes.gui.post_quantum import NewKeyDialog
        form = NewKeyDialog(None)
        ok = form.buttons.button(QDialogButtonBox.StandardButton.Ok)
        self.assertFalse(ok.isEnabled())
        form.name.setText("Alex Example")
        self.assertTrue(ok.isEnabled())
        form.email.setText("not an email")
        self.assertFalse(ok.isEnabled())
        self.assertIn("email", form.problem.text())
        form.email.setText("alex@example.invalid")
        self.assertEqual(form.uid(), "Alex Example <alex@example.invalid>")

    def test_the_tools_menu_opens_it_and_new_keys_reach_the_key_list(self):
        titles = [action.text().replace("&", "") for action in self.window.findChildren(QAction)]
        self.assertIn("Post-quantum keys…", titles)
        with patch.object(main_window, "PostQuantumDialog") as dialog, patch.object(self.window, "refresh_keys"):
            self.window.show_post_quantum()
            dialog.return_value.keys_changed.connect.assert_called_once_with(self.window.refresh_keys)
            dialog.return_value.exec.assert_called_once()


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class RecoveryGuideTests(unittest.TestCase):
    def setUp(self):
        app()
        from shiboken6 import delete

        from mindyourownbytes.gui.recovery_guide import RecoveryGuide
        self.guide = RecoveryGuide(None)
        # Destroyed now, while Qt is running: left for Python's exit, it crashed the test process.
        self.addCleanup(delete, self.guide)
        self.addCleanup(self.guide.close)
        temp = tempfile.TemporaryDirectory(prefix="myobtest")
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)

    def page_text(self) -> str:
        page = self.guide.pages.currentWidget()
        from PySide6.QtWidgets import QLineEdit
        return " ".join([child.text() for child in page.findChildren(QLabel)]
                        + [child.text() for child in page.findChildren(QLineEdit)])

    def test_starts_on_this_computers_system_and_steps_through(self):
        self.assertEqual(self.guide.chosen(), "windows" if sys.platform == "win32" else self.guide.chosen())
        self.assertEqual(self.guide.position.text(), "Step 1 of 5")
        self.assertFalse(self.guide.back_button.isEnabled())
        for expected in range(2, 6):
            self.guide.next_button.click()
            self.assertEqual(self.guide.position.text(), f"Step {expected} of 5")
        self.assertEqual(self.guide.next_button.text(), "Done")
        self.guide.back_button.click()
        self.assertEqual(self.guide.position.text(), "Step 4 of 5")
        self.assertEqual(self.guide.next_button.text(), "Next")

    def test_choosing_another_system_changes_the_commands_but_not_the_step(self):
        for _ in range(3):
            self.guide.next_button.click()
        self.guide.platform.setCurrentIndex(self.guide.platform.findData("windows"))
        self.assertIn("Get-ChildItem", self.page_text())
        self.guide.platform.setCurrentIndex(self.guide.platform.findData("linux"))
        self.assertEqual(self.guide.position.text(), "Step 4 of 5")
        self.assertIn("find . -name", self.page_text())
        self.assertNotIn("Get-ChildItem", self.page_text())

    def test_copy_puts_the_command_on_the_clipboard(self):
        from PySide6.QtWidgets import QPushButton
        for _ in range(3):
            self.guide.next_button.click()
        copy = next(button for button in self.guide.pages.currentWidget().findChildren(QPushButton)
                    if button.text() == "Copy")
        self.addCleanup(QApplication.clipboard().clear)
        copy.click()
        if QApplication.clipboard().text() == "":
            self.skipTest("this platform has no clipboard to test against")
        self.assertEqual(QApplication.clipboard().text(), "gpg --output report.pdf --decrypt report.pdf.gpg")

    def test_saves_every_step_as_text_with_the_systems_line_endings(self):
        from mindyourownbytes import recovery
        from mindyourownbytes.gui import recovery_guide
        for platform, ending in (("windows", b"\r\n"), ("linux", b"\n")):
            with self.subTest(platform):
                self.guide.platform.setCurrentIndex(self.guide.platform.findData(platform))
                target = self.folder / f"{platform}.txt"
                with patch.object(recovery_guide.QFileDialog, "getSaveFileName", return_value=(str(target), "")), \
                        patch.object(QMessageBox, "information") as told:
                    self.guide.save()
                data = target.read_bytes()
                self.assertEqual(data.decode("utf-8").replace("\r\n", "\n"), recovery.as_text(platform))
                self.assertIn(ending, data)
                if ending == b"\n":
                    self.assertNotIn(b"\r\n", data)
                self.assertIn("no secrets", told.call_args.args[2])

    def test_the_help_menu_opens_it(self):
        settings_folder = Path(tempfile.mkdtemp(prefix="myobtest"))
        window = MainWindow(isolated_settings(settings_folder), settings_folder / "vault.gpg")
        self.addCleanup(window.close)
        titles = [action.text().replace("&", "") for action in window.findChildren(QAction)]
        self.assertIn("Restore on another computer…", titles)


class DownloadCheckTests(GuiCase):
    """Restoring checks each download against the checksums saved here when it was made."""

    def finish(self):
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)

    def encrypt(self, name: str, content: bytes) -> Path:
        self.window.set_operation("encrypt")
        self.window.add_paths([str(self.write(name, content))])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.window.clear_files()
        return self.root / "exports" / f"{name}.gpg"

    def download(self, encrypted: Path, name: str | None = None) -> Path:
        downloaded = self.root / "Downloads" / (name or encrypted.name)
        downloaded.parent.mkdir(exist_ok=True)
        shutil.copyfile(encrypted, downloaded)
        return downloaded

    def restore(self, *paths: Path):
        self.window.set_operation("restore")
        self.window.add_paths([str(path) for path in paths])
        self.select_method("once")
        self.run_with_typed_passphrase()

    def test_encrypting_saves_a_checksum_of_each_new_file(self):
        encrypted = self.encrypt("a.txt", b"first")
        saved = records.Ledger(self.root / "app" / "records.jsonl").load().records
        self.assertEqual([(r.name, r.path, r.sha256) for r in saved],
                         [("a.txt.gpg", "a.txt.gpg", records.sha256_of(encrypted))])

    def test_a_download_of_the_file_made_here_says_it_matches(self):
        downloaded = self.download(self.encrypt("a.txt", b"first"), "a (1).txt.gpg")
        self.restore(downloaded)
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored, matches your record")
        self.assertIn("Matches the copy made here", self.window.table.item(0, 3).toolTip())
        self.assertEqual(self.window.result_bar.property("kind"), "success")
        self.assertIn("Each one matches the checksum", self.window.result_bar.text())

    def test_a_swapped_file_is_restored_but_flagged(self):
        taxes = self.encrypt("taxes.txt", b"taxes")
        medical = self.encrypt("medical.txt", b"medical")
        # The provider hands back each file under the other's name.
        swapped_taxes = self.download(medical, "taxes.txt.gpg")
        self.restore(swapped_taxes)
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored, but it was renamed or swapped")
        self.assertIn("saved as medical.txt.gpg", self.window.table.item(0, 3).toolTip())
        self.assertEqual(self.window.result_bar.property("kind"), "warning")
        self.assertIn("1 is not the copy you made", self.window.result_bar.text())
        self.assertTrue(taxes.exists())
        self.assertEqual(self.questions()[0][0], "Restore a file that isn't the copy you made?")

    def questions(self) -> list[tuple[str, str]]:
        """What restoring asked about downloads that aren't the copies made here, as (title, text)."""
        return [(call.args[1], call.args[2]) for call in self.message_boxes["warning"].call_args_list
                if "the copy you made" in call.args[1] or "the copies you made" in call.args[1]]

    def answer_no_to_doubtful_downloads(self) -> list[list[str]]:
        """Leave doubtful downloads out. Returns what had been restored each time the question came."""
        restored_then = []

        def answer(_parent, title, *_rest):
            if "the copy you made" not in title and "the copies you made" not in title:
                return QMessageBox.StandardButton.Yes
            folder = self.root / "restored"
            restored_then.append(sorted(p.name for p in folder.rglob("*")) if folder.exists() else [])
            return QMessageBox.StandardButton.No

        self.message_boxes["warning"].side_effect = answer
        return restored_then

    def test_a_doubtful_download_is_left_out_unless_you_say_so(self):
        # Regression: a download that isn't the copy made here was decrypted anyway, with only a warning
        # afterwards. Now nothing is decrypted until someone says to, and leaving it out is the default.
        self.encrypt("taxes.txt", b"taxes")
        medical = self.encrypt("medical.txt", b"medical")
        notes = self.encrypt("notes.txt", b"notes")
        restored_then = self.answer_no_to_doubtful_downloads()
        self.restore(self.download(medical, "taxes.txt.gpg"), self.download(notes))
        (title, text), = self.questions()
        self.assertEqual(title, "Restore a file that isn't the copy you made?")
        self.assertIn("taxes.txt.gpg: This is the file that was saved as medical.txt.gpg", text)
        self.assertIn("If not, it's left out, and the other files are still restored.", text)
        self.assertEqual(restored_then, [[]], "nothing may be decrypted before the answer")
        self.assertEqual(self.window.table.item(0, 3).text(), "Not restored, it was renamed or swapped")
        self.assertIn("saved as medical.txt.gpg", self.window.table.item(0, 3).toolTip())
        self.assertEqual(self.window.table.item(1, 3).text(), "Restored, matches your record")
        self.assertEqual(sorted(p.name for p in (self.root / "restored").rglob("*")), ["notes.txt"])
        self.assertEqual(self.window.result_bar.property("kind"), "warning")
        self.assertEqual(self.window.result_bar.title_label.text(), "1 file restored, 1 left out")
        self.assertIn("1 left out", self.window.status_text.text())
        self.assertEqual([item.source.name for item in self.window._unfinished_items], ["taxes.txt.gpg"])

    def test_when_every_download_is_doubtful_nothing_is_restored_without_a_yes(self):
        first = self.encrypt("a.txt", b"first")
        second = self.encrypt("b.txt", b"second")
        self.answer_no_to_doubtful_downloads()
        self.restore(self.download(second, "a.txt.gpg"), self.download(first, "b.txt.gpg"))
        (title, text), = self.questions()
        self.assertEqual(title, "Restore 2 files that aren't the copies you made?")
        self.assertIn("• a.txt.gpg: it was renamed or swapped\n• b.txt.gpg: it was renamed or swapped", text)
        self.assertIn("If not, nothing is restored.", text)
        self.assertEqual([self.window.table.item(row, 3).text() for row in range(2)],
                         ["Not restored, it was renamed or swapped"] * 2)
        self.assertEqual(self.window.result_bar.title_label.text(), "Nothing was restored")
        restored = self.root / "restored"
        self.assertEqual([p for p in restored.rglob("*") if p.is_file()] if restored.exists() else [], [])

    def test_a_file_from_another_collection_is_flagged_and_a_match_says_which_it_is(self):
        # Regression: Taxes and Medical each had a report.txt.gpg. The Medical one, handed back in the
        # Taxes folder, was called a match, because its name and checksum were both known.
        made = {}
        for collection, content in (("Taxes", b"taxes"), ("Medical", b"medical")):
            self.window.set_operation("encrypt")
            self.window.add_paths([str(self.write(f"{collection}/report.txt", content))])
            self.window.collection_combo.setCurrentText(collection)
            self.select_method("once")
            self.run_with_typed_passphrase()
            self.window.clear_files()
            made[collection] = self.root / "exports" / collection / "report.txt.gpg"
        (self.root / "Downloads" / "Taxes").mkdir(parents=True)
        self.restore(self.download(made["Medical"], "Taxes/report.txt.gpg"))
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored, but it was renamed or swapped")
        self.assertIn("saved as Medical/report.txt.gpg", self.window.table.item(0, 3).toolTip())
        self.window.clear_files()
        self.restore(self.download(made["Medical"]))
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored, matches Medical/report.txt.gpg")
        self.assertIn("Taxes/report.txt.gpg is a different file", self.window.table.item(0, 3).toolTip())

    def test_an_older_version_is_restored_but_flagged(self):
        first = self.encrypt("report.txt", b"version one")
        old_copy = self.download(first)
        first.unlink()
        time.sleep(1.1)  # Records are kept to the second.
        self.encrypt("report.txt", b"version two")
        self.restore(old_copy)
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored, but it's an older copy")
        self.assertEqual((self.root / "restored" / "report.txt").read_bytes(), b"version one")

    def test_with_the_record_turned_off_nothing_is_saved(self):
        self.window.records_action.setChecked(False)
        self.encrypt("a.txt", b"first")
        self.assertFalse((self.root / "app" / "records.jsonl").exists())
        again = MainWindow(self.settings, self.root / "app" / "vault.gpg")
        self.addCleanup(again.close)
        self.assertFalse(again.records_action.isChecked())

    def test_files_from_elsewhere_restore_without_a_verdict(self):
        stranger = self.encrypt("a.txt", b"first")
        (self.root / "app" / "records.jsonl").unlink()
        self.restore(self.download(stranger))
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored")

    def test_checksums_saved_in_the_library_can_be_imported_on_another_computer(self):
        made = self.encrypt("a.txt", b"first")
        self.window.show_library()
        target = self.root / "SHA256SUMS.txt"
        with patch.object(library_page.QFileDialog, "getSaveFileName", return_value=(str(target), "")):
            self.window.library_page.save_checksums()
        self.assertEqual(target.read_text(encoding="utf-8"), f"{records.sha256_of(made)}  a.txt.gpg\n")
        self.assertIn("password manager", self.message_boxes["information"].call_args.args[2])

        (self.root / "app" / "records.jsonl").unlink()  # As on a computer that never made it.
        with patch.object(main_window.QFileDialog, "getOpenFileName", return_value=(str(target), "")):
            self.window.import_checksums()
        self.assertIn("Imported 1 checksum.", self.message_boxes["information"].call_args.args[2])
        self.restore(self.download(made))
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored, matches your record")
        self.assertIn("checksum from SHA256SUMS.txt", self.window.table.item(0, 3).toolTip())

    def test_forgetting_the_checksums_asks_first(self):
        self.encrypt("a.txt", b"first")
        self.message_boxes["warning"].return_value = QMessageBox.StandardButton.No
        self.window.forget_checksums()
        self.assertTrue((self.root / "app" / "records.jsonl").exists())
        self.message_boxes["warning"].return_value = QMessageBox.StandardButton.Yes
        self.window.forget_checksums()
        self.assertFalse((self.root / "app" / "records.jsonl").exists())

    def test_a_checksum_that_cant_be_saved_is_mentioned_and_the_file_is_still_made(self):
        with patch.object(records.Ledger, "add", side_effect=PermissionError(13, "denied")):
            self.encrypt("a.txt", b"first")
        self.assertTrue((self.root / "exports" / "a.txt.gpg").exists())
        self.assertIn("couldn't be saved", self.message_boxes["warning"].call_args.args[2])

    def test_a_swapped_archive_is_unpacked_but_flagged(self):
        made = {}
        for name in ("Taxes", "Medical"):
            self.window.set_operation("encrypt")
            self.window.add_paths([str(self.write(f"{name}/notes.txt", name.encode()))])
            self.select_method("once")
            self.window.archive_radio.click()
            self.window.archive_name_edit.setText(name)
            self.run_with_typed_passphrase()
            self.window.clear_files()
            made[name] = self.root / "exports" / f"{name}.zip.gpg"
        saved = records.Ledger(self.root / "app" / "records.jsonl").load().records
        self.assertEqual([r.name for r in saved], ["Taxes.zip.gpg", "Medical.zip.gpg"])
        # The provider hands back one archive under the other's name.
        self.restore(self.download(made["Medical"], "Taxes.zip.gpg"))
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored and unpacked, but it was renamed or swapped")
        self.assertIn("saved as Medical.zip.gpg", self.window.table.item(0, 3).toolTip())
        self.assertEqual(self.window.result_bar.property("kind"), "warning")


class ArchiveModeTests(GuiCase):
    """Step 3 can put every file into one archive, which hides the names inside."""

    def finish(self):
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)

    def choose_archive(self, name: str = ""):
        self.window.archive_radio.click()
        self.window.archive_name_edit.setText(name)

    def test_separate_files_stay_the_default(self):
        self.assertTrue(self.window.separate_radio.isChecked())
        self.assertTrue(self.window.archive_help.isHidden())
        self.assertFalse(self.window.archive_name_edit.isEnabled())
        self.assertRegex(self.window.archive_name_edit.placeholderText(), r"^Archive \d{4}-\d{2}-\d{2}$")

    def test_choosing_an_archive_says_what_it_hides_and_what_it_costs(self):
        self.choose_archive()
        self.assertFalse(self.window.archive_help.isHidden())
        self.assertIn("Hides the names", self.window.archive_help.text())
        self.assertIn("whole archive again", self.window.archive_help.text())
        self.assertIn("one .zip.gpg file", self.window.privacy_note.text())
        self.assertTrue(self.window.archive_name_edit.isEnabled())

    def test_restoring_has_no_such_choice(self):
        self.choose_archive()
        self.window.set_operation("restore")
        for widget in (self.window.save_as_label, self.window.separate_radio, self.window.archive_radio,
                       self.window.archive_name_edit, self.window.archive_help):
            self.assertTrue(widget.isHidden())
        self.assertFalse(self.window.archive_chosen())
        self.assertIn("no cloud service syncs", self.window.privacy_note.text())

    def test_the_choice_is_remembered(self):
        self.choose_archive()
        again = MainWindow(self.settings, self.root / "app" / "vault.gpg")
        self.addCleanup(again.close)
        self.assertTrue(again.archive_radio.isChecked())
        self.window.separate_radio.click()
        third = MainWindow(self.settings, self.root / "app" / "vault.gpg")
        self.addCleanup(third.close)
        self.assertTrue(third.separate_radio.isChecked())

    def test_a_folder_becomes_one_checked_archive_and_comes_back_as_a_folder(self):
        self.write("Taxes/return.pdf", b"return")
        self.write("Taxes/receipts/scan.jpg", b"scan")
        self.window.add_paths([str(self.root / "input" / "Taxes")])
        self.select_method("once")
        self.choose_archive("Paperwork")
        packed = []
        real = main_window.encrypt_archive

        def recording(*args, **kwargs):
            notify = kwargs["on_packing"]
            kwargs["on_packing"] = lambda index: (packed.append(index), notify(index))
            return real(*args, **kwargs)

        with patch.object(main_window, "encrypt_archive", side_effect=recording), patch.object(
            self.window, "_set_row_status", wraps=self.window._set_row_status
        ) as shown:
            self.run_with_typed_passphrase()
        self.assertEqual(packed, [0, 1])
        self.assertIn("Adding to the archive…", [call.args[1] for call in shown.call_args_list])
        self.assertEqual([p.name for p in (self.root / "exports").iterdir()], ["Paperwork.zip.gpg"])
        for row in range(2):
            self.assertEqual(self.window.table.item(row, 3).text(), "In the archive, checked")
        self.assertEqual(self.window.result_bar.title_label.text(),
                         "2 files encrypted into one archive with AES-256 and checked")
        self.assertIn("Upload only Paperwork.zip.gpg", self.window.result_bar.text())
        self.assertNotIn(b"return.pdf", (self.root / "exports" / "Paperwork.zip.gpg").read_bytes())

        self.window.set_operation("restore")
        self.window.add_paths([str(self.root / "exports" / "Paperwork.zip.gpg")])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored and unpacked, matches your record")
        unpacked = self.root / "restored" / "Paperwork" / "Taxes"
        self.assertEqual((unpacked / "return.pdf").read_bytes(), b"return")
        self.assertEqual((unpacked / "receipts" / "scan.jpg").read_bytes(), b"scan")

    def test_a_name_that_clashes_is_numbered_and_its_row_says_so(self):
        self.write("one/docs", b"a file called docs")
        self.write("two/docs/inside.txt", b"inside the folder")
        self.window.add_paths([str(self.root / "input" / "one" / "docs"), str(self.root / "input" / "two" / "docs")])
        self.select_method("once")
        self.choose_archive("Clash")
        self.run_with_typed_passphrase()
        self.assertEqual([self.window.table.item(row, 3).text() for row in range(2)],
                         ["In the archive, checked"] * 2)
        self.assertNotIn("In the archive it's", self.window.table.item(0, 3).toolTip())
        self.assertIn("In the archive it's docs (2)/inside.txt", self.window.table.item(1, 3).toolTip())

    def test_the_suggested_name_is_used_when_none_is_typed(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        self.choose_archive("")
        self.run_with_typed_passphrase()
        suggested = self.window.archive_name_edit.placeholderText()
        self.assertEqual([p.name for p in (self.root / "exports").iterdir()], [f"{suggested}.zip.gpg"])

    def test_a_name_that_cannot_be_used_stops_before_any_work(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        self.choose_archive("../../Startup")
        self.window.start()
        self.assertFalse(self.window.running)
        self.assertIn("archive name", self.message_boxes["warning"].call_args.args[1])
        self.assertFalse((self.root / "exports").exists())

    def test_a_failed_archive_says_so_and_can_be_tried_again(self):
        self.write("Taxes/a.txt", b"a")
        self.write("Taxes/b.txt", b"b")
        self.window.add_paths([str(self.root / "input" / "Taxes")])
        self.select_method("once")
        self.choose_archive("Paperwork")
        real = main_window.encrypt_archive

        def spoiling(*args, **kwargs):
            def spoil():
                staged = next((self.root / "exports").glob(".myob-*.partial"))
                staged.write_bytes(b"not an OpenPGP file")

            kwargs["on_checking"] = spoil
            return real(*args, **kwargs)

        with patch.object(main_window, "encrypt_archive", side_effect=spoiling):
            self.run_with_typed_passphrase()
        self.assertEqual(self.window.result_bar.property("kind"), "error")
        self.assertEqual(self.window.result_bar.title_label.text(), "The archive wasn't made")
        self.assertIn("Check failed", self.window.result_bar.text())
        self.assertEqual(list((self.root / "exports").iterdir()), [])
        self.assertEqual(self.window.start_button.text(), "Try these again")
        self.run_with_typed_passphrase(action=self.window._primary_clicked)
        self.assertEqual([p.name for p in (self.root / "exports").iterdir()], ["Paperwork.zip.gpg"])
        self.assertEqual(self.window.start_button.text(), "Start over")

    def test_a_key_archive_is_reported_as_not_checked(self):
        self.generate_key("Me <me@example.invalid>")
        self.window.refresh_keys()
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("public-key")
        self.choose_archive("Paperwork")
        self.window.start()
        self.finish()
        self.assertEqual(self.window.table.item(0, 3).text(), "In the archive, not checked")
        self.assertEqual(self.window.result_bar.title_label.text(), "1 file signed and encrypted into one archive")
        self.assertIn("Not checked", self.window.result_bar.text())

    def test_the_provider_view_shows_the_one_archive_they_get(self):
        from mindyourownbytes.gui import provider_view
        self.write("Taxes/return.pdf", b"return")
        self.write("Taxes/scan.jpg", b"scan")
        self.window.add_paths([str(self.root / "input" / "Taxes")])
        self.window.collection_combo.setCurrentText("Paperwork")
        self.choose_archive("Year end")
        with patch.object(provider_view, "ProviderView") as view:
            self.window.provider_link.linkActivated.emit("#provider")
        self.assertEqual(view.call_args.args[2], "Paperwork/Year end.zip.gpg")
        self.assertEqual(len(view.call_args.args[1]), 2, "your own view still lists every file")
        self.window.separate_radio.click()
        with patch.object(provider_view, "ProviderView") as view:
            self.window.provider_link.linkActivated.emit("#provider")
        self.assertEqual(view.call_args.args[2], "")

    def test_the_choice_is_locked_while_a_job_runs(self):
        self.choose_archive()
        self.window.running = True
        self.window._set_busy(True)
        self.assertFalse(self.window.archive_radio.isEnabled())
        self.assertFalse(self.window.archive_name_edit.isEnabled())
        self.window.running = False
        self.window._set_busy(False)
        self.assertTrue(self.window.archive_name_edit.isEnabled())


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class ProviderViewTests(unittest.TestCase):
    """The same files, as you see them and as your provider does."""

    def setUp(self):
        app()
        temp = tempfile.TemporaryDirectory(prefix="myobtest")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def keep_until_the_end_of_this_test(self, widget):
        """Destroyed while Qt is running. A widget with no parent, left for Python's exit, can crash it."""
        from shiboken6 import delete
        self.addCleanup(delete, widget)
        return widget

    def open(self, files=()):
        from mindyourownbytes.gui import provider_view
        return self.keep_until_the_end_of_this_test(provider_view.ProviderView(None, files))

    def column(self, view, column):
        return [view.table.item(row, column).text() for row in range(view.table.rowCount())]

    def test_with_nothing_of_yours_it_shows_examples_and_starts_on_the_providers_view(self):
        from mindyourownbytes.gui import provider_view
        view = self.open()
        self.assertTrue(view.examples)
        self.assertTrue(view.providers_view())
        self.assertEqual(self.column(view, 0), [shown.stored_name for shown in provider_view.EXAMPLES])
        self.assertIn("divorce-settlement.pdf.gpg", self.column(view, 0))
        self.assertEqual(self.column(view, 3), ["Unreadable once encrypted"] * 3)

    def test_switching_shows_what_changes_and_what_doesnt(self):
        from mindyourownbytes.gui import provider_view, theme
        view = self.open(provider_view.EXAMPLES)
        self.assertEqual(self.column(view, 1), ["Legal", "Medical", "—"])
        self.assertEqual(view.table.item(0, 0).foreground().color(), theme.color("warn"))
        self.assertEqual(view.table.item(0, 3).foreground().color(), theme.color("ok"))
        self.assertIn("can see this name", view.table.item(0, 0).toolTip())
        self.assertTrue(self.column(view, 2)[0].startswith("about "))
        view.yours.click()
        self.assertFalse(view.providers_view())
        self.assertEqual(self.column(view, 0), ["divorce-settlement.pdf", "scan-001.jpg", "notes.txt"])
        self.assertEqual(self.column(view, 3), ["Readable, on this computer"] * 3)
        self.assertFalse(self.column(view, 2)[0].startswith("about"))
        view.theirs.click()
        self.assertEqual(self.column(view, 0)[0], "divorce-settlement.pdf.gpg")

    def test_says_plainly_what_they_can_and_cant_see(self):
        view = self.open()
        text = " ".join(child.text() for child in view.findChildren(QLabel))
        for phrase in ("File names", "Folder and collection names", "Roughly how big", "Which algorithm",
                       "which key the files are for", "internet address", "What's inside any file",
                       "never leave this computer", "keep them vague"):
            self.assertIn(phrase, text)

    def test_files_about_to_be_encrypted_show_the_names_they_will_get(self):
        from mindyourownbytes.core import SourceItem
        from mindyourownbytes.gui import provider_view
        items = [SourceItem(self.root / "return.pdf", Path("Taxes 2026/return.pdf"), 1000),
                 SourceItem(self.root / "notes.txt", Path("notes.txt"), 20)]
        shown = provider_view.from_items(items, "Paperwork")
        self.assertEqual([(s.name, s.folder, s.stored_as, s.encrypted) for s in shown], [
            ("return.pdf", "Taxes 2026", "Paperwork/Taxes 2026/return.pdf.gpg", None),
            ("notes.txt", "", "Paperwork/notes.txt.gpg", None)])
        self.assertEqual(provider_view.from_items(items[1:])[0].stored_as, "notes.txt.gpg")

    def test_files_already_encrypted_show_real_bytes_from_their_middle(self):
        from mindyourownbytes.gui import provider_view
        from mindyourownbytes.library import scan_library
        (self.root / "Taxes").mkdir()
        big = bytes([0x8C, 0x0D] * 8) + bytes(range(256)) * 4
        (self.root / "Taxes" / "return.pdf.gpg").write_bytes(big)
        (self.root / "tiny.txt.gpg").write_bytes(b"\x01\x02\x03")
        shown = sorted(provider_view.from_library(scan_library(self.root)), key=lambda s: s.name)
        self.assertEqual([(s.name, s.folder, s.stored_as) for s in shown],
                         [("return.pdf", "Taxes", "Taxes/return.pdf.gpg"), ("tiny.txt", "", "tiny.txt.gpg")])
        middle = len(big) // 2
        expected = " ".join(f"{byte:02x}" for byte in big[middle:middle + 16])
        self.assertEqual(provider_view.sample_bytes(shown[0].encrypted), f"… {expected} …")
        self.assertEqual(provider_view.sample_bytes(shown[1].encrypted), "… 01 02 03 …")
        self.assertEqual(provider_view.sample_bytes(self.root / "gone.gpg"), "")
        view = self.open(shown)
        self.assertEqual(view.table.item(0, 3).text(), f"… {expected} … (unreadable)")
        self.assertIn("real bytes from the middle", view.table.item(0, 3).toolTip())

    def test_the_window_offers_it_with_your_own_files(self):
        from mindyourownbytes.gui import provider_view
        folder = Path(tempfile.mkdtemp(prefix="myobtest"))
        window = self.keep_until_the_end_of_this_test(MainWindow(isolated_settings(folder), folder / "vault.gpg"))
        self.addCleanup(window.close)
        titles = [action.text().replace("&", "") for action in window.findChildren(QAction)]
        self.assertIn("What your provider sees", titles)
        self.assertFalse(window.provider_link.isHidden())
        window.set_operation("restore")
        self.assertTrue(window.provider_link.isHidden())
        window.set_operation("encrypt")
        original = folder / "input" / "return.pdf"
        original.parent.mkdir()
        original.write_bytes(b"x")
        window.add_paths([str(original)])
        window.collection_combo.setCurrentText("Taxes")
        with patch.object(provider_view, "ProviderView") as view:
            window.provider_link.linkActivated.emit("#provider")
        files = view.call_args.args[1]
        self.assertEqual([shown.stored_as for shown in files], ["Taxes/return.pdf.gpg"])
        view.return_value.exec.assert_called_once()

    def test_with_one_archive_your_provider_sees_one_file(self):
        from mindyourownbytes.gui import provider_view
        files = [provider_view.Shown("return.pdf", "Taxes", 1000, "Paperwork/Taxes/return.pdf.gpg"),
                 provider_view.Shown("scan.jpg", "Taxes", 3000, "Paperwork/Taxes/scan.jpg.gpg")]
        view = self.open_archive(files, "Paperwork/Year end.zip.gpg")
        self.assertEqual(view.table.rowCount(), 1)
        self.assertEqual([view.table.item(0, column).text() for column in range(4)],
                         ["Year end.zip.gpg", "Paperwork", "about 3.9 KB", "2 files, unreadable once encrypted"])
        text = " ".join(child.text() for child in view.findChildren(QLabel))
        self.assertIn("The names, folders, sizes, and number of the files inside", text)
        self.assertNotIn("File names, exactly as they are", text)
        view.yours.click()
        self.assertEqual(self.column(view, 0), ["return.pdf", "scan.jpg"])

    def open_archive(self, files, stored):
        from mindyourownbytes.gui import provider_view
        return self.keep_until_the_end_of_this_test(provider_view.ProviderView(None, files, stored))

    def test_the_library_offers_it_for_the_files_chosen(self):
        from mindyourownbytes.gui import library_page
        exports = self.root / "exports"
        (exports / "Taxes").mkdir(parents=True)
        (exports / "Taxes" / "a.pdf.gpg").write_bytes(b"x" * 100)
        (exports / "b.txt.gpg").write_bytes(b"y" * 100)
        page = self.keep_until_the_end_of_this_test(library_page.LibraryPage(lambda: exports))
        page.refresh()
        with patch.object(library_page, "ProviderView") as view:
            page.privacy_line.linkActivated.emit("#provider")
            self.assertEqual(len(view.call_args.args[1]), 2, "every file shown, when none is selected")
            page.table.selectRow(0)
            page.privacy_line.linkActivated.emit("#provider")
            self.assertEqual(len(view.call_args.args[1]), 1)


class FromFileExplorerTests(GuiCase):
    """Right-clicking a file in File Explorer starts the app with that file's path."""

    def test_files_land_on_the_encrypt_screen_and_nothing_is_encrypted(self):
        self.window.show_library()
        taken = self.window.open_paths([str(self.write("a.txt")), str(self.write("b.txt"))])
        self.assertTrue(taken)
        self.assertIs(self.window.pages.currentWidget(), self.window.transfer_page)
        self.assertEqual(self.window.operation, "encrypt")
        self.assertEqual([item.source.name for item in self.window.items], ["a.txt", "b.txt"])
        self.assertFalse(self.window.running)
        self.assertFalse((self.root / "exports").exists())

    def test_a_folder_brings_what_is_inside_it(self):
        self.write("Taxes/a.txt")
        self.write("Taxes/2026/b.txt")
        self.window.open_paths([str(self.root / "input" / "Taxes")])
        self.assertEqual(sorted(str(item.relative) for item in self.window.items),
                         sorted([str(Path("Taxes/a.txt")), str(Path("Taxes/2026/b.txt"))]))

    def test_each_further_file_joins_the_same_list(self):
        self.window.open_paths([str(self.write("a.txt"))])
        self.window.open_paths([str(self.write("b.txt"))])
        self.window.open_paths([str(self.root / "input" / "a.txt")])
        self.assertEqual(sorted(item.source.name for item in self.window.items), ["a.txt", "b.txt"])

    def test_it_switches_from_the_restore_screen(self):
        self.window.set_operation("restore")
        self.window.open_paths([str(self.write("a.txt"))])
        self.assertEqual(self.window.operation, "encrypt")
        self.assertEqual([item.source.name for item in self.window.items], ["a.txt"])

    def test_a_path_that_is_gone_is_left_out_without_a_fuss(self):
        self.window.open_paths([str(self.root / "input" / "gone.txt"), str(self.write("a.txt"))])
        self.assertEqual([item.source.name for item in self.window.items], ["a.txt"])
        self.message_boxes["warning"].assert_not_called()

    def test_nothing_is_added_while_a_job_runs(self):
        self.window.open_paths([str(self.write("a.txt"))])
        self.window.running = True
        self.addCleanup(setattr, self.window, "running", False)
        self.assertFalse(self.window.open_paths([str(self.write("b.txt"))]))
        self.assertEqual([item.source.name for item in self.window.items], ["a.txt"])

    def native(self, paths, magic=None):
        """Deliver a message the way Windows would, and say how the window answered."""
        import ctypes
        from ctypes import wintypes

        from PySide6.QtCore import QByteArray
        from shiboken6 import VoidPtr

        from mindyourownbytes.gui import handover

        data = handover.encode(paths)
        buffer = ctypes.create_string_buffer(data, len(data))
        copy = handover._CopyData(magic or handover._MAGIC, len(data), ctypes.cast(buffer, ctypes.c_void_p))
        message = wintypes.MSG()
        message.message = handover._WM_COPYDATA
        message.lParam = ctypes.addressof(copy)
        answer = self.window.nativeEvent(QByteArray(b"windows_generic_MSG"), VoidPtr(ctypes.addressof(message)))
        QApplication.processEvents()
        return answer

    @unittest.skipUnless(sys.platform == "win32", "Windows messages")
    def test_a_second_copy_of_the_app_can_pass_its_file_to_this_window(self):
        handled, answer = self.native([str(self.write("a.txt"))])
        self.assertEqual((handled, answer), (True, 1))
        self.assertEqual([item.source.name for item in self.window.items], ["a.txt"])

    @unittest.skipUnless(sys.platform == "win32", "Windows messages")
    def test_the_window_says_no_while_a_job_runs_so_the_second_copy_opens_its_own(self):
        self.window.running = True
        self.addCleanup(setattr, self.window, "running", False)
        self.assertEqual(tuple(self.native([str(self.write("a.txt"))])), (True, 0))
        self.assertEqual(self.window.items, [])

    @unittest.skipUnless(sys.platform == "win32", "Windows messages")
    def test_files_that_arrive_while_a_dialog_is_open_wait_for_it_to_close(self):
        # Such as the passphrase dialog: files must not join a list someone is confirming.
        self.window.open_paths([str(self.write("a.txt"))])
        with patch.object(QApplication, "activeModalWidget", return_value=QWidget()):
            self.assertEqual(tuple(self.native([str(self.write("b.txt"))])), (True, 1))
            deadline = time.monotonic() + 0.6
            while time.monotonic() < deadline:
                QApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
            self.assertEqual([item.source.name for item in self.window.items], ["a.txt"])
        self.wait_until(lambda: len(self.window.items) == 2, timeout=5)
        self.assertEqual([item.source.name for item in self.window.items], ["a.txt", "b.txt"])

    def test_files_accepted_just_before_a_job_starts_wait_until_it_ends(self):
        self.window.running = True
        self.window._open_when_ready([str(self.write("a.txt"))])
        deadline = time.monotonic() + 0.6
        while time.monotonic() < deadline:
            QApplication.processEvents(QEventLoop.ProcessEventsFlag.AllEvents, 50)
        self.assertEqual(self.window.items, [])
        self.window.running = False
        self.wait_until(lambda: len(self.window.items) == 1, timeout=5)

    @unittest.skipUnless(sys.platform == "win32", "Windows messages")
    def test_messages_from_anything_else_change_nothing(self):
        self.native([str(self.write("a.txt"))], magic=12345)
        self.assertEqual(self.window.items, [])

    def test_starting_with_a_file_while_the_app_is_open_hands_it_over_and_opens_no_window(self):
        path = str(self.write("a.txt"))
        with patch.object(sys, "argv", ["mindyourownbytes", path]), patch.object(
            main_window.handover, "mark_as_running", return_value=True
        ), patch.object(main_window.handover, "hand_over", return_value=True) as hand_over, patch.object(
            main_window, "create_application"
        ) as create:
            main_window.main()
        hand_over.assert_called_once_with([path])
        create.assert_not_called()

    def test_starting_with_a_file_opens_a_window_holding_it_when_nothing_takes_it(self):
        path = str(self.write("a.txt"))
        for already_open in (False, True):
            with self.subTest(already_open=already_open), patch.object(
                sys, "argv", ["mindyourownbytes", path]
            ), patch.object(main_window.handover, "mark_as_running", return_value=already_open), patch.object(
                main_window.handover, "hand_over", return_value=False
            ), patch.object(main_window.handover, "announce_window") as announce, patch.object(
                main_window, "create_application"
            ), patch.object(main_window, "MainWindow") as window, patch.object(
                main_window.sys, "exit"
            ), patch.object(main_window.sys, "excepthook"):
                window.return_value.winId.return_value = 4242
                main_window.main()
                window.return_value.open_paths.assert_called_once_with([path])
                announce.assert_called_once_with(4242)

    def test_starting_normally_opens_a_window_and_adds_nothing(self):
        with patch.object(sys, "argv", ["mindyourownbytes"]), patch.object(
            main_window.handover, "mark_as_running", return_value=True
        ), patch.object(main_window.handover, "announce_window"), patch.object(
            main_window, "create_application"
        ), patch.object(main_window, "MainWindow") as window, patch.object(main_window.sys, "exit"), patch.object(
            main_window.sys, "excepthook"
        ):
            window.return_value.winId.return_value = 1
            main_window.main()
        window.return_value.show.assert_called_once()
        window.return_value.open_paths.assert_not_called()


class CheckAfterEncryptingTests(GuiCase):
    def finish(self):
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)

    def reopen(self):
        window = MainWindow(self.settings, self.root / "app" / "vault.gpg")
        self.addCleanup(window.close)
        return window

    def test_a_typed_passphrase_gets_every_file_checked_and_the_screen_says_so(self):
        for name in ("a.txt", "b.txt"):
            self.write(name, name.encode())
        self.window.add_paths([str(self.root / "input")])
        self.select_method("once")
        announced = []
        real = main_window.process_items

        def recording(*args, **kwargs):
            notify = kwargs["on_checking"]
            kwargs["on_checking"] = lambda index: (announced.append(index), notify(index))
            return real(*args, **kwargs)

        with patch.object(main_window, "process_items", side_effect=recording) as process, patch.object(
            self.window, "_set_row_status", wraps=self.window._set_row_status
        ) as shown:
            self.run_with_typed_passphrase()
        self.assertTrue(process.call_args.kwargs["verify"])
        self.assertEqual(announced, [0, 1])
        self.assertEqual([call.args[1] for call in shown.call_args_list if call.args[0] == 0],
                         ["Waiting", "Encrypting…", "Checking…", "Encrypted and checked"])
        for row in range(2):
            self.assertEqual(self.window.table.item(row, 3).text(), "Encrypted and checked")
            self.assertIn("matched the original", self.window.table.item(row, 3).toolTip())
            self.assertIn(".txt.gpg", self.window.table.item(row, 3).toolTip())
        self.assertEqual(self.window.result_bar.property("kind"), "success")
        self.assertEqual(self.window.result_bar.title_label.text(), "2 files encrypted with AES-256 and checked")
        self.assertIn("Each one was decrypted again", self.window.result_bar.text())
        self.assertIn("Upload only the .gpg files", self.window.result_bar.text())

    def test_one_file_is_described_in_the_singular(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.assertIn("It was decrypted again and matched the original.", self.window.result_bar.text())

    def test_a_saved_passphrase_gets_files_checked_too(self):
        self.window.vault.create(MASTER)
        self.window.vault_page.refresh()
        self.window.vault.add("Taxes", "tax passphrase here")
        self.window.vault_page.changed.emit()
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("saved")
        self.window.start()
        self.finish()
        self.assertEqual(self.window.table.item(0, 3).text(), "Encrypted and checked")
        self.assertIn("and checked", self.window.result_bar.title_label.text())

    def test_the_switch_is_on_by_default_and_remembered(self):
        self.assertTrue(self.window.check_action.isChecked())
        self.assertTrue(self.window.check_action.isCheckable())
        self.assertIn(self.window.check_action, self.window.menuBar().actions()[2].menu().actions())
        self.assertTrue(self.window.menuBar().actions()[2].menu().toolTipsVisible())
        self.window.check_action.setChecked(False)
        self.assertFalse(self.reopen().check_action.isChecked())
        self.window.check_action.setChecked(True)
        self.assertTrue(self.reopen().check_action.isChecked())

    def test_only_turning_it_off_here_turns_it_off(self):
        # A damaged or edited setting must not quietly stop the checks.
        for saved in ("", "no", "0", "garbage", "False "):
            with self.subTest(saved):
                self.settings.setValue("check_after_encrypting", saved)
                self.assertTrue(self.reopen().check_action.isChecked())

    def test_turned_off_files_are_encrypted_without_claiming_a_check(self):
        self.window.check_action.setChecked(False)
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        with patch.object(main_window, "process_items", wraps=main_window.process_items) as process:
            self.run_with_typed_passphrase()
        self.assertFalse(process.call_args.kwargs["verify"])
        self.assertEqual(self.window.table.item(0, 3).text(), "Encrypted")
        self.assertEqual(self.window.result_bar.title_label.text(), "1 file encrypted with AES-256")
        self.assertNotIn("check", self.window.result_bar.text().lower())
        self.assertTrue((self.root / "exports" / "a.txt.gpg").exists())

    def test_files_for_a_key_are_reported_as_encrypted_but_not_checked(self):
        self.generate_key("Me <me@example.invalid>")
        self.window.refresh_keys()
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("public-key")
        self.window.start()
        self.finish()
        self.assertEqual(self.window.table.item(0, 3).text(), "Signed and encrypted, not checked")
        self.assertIn("private key", self.window.table.item(0, 3).toolTip())
        self.assertEqual(self.window.result_bar.title_label.text(), "1 file signed and encrypted")
        self.assertIn("Not checked, because that takes the private key", self.window.result_bar.text())
        self.assertTrue((self.root / "exports" / "a.txt.gpg").exists())

    def test_files_gnupg_asked_about_are_reported_as_encrypted_but_not_checked(self):
        # The engine is stood in for here, because a real run would open GnuPG's own window.
        seen = {}

        def encrypt_without_checking(gpg, items, output, operation, method, fingerprint, cancel, on_progress,
                                     **kwargs):
            seen.update(kwargs, method=method)
            on_progress(0, True, READY, output / "a.txt.gpg")
            return JobResult(1, 0, False, (output / "a.txt.gpg",))

        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("pinentry")
        with patch.object(main_window, "process_items", side_effect=encrypt_without_checking):
            self.window.start()
            self.finish()
        self.assertEqual((seen["passphrases"], seen["method"]), ([], "password"))
        self.assertEqual(self.window.table.item(0, 3).text(), "Encrypted, not checked")
        self.assertEqual(self.window.result_bar.title_label.text(), "1 file encrypted with AES-256")
        self.assertIn("Not checked, because GnuPG asked for the passphrase itself", self.window.result_bar.text())

    def test_a_restore_never_mentions_the_check(self):
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.window.set_operation("restore")
        self.window.add_paths([str(self.root / "exports" / "a.txt.gpg")])
        self.select_method("once")
        with patch.object(main_window, "process_items", wraps=main_window.process_items) as process:
            self.run_with_typed_passphrase()
        self.assertFalse(process.call_args.kwargs["verify"])
        # It does say that the download matches its saved checksum, which is a different thing.
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored, matches your record")
        self.assertNotIn("and checked", self.window.result_bar.text())
        self.assertNotIn("decrypted again", self.window.result_bar.text())

    def test_an_original_that_changes_meanwhile_fails_plainly_and_can_be_tried_again(self):
        changing = self.write("changing.txt", b"first version")
        self.write("steady.txt", b"stays as it is")
        self.window.add_paths([str(self.root / "input")])
        self.select_method("once")
        real = main_window.process_items

        def changing_the_first(*args, **kwargs):
            notify = kwargs["on_checking"]

            def change_then_notify(index):
                if index == 0:
                    changing.write_bytes(b"second version, saved meanwhile")
                notify(index)

            kwargs["on_checking"] = change_then_notify
            return real(*args, **kwargs)

        with patch.object(main_window, "process_items", side_effect=changing_the_first):
            self.run_with_typed_passphrase()
        self.assertEqual(self.window.table.item(0, 3).text(), "The original changed")
        self.assertIn("no encrypted copy was kept", self.window.table.item(0, 3).toolTip())
        self.assertEqual(self.window.table.item(1, 3).text(), "Encrypted and checked")
        self.assertEqual(self.window.result_bar.property("kind"), "error")
        self.assertIn("1 of 2 files failed", self.window.result_bar.text())
        self.assertNotIn("damaged", self.window.result_bar.text())
        exports = self.root / "exports" / "input"
        self.assertEqual(sorted(p.name for p in exports.iterdir()), ["steady.txt.gpg"])
        self.assertEqual(self.window.start_button.text(), "Try these again")

        self.run_with_typed_passphrase(action=self.window._primary_clicked)
        self.assertEqual([item.source.name for item in self.window.items], ["changing.txt"])
        self.assertEqual(self.window.table.item(0, 3).text(), "Encrypted and checked")
        self.assertEqual(sorted(p.name for p in exports.iterdir()), ["changing.txt.gpg", "steady.txt.gpg"])
        self.assertEqual(self.window.start_button.text(), "Start over")

    def test_progress_says_when_a_file_is_being_checked(self):
        for name in ("a.txt", "b.txt"):
            self.write(name)
        self.window.add_paths([str(self.root / "input")])
        self.window.worker = MagicMock()
        self.window.worker.cancel_event.is_set.return_value = False
        self.window._checking(0)
        self.assertEqual(self.window.table.item(0, 3).text(), "Checking…")
        self.assertEqual(self.window.status_text.text(), "Checking 1 of 2…")
        # Once someone has pressed Cancel, a late message mustn't replace what the screen says about that.
        self.window.worker.cancel_event.is_set.return_value = True
        self.window.status_text.setText("Cancelling after the current file…")
        self.window._checking(1)
        self.assertEqual(self.window.table.item(1, 3).text(), "Waiting")
        self.assertEqual(self.window.status_text.text(), "Cancelling after the current file…")
        self.window.worker = None

    def test_the_switch_cannot_be_changed_while_a_job_runs(self):
        self.window._set_busy(True)
        self.assertFalse(self.window.menuBar().isEnabled())
        self.window._set_busy(False)
        self.assertTrue(self.window.menuBar().isEnabled())


class SimpleAndAdvancedModeTests(GuiCase):
    """Simple by default, with safe settings. One remembered switch shows everything else."""

    def fresh(self, **saved):
        """A window as on a computer where this switch was never set."""
        folder = Path(tempfile.mkdtemp(dir=self.root))
        settings = isolated_settings(folder, advanced=False)
        settings.setValue("output_encrypt", str(self.root / "exports"))
        settings.setValue("output_restore", str(self.root / "restored"))
        for name, value in saved.items():
            settings.setValue(name, value)
        window = MainWindow(settings, folder / "vault.gpg")
        self.addCleanup(window.close)
        return window, settings

    def advanced_widgets_hidden(self, window) -> list[bool]:
        return [window.key_radio.isHidden(), window.algorithm_combo.isHidden(), window.algorithm_label.isHidden(),
                window.check_action.isVisible(), window.pinentry_action.isVisible()]

    def test_a_new_installation_starts_simple_and_remembers_it(self):
        window, settings = self.fresh()
        self.assertFalse(window.advanced())
        self.assertEqual(settings.value("advanced"), "false")
        self.assertEqual(self.advanced_widgets_hidden(window), [True, True, True, False, False])
        self.assertFalse(window.more_options.isHidden())
        self.assertTrue(window.passphrase_radio.isVisibleTo(window.method_card))
        self.assertTrue(window.saved_radio.isVisibleTo(window.method_card))
        self.assertEqual(window.method(), "once")

    def test_anyone_relying_on_an_advanced_option_starts_advanced(self):
        for saved in ({"cipher": "TWOFISH"}, {"use_pinentry": "true"}, {"check_after_encrypting": "false"},
                      {"keep_records": "false"}):
            with self.subTest(saved):
                window, settings = self.fresh(**saved)
                self.assertTrue(window.advanced())
                self.assertEqual(settings.value("advanced"), "true")
                self.assertTrue(window.more_options.isHidden())

    def test_someone_with_a_key_of_their_own_starts_advanced(self):
        self.generate_key("Me <me@example.invalid>")
        window, _ = self.fresh()
        self.assertTrue(window.advanced())
        self.assertFalse(window.key_radio.isHidden())

    def test_a_saved_choice_of_mode_wins_over_any_guess(self):
        window, _ = self.fresh(advanced="false", cipher="TWOFISH", use_pinentry="true")
        self.assertFalse(window.advanced())

    def test_simple_mode_uses_safe_settings_whatever_was_chosen_before(self):
        window, _ = self.fresh(advanced="false", cipher="TWOFISH", use_pinentry="true",
                               check_after_encrypting="false")
        self.assertEqual((window.method(), window.chosen_cipher()), ("once", "AES256"))
        window.add_paths([str(self.write("a.txt", b"simple"))])
        dialog = MagicMock()
        dialog.exec.return_value = True
        dialog.passphrase.return_value = PASSPHRASE
        with patch.object(main_window, "PassphraseDialog", return_value=dialog):
            window.start()
        self.wait_until(lambda: not window.running)
        self.wait_until(lambda: window._thread is None)
        self.assertRegex(self.packets(self.root / "exports" / "a.txt.gpg", PASSPHRASE), r"cipher 9\b")
        self.assertIn("with AES-256 and checked", window.result_bar.title_label.text())

    def test_the_post_quantum_assistant_is_an_advanced_option(self):
        window, _ = self.fresh()
        self.assertFalse(window.post_quantum_action.isVisible())
        window.advanced_action.setChecked(True)
        self.assertTrue(window.post_quantum_action.isVisible())

    def test_simple_mode_always_keeps_checksums_and_hides_the_switch(self):
        window, _ = self.fresh(advanced="false", keep_records="false")
        self.assertFalse(window.records_action.isVisible())
        titles = [action.text().replace("&", "") for action in window.findChildren(QAction) if action.isVisible()]
        self.assertIn("Import checksums…", titles, "importing is needed on any computer, in either mode")
        window.add_paths([str(self.write("a.txt", b"kept"))])
        dialog = MagicMock()
        dialog.exec.return_value = True
        dialog.passphrase.return_value = PASSPHRASE
        with patch.object(main_window, "PassphraseDialog", return_value=dialog):
            window.start()
        self.wait_until(lambda: not window.running)
        self.wait_until(lambda: window._thread is None)
        self.assertEqual([record.name for record in window.ledger.load().records], ["a.txt.gpg"])

    def test_more_options_turns_on_advanced_and_keeps_earlier_choices(self):
        window, settings = self.fresh(advanced="false", cipher="TWOFISH")
        window.more_options.linkActivated.emit("#more")
        self.assertTrue(window.advanced())
        self.assertEqual(settings.value("advanced"), "true")
        self.assertEqual(self.advanced_widgets_hidden(window), [False, False, False, True, True])
        self.assertEqual(window.chosen_cipher(), "TWOFISH", "the earlier choice was kept, not lost")

    def test_switching_to_simple_never_leaves_a_key_chosen(self):
        self.window.set_method("public-key")
        self.assertEqual(self.window.method(), "public-key")
        self.window.advanced_action.setChecked(False)
        self.assertEqual(self.window.method(), "once")
        self.assertTrue(self.window.passphrase_radio.isChecked())
        self.assertEqual(self.settings.value("advanced"), "false")

    def test_simple_mode_still_restores_files_for_a_key(self):
        window, _ = self.fresh()
        self.assertFalse(window.advanced())
        fingerprint = self.generate_key("Me <me@example.invalid>")
        source = self.write("k.txt", b"for the key")
        encrypted = process_items(self.gpg, [SourceItem(source, Path("k.txt"), source.stat().st_size)],
                                  self.root / "exports", "encrypt", "public-key", fingerprint, threading.Event(),
                                  lambda *args: None)
        window.set_operation("restore")
        window.add_paths([str(encrypted.outputs[0])])
        self.assertFalse(window.key_radio.isHidden(), "restoring offers the key when the files need it")
        self.assertEqual(window.method(), "pinentry")
        window.start()
        self.wait_until(lambda: not window.running)
        self.wait_until(lambda: window._thread is None)
        self.assertFalse((self.root / "restored" / "k.txt").exists(), "unsigned, so it waits to be asked")
        anyway = next(button for button in window.result_bar._actions if button.text() == "Restore anyway…")
        anyway.click()
        self.wait_until(lambda: not window.running)
        self.wait_until(lambda: window._thread is None)
        self.assertEqual((self.root / "restored" / "k.txt").read_bytes(), b"for the key")

    def test_the_switch_is_first_in_the_tools_menu_and_explains_itself(self):
        tools = self.window.menuBar().actions()[2].menu()
        self.assertIs(tools.actions()[0], self.window.advanced_action)
        self.assertIn("AES-256", self.window.advanced_action.toolTip())


class AlgorithmChoiceTests(GuiCase):
    def offered(self, window=None):
        combo = (window or self.window).algorithm_combo
        return [combo.itemData(row) for row in range(combo.count())]

    def choose(self, name: str):
        """As a person would, which is the only way a choice gets remembered."""
        row = self.window.algorithm_combo.findData(name)
        self.assertGreaterEqual(row, 0, name)
        self.window.algorithm_combo.setCurrentIndex(row)
        self.window.algorithm_combo.activated.emit(row)

    def reopen(self):
        window = MainWindow(self.settings, self.root / "app" / "vault.gpg")
        self.addCleanup(window.close)
        return window

    def test_aes_256_is_preselected_and_recommended(self):
        self.assertEqual(self.offered(), [cipher.name for cipher in available_ciphers(self.gpg)])
        self.assertEqual(self.window.chosen_cipher(), "AES256")
        self.assertEqual(self.window.algorithm_combo.currentText(), "AES-256 (recommended)")
        self.assertEqual([self.window.algorithm_combo.itemText(row).count("recommended")
                          for row in range(self.window.algorithm_combo.count())],
                         [1] + [0] * (self.window.algorithm_combo.count() - 1))

    def test_the_chosen_algorithm_is_what_the_file_really_uses(self):
        for cipher in available_ciphers(self.gpg):
            with self.subTest(cipher.label):
                self.choose(cipher.name)
                self.window.add_paths([str(self.write(f"{cipher.name}.txt"))])
                self.select_method("once")
                self.run_with_typed_passphrase()
                self.assertRegex(self.packets(self.root / "exports" / f"{cipher.name}.txt.gpg", PASSPHRASE),
                                 rf"symkey enc packet: version \d+, cipher {cipher.packet_id}\b")
                self.assertIn(f"1 file encrypted with {cipher.label}", self.window.result_bar.text())
                self.window.clear_files()

    def test_files_restore_without_being_told_the_algorithm(self):
        self.choose("TWOFISH")
        self.window.add_paths([str(self.write("a.txt", b"no need to remember"))])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.choose("CAMELLIA256")
        self.window.set_operation("restore")
        self.window.add_paths([str(self.root / "exports" / "a.txt.gpg")])
        self.select_method("once")
        self.run_with_typed_passphrase()
        self.assertEqual((self.root / "restored" / "a.txt").read_bytes(), b"no need to remember")
        self.assertNotIn(" with ", self.window.result_bar.title_label.text())

    def test_the_main_button_passes_on_the_chosen_algorithm(self):
        self.choose("TWOFISH")
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("once")
        with patch.object(main_window, "process_items", wraps=main_window.process_items) as process:
            self.run_with_typed_passphrase(action=self.window._primary_clicked)
        self.assertEqual(process.call_args.kwargs["cipher"], "TWOFISH")

    def test_saved_passphrases_use_the_chosen_algorithm_but_the_vault_stays_on_aes_256(self):
        self.choose("CAMELLIA256")
        self.window.vault.create(MASTER)
        self.window.vault_page.refresh()
        self.window.vault.add("Taxes", "tax passphrase here")
        self.window.vault_page.changed.emit()
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("saved")
        self.window.start()
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)
        self.assertRegex(self.packets(self.root / "exports" / "a.txt.gpg", "tax passphrase here"), r"cipher 13\b")
        self.assertRegex(self.packets(self.root / "app" / "vault.gpg", MASTER), r"cipher 9\b")

    def test_a_key_decides_for_itself_and_the_screen_says_so(self):
        self.choose("TWOFISH")
        self.window.key_radio.click()
        self.assertFalse(self.window.algorithm_combo.isEnabled())
        self.assertIn("key", self.window.algorithm_help.text())
        self.window.passphrase_radio.click()
        self.assertTrue(self.window.algorithm_combo.isEnabled())
        self.assertEqual(self.window.chosen_cipher(), "TWOFISH")
        self.assertIn("GnuPG opens it", self.window.algorithm_help.text())

    def test_files_encrypted_to_a_key_dont_claim_the_chosen_algorithm(self):
        self.choose("TWOFISH")
        self.generate_key("Me <me@example.invalid>")
        self.window.refresh_keys()
        self.window.add_paths([str(self.write("a.txt"))])
        self.select_method("public-key")
        self.window.start()
        self.wait_until(lambda: not self.window.running)
        self.wait_until(lambda: self.window._thread is None)
        self.assertIn("1 file signed and encrypted", self.window.result_bar.text())
        self.assertNotIn("Twofish", self.window.result_bar.text())

    def test_key_list_names_each_kind_of_key(self):
        self.generate_key("Me <me@example.invalid>")
        self.window.refresh_keys()
        kind = list_public_keys(self.gpg)[0].algorithm
        self.assertTrue(kind)
        self.assertIn(f" · {kind} · ", self.window.key_combo.itemText(0))

    def test_restoring_has_nothing_to_choose(self):
        shown = (self.window.algorithm_label, self.window.algorithm_combo, self.window.algorithm_help)
        self.assertEqual([widget.isHidden() for widget in shown], [False] * 3)
        self.window.set_operation("restore")
        self.assertEqual([widget.isHidden() for widget in shown], [True] * 3)
        self.window.set_operation("encrypt")
        self.assertEqual([widget.isHidden() for widget in shown], [False] * 3)

    def test_the_choice_is_remembered(self):
        self.choose("CAMELLIA256")
        self.assertEqual(self.reopen().chosen_cipher(), "CAMELLIA256")

    def test_a_saved_choice_this_app_does_not_offer_is_ignored(self):
        # Nothing may weaken encryption by editing a setting.
        for saved in ("CAST5", "3DES", "", "AES256 --s2k-count 1024"):
            with self.subTest(saved):
                self.settings.setValue("cipher", saved)
                window = self.reopen()
                self.assertEqual(window.algorithm_combo.currentText(), "AES-256 (recommended)")
                self.assertEqual(window.chosen_cipher(), "AES256")
                self.assertEqual(self.offered(window), self.offered())

    def test_a_saved_choice_this_gnupg_cannot_use_falls_back_to_the_default(self):
        self.settings.setValue("cipher", "CAMELLIA256")
        with patch.object(main_window, "available_ciphers", return_value=CIPHERS[:2]):
            window = self.reopen()
        self.assertEqual(self.offered(window), ["AES256", "TWOFISH"])
        self.assertEqual(window.algorithm_combo.currentText(), "AES-256 (recommended)")
        self.assertEqual(window.chosen_cipher(), "AES256")

    def test_locating_another_gnupg_updates_the_list(self):
        self.choose("TWOFISH")
        with patch.object(main_window.QFileDialog, "getOpenFileName", return_value=(self.gpg, "")), patch.object(
            main_window, "available_ciphers", return_value=CIPHERS[:1]
        ):
            self.window.select_gpg()
        self.assertEqual(self.offered(), ["AES256"])
        self.assertEqual(self.window.chosen_cipher(), "AES256")

    def test_the_choice_is_locked_while_a_job_runs(self):
        self.window.running = True
        self.window._set_busy(True)
        self.assertFalse(self.window.algorithm_combo.isEnabled())
        self.window.running = False
        self.window._set_busy(False)
        self.assertTrue(self.window.algorithm_combo.isEnabled())
        self.window.key_radio.click()
        self.window.running = True
        self.window._set_busy(True)
        self.window.running = False
        self.window._set_busy(False)
        self.assertFalse(self.window.algorithm_combo.isEnabled(), "a key still decides after the job")

    def test_each_choice_says_what_it_costs(self):
        self.assertEqual(set(main_window.CIPHER_HELP), {cipher.name for cipher in CIPHERS})
        seen = set()
        for row in range(self.window.algorithm_combo.count()):
            self.window.algorithm_combo.setCurrentIndex(row)
            seen.add(self.window.algorithm_help.text())
        self.assertEqual(len(seen), self.window.algorithm_combo.count())
        self.assertNotIn("", seen)

    def test_scrolling_past_a_choice_does_not_change_it(self):
        combo = self.window.algorithm_combo
        self.assertGreater(combo.count(), 1)
        event = QWheelEvent(QPointF(5, 5), QPointF(5, 5), QPoint(), QPoint(0, -120), Qt.MouseButton.NoButton,
                            Qt.KeyboardModifier.NoModifier, Qt.ScrollPhase.NoScrollPhase, False)
        QApplication.sendEvent(combo, event)
        self.assertEqual(combo.currentIndex(), 0)
        for other in (self.window.saved_combo, self.window.key_combo, self.window.collection_combo):
            self.assertIsInstance(other, SteadyComboBox)


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
        page.select_collection("Taxes")
        self.assertEqual([e.display_name for e in page.visible], ["return.pdf"])
        page.select_collection("")
        self.assertEqual([e.display_name for e in page.visible], ["loose.txt"])
        page.select_collection(library_page.ALL_COLLECTIONS)
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

    def test_empty_library_explains_itself_and_offers_a_next_step(self):
        self.window.show_library()
        page = self.window.library_page
        self.assertIs(page.stack.currentWidget(), page.empty_state)
        self.export("a.txt.gpg")
        page.refresh()
        self.assertIs(page.stack.currentWidget(), page.content)

    def test_move_needs_a_selection_and_restore_takes_everything_shown_without_one(self):
        self.export("a.txt.gpg")
        self.export("b.txt.gpg")
        self.window.show_library()
        page = self.window.library_page
        self.assertFalse(page.move_button.isEnabled())
        self.assertTrue(page.restore_button.isEnabled())
        self.assertEqual(page.restore_button.text(), "Restore all 2 files")
        page.table.selectRow(0)
        self.assertTrue(page.move_button.isEnabled())
        self.assertEqual(page.restore_button.text(), "Restore 1 file")

    def test_restoring_everything_in_a_collection_keeps_its_folders(self):
        self.export("Taxes/2026/return.pdf.gpg")
        self.export("Taxes/receipts.pdf.gpg")
        self.export("Medical/scan.png.gpg")
        self.window.show_library()
        page = self.window.library_page
        page.select_collection("Taxes")
        self.assertEqual(page.restore_button.text(), "Restore all 2 files")
        page.restore_selected()
        self.assertEqual(self.window.operation, "restore")
        self.assertEqual(sorted(item.relative.as_posix() for item in self.window.items),
                         ["Taxes/2026/return.pdf.gpg", "Taxes/receipts.pdf.gpg"])

    def test_an_empty_library_has_nothing_to_restore(self):
        self.window.show_library()
        page = self.window.library_page
        page.refresh()
        self.assertFalse(page.restore_button.isEnabled())
        self.assertEqual(page.restore_button.text(), "Restore")

    def test_new_collection_appears_in_both_screens(self):
        self.window.show_library()
        with patch("mindyourownbytes.gui.library_page.QInputDialog.getText", return_value=("Taxes", True)):
            self.window.library_page.new_collection()
        page = self.window.library_page
        page.select_collection("Taxes")
        self.assertEqual(page.current_collection(), "Taxes")
        self.window.set_operation("encrypt")
        self.assertGreaterEqual(self.window.collection_combo.findText("Taxes"), 0)


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class ReadabilityTests(unittest.TestCase):
    """Regression: dialogs once had light text on a light background, which made every
    warning in the app, including the security ones, effectively invisible."""

    #: WCAG AA for normal text.
    MINIMUM = 4.5

    def setUp(self):
        app()
        self.parent = QWidget()
        self.parent.setStyleSheet(theme.stylesheet())

    @staticmethod
    def contrast(first: "QColor", second: "QColor") -> float:
        def luminance(color):
            channels = []
            for value in (color.redF(), color.greenF(), color.blueF()):
                channels.append(value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4)
            return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]

        high, low = sorted((luminance(first), luminance(second)), reverse=True)
        return (high + 0.05) / (low + 0.05)

    def assert_readable(self, widget) -> None:
        widget.resize(420, 200)
        widget.ensurePolished()
        surface = widget.grab().toImage().pixelColor(2, 2)
        label = next((child for child in widget.findChildren(QLabel) if child.text()), None)
        text = (label or widget).palette().windowText().color()
        self.assertGreaterEqual(self.contrast(text, surface), self.MINIMUM)
        widget.close()

    def test_message_box(self):
        box = QMessageBox(self.parent)
        box.setText("A warning the user must be able to read")
        self.assert_readable(box)

    def test_passphrase_dialog(self):
        self.assert_readable(PassphraseDialog(self.parent, "t", "message"))

    def test_input_dialog(self):
        self.assert_readable(QInputDialog(self.parent))

    def test_every_color_pair_is_readable_in_light_and_dark(self):
        pairs = (("on_accent", "accent"), ("text", "card"), ("muted", "card"), ("text", "nav_active"),
                 ("ok", "ok_bg"), ("warn", "warn_bg"), ("error", "error_bg"), ("info", "info_bg"),
                 ("ok", "card"), ("error", "card"), ("muted", "drop"))
        for name, palette in (("light", theme._LIGHT), ("dark", theme._DARK)):
            for foreground, background in pairs:
                with self.subTest(theme=name, pair=(foreground, background)):
                    ratio = self.contrast(QColor(palette[foreground]), QColor(palette[background]))
                    self.assertGreaterEqual(ratio, self.MINIMUM)

    def test_light_and_dark_define_the_same_colors(self):
        self.assertEqual(set(theme._LIGHT), set(theme._DARK))

    def test_every_icon_draws_something(self):
        for name in icons._SHAPES:
            with self.subTest(icon=name):
                image = icons.pixmap(name, 24, "#000000").toImage()
                painted = {image.pixelColor(x, y).alpha() > 0 for x in range(24) for y in range(24)}
                self.assertIn(True, painted)
        self.assertFalse(icons.app_icon().isNull())


@unittest.skipUnless(HAS_QT, "PySide6 is not installed")
class PassphraseDialogTests(unittest.TestCase):
    def setUp(self):
        app()

    def dialog(self, *args, **kwargs):
        """A dialog with no parent, destroyed at the end of the test, on this thread, while Qt runs."""
        from shiboken6 import delete
        dialog = PassphraseDialog(None, *args, **kwargs)
        self.addCleanup(delete, dialog)
        return dialog

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

    def test_a_generated_passphrase_says_how_strong_it_is_and_must_be_saved_first(self):
        dialog = self.dialog("t", "m", confirm=True, min_length=8)
        self.assertIsNotNone(dialog.generator)
        dialog.generator.generate()
        phrase = dialog.first.text()
        self.assertEqual(dialog.second.text(), phrase)
        self.assertEqual(len(phrase.split("-")) >= 7, True)
        self.assertEqual(dialog.first.echoMode(), dialog.first.EchoMode.Normal, "it has to be seen to be saved")
        self.assertIn("about 90 bits", dialog.generator.strength.text())
        self.assertFalse(dialog.generator.strength.isHidden())
        self.assertFalse(self.ok_enabled(dialog))
        self.assertIn("Save it before you continue", dialog.hint.text())
        self.assertFalse(dialog.saved_box.isHidden())
        dialog.saved_box.setChecked(True)
        self.assertTrue(self.ok_enabled(dialog))
        self.assertEqual(dialog.passphrase(), phrase)

    def test_changing_a_generated_passphrase_makes_it_an_ordinary_one(self):
        dialog = self.dialog("t", "m", confirm=True, min_length=8)
        dialog.generator.kind.setCurrentIndex(dialog.generator.kind.findData("characters"))
        dialog.generator.generate()
        self.assertIn("about 147 bits", dialog.generator.strength.text())
        dialog.first.setText(dialog.first.text() + "x")
        dialog.second.setText(dialog.first.text())
        self.assertTrue(dialog.saved_box.isHidden())
        self.assertTrue(dialog.generator.strength.isHidden(), "its strength is no longer known")
        self.assertTrue(self.ok_enabled(dialog))

    def test_a_dialog_with_the_generator_is_freed_as_soon_as_it_is_dropped(self):
        # Regression: a callback into the dialog made a reference cycle, so the dialog was freed whenever
        # Python's collector ran, which can be on a worker thread. That crashed the tests on Linux.
        import gc
        import weakref

        from mindyourownbytes.gui.dialogs import VaultEntryDialog
        gc.disable()
        self.addCleanup(gc.enable)
        for make in (lambda: PassphraseDialog(None, "t", "m", confirm=True), lambda: VaultEntryDialog(None)):
            dialog = make()
            dialog.generator.generate()
            alive = weakref.ref(dialog)
            del dialog
            self.assertIsNone(alive(), "only reference counting may free it, on the thread that dropped it")

    def test_typing_a_passphrase_to_unlock_offers_no_generator(self):
        dialog = self.dialog("t", "m")
        self.assertIsNone(dialog.generator)
        self.assertTrue(dialog.saved_box.isHidden())

    def test_a_problem_generating_leaves_the_fields_alone(self):
        dialog = self.dialog("t", "m", confirm=True)
        with patch("mindyourownbytes.gui.dialogs.generator.generate", side_effect=RuntimeError("no list")), \
                patch.object(QMessageBox, "warning") as warning:
            dialog.generator.generate()
        self.assertEqual(dialog.first.text(), "")
        self.assertIn("no list", warning.call_args.args[2])

    def test_saved_passphrases_can_be_generated_too(self):
        from shiboken6 import delete

        from mindyourownbytes.gui.dialogs import VaultEntryDialog
        dialog = VaultEntryDialog(None)
        self.addCleanup(delete, dialog)
        dialog.label.setText("Taxes")
        dialog.generator.generate()
        self.assertTrue(dialog.passphrase_field.text())
        self.assertTrue(dialog.show_box.isChecked())
        self.assertIn("bits", dialog.generator.strength.text())
        dialog.passphrase_field.setText("typed by hand")
        self.assertTrue(dialog.generator.strength.isHidden())

    def test_input_is_masked_by_default(self):
        from PySide6.QtWidgets import QLineEdit
        dialog = PassphraseDialog(None, "t", "m")
        self.assertEqual(dialog.first.echoMode(), QLineEdit.EchoMode.Password)
        dialog.show_box.setChecked(True)
        self.assertEqual(dialog.first.echoMode(), QLineEdit.EchoMode.Normal)


if __name__ == "__main__":
    unittest.main()
