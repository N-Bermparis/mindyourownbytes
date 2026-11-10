"""Drive the real window headlessly, with a real GnuPG behind it."""

import importlib.util
import os
import runpy
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from mindyourownbytes.core import CIPHERS, READY, JobResult, available_ciphers, list_public_keys
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
        self.assertEqual(self.window.table.item(0, 3).text(), "Encrypted, not checked")
        self.assertIn("private key", self.window.table.item(0, 3).toolTip())
        self.assertEqual(self.window.result_bar.title_label.text(), "1 file encrypted")
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
        self.assertEqual(self.window.table.item(0, 3).text(), "Restored")
        self.assertNotIn("check", self.window.result_bar.text().lower())

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
        self.assertIn("1 file encrypted", self.window.result_bar.text())
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

    def test_actions_are_only_available_with_a_selection(self):
        self.export("a.txt.gpg")
        self.export("b.txt.gpg")
        self.window.show_library()
        page = self.window.library_page
        self.assertFalse(page.restore_button.isEnabled())
        self.assertFalse(page.move_button.isEnabled())
        page.table.selectRow(0)
        self.assertTrue(page.restore_button.isEnabled())
        self.assertEqual(page.restore_button.text(), "Restore 1 file")

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
