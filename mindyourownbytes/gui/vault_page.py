"""The Passphrases screen: create, unlock, and manage the encrypted vault."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QHBoxLayout,
    QInputDialog,
    QLineEdit,
    QMessageBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes.core import is_valid_gpg
from mindyourownbytes.gui import gnupg_help
from mindyourownbytes.gui.dialogs import PassphraseDialog, VaultEntryDialog
from mindyourownbytes.gui.widgets import (
    EmptyState,
    SecretClipboard,
    WaitCursor,
    action_button,
    card,
    configure_table,
    label,
)
from mindyourownbytes.vault import MIN_MASTER_LENGTH, Vault, VaultEntry, VaultError, WrongMasterPassphrase

AUTO_LOCK_MS = 15 * 60 * 1000

_NO_RECOVERY = (
    "There is no way to recover a forgotten master passphrase, and nobody can reset it. "
    "Write it down and keep it somewhere safe."
)


class VaultPage(QWidget):
    #: Lock state or the list of entries changed.
    changed = Signal()

    def __init__(self, vault: Vault, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.vault = vault
        self.clipboard = SecretClipboard()
        self._lock_timer = QTimer(self)
        self._lock_timer.setSingleShot(True)
        self._lock_timer.setInterval(AUTO_LOCK_MS)
        self._lock_timer.timeout.connect(self.lock)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 18, 24, 16)
        layout.setSpacing(10)
        layout.addWidget(label("Passphrases", "title"))
        layout.addWidget(label(
            "Keep a different passphrase for each kind of document, safely in one place.", "muted", wrap=True,
        ))
        layout.addSpacing(4)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, stretch=1)
        self.setup_panel = self._build_setup_panel()
        self.locked_panel = self._build_locked_panel()
        self.unlocked_panel = self._build_unlocked_panel()
        for panel in (self.setup_panel, self.locked_panel, self.unlocked_panel):
            self.stack.addWidget(panel)
        self.refresh()

    def _build_setup_panel(self) -> QWidget:
        self.create_button = action_button("Create vault", "primary")
        self.create_button.clicked.connect(self.create_vault)
        self.setup_state = EmptyState(
            "key", "Save your passphrases in an encrypted vault",
            "This is optional. They stay on this computer, in one file that GnuPG encrypts under a master "
            "passphrase of your choice. Nothing is uploaded, and your encrypted files still open without "
            f"this app.\n\n{_NO_RECOVERY}",
            (self.create_button,),
        )
        return self.setup_state

    def _build_locked_panel(self) -> QWidget:
        self.unlock_button = action_button("Unlock", "primary", "restore")
        self.unlock_button.clicked.connect(self.request_unlock)
        self.locked_state = EmptyState(
            "encrypt", "Your saved passphrases are locked", "Enter your master passphrase to use them.",
            (self.unlock_button,),
        )
        return self.locked_state

    def _build_unlocked_panel(self) -> QWidget:
        panel = QWidget()
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(8)

        actions = QHBoxLayout()
        actions.setSpacing(6)
        self.add_button = action_button("Add passphrase", "primary", "plus")
        self.add_button.clicked.connect(self.add_entry)
        actions.addWidget(self.add_button)
        actions.addStretch(1)
        self.copy_button = action_button("Copy", icon_name="copy")
        self.copy_button.setToolTip("Copies it for 30 seconds, then clears the clipboard")
        self.copy_button.clicked.connect(self.copy_selected)
        self.show_button = action_button("Show", icon_name="eye")
        self.show_button.clicked.connect(self.show_selected)
        self.rename_button = action_button("Rename", icon_name="edit")
        self.rename_button.clicked.connect(self.rename_selected)
        self.delete_button = action_button("Delete", icon_name="trash")
        self.delete_button.clicked.connect(self.delete_selected)
        self._selection_buttons = (self.copy_button, self.show_button, self.rename_button, self.delete_button)
        for button in self._selection_buttons:
            actions.addWidget(button)
        outer.addLayout(actions)

        frame = card()
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(1, 1, 1, 1)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Name", "Note", "Created"])
        configure_table(self.table, stretch=(0, 1), multi_select=False)
        self.table.setAccessibleName("Saved passphrases")
        self.table.itemSelectionChanged.connect(self._update_actions)
        frame_layout.addWidget(self.table)
        outer.addWidget(frame, stretch=1)

        self.feedback = label("", "muted", wrap=True)
        outer.addWidget(self.feedback)

        footer = QHBoxLayout()
        footer.setSpacing(6)
        self.location_note = label("", "muted", wrap=True)
        self.location_note.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        footer.addWidget(self.location_note, stretch=1)
        self.open_folder_button = action_button("Open folder", icon_name="folder")
        self.open_folder_button.setToolTip("Open the folder holding the vault, so you can back it up")
        self.open_folder_button.clicked.connect(self.open_vault_folder)
        footer.addWidget(self.open_folder_button)
        self.change_master_button = action_button("Change master passphrase")
        self.change_master_button.clicked.connect(self.change_master)
        footer.addWidget(self.change_master_button)
        self.lock_button = action_button("Lock now", icon_name="encrypt")
        self.lock_button.clicked.connect(self.lock)
        footer.addWidget(self.lock_button)
        outer.addLayout(footer)
        return panel

    def refresh_theme(self) -> None:
        self.setup_state.refresh_icon()
        self.locked_state.refresh_icon()

    def refresh(self) -> None:
        if not self.vault.exists:
            self.vault.lock()
            self.stack.setCurrentWidget(self.setup_panel)
        elif not self.vault.unlocked:
            self.stack.setCurrentWidget(self.locked_panel)
        else:
            self.stack.setCurrentWidget(self.unlocked_panel)
            self._render_entries()

    def _render_entries(self) -> None:
        entries = self.vault.entries
        self.table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            for column, value in enumerate((entry.label, entry.note or "—", entry.created[:10] or "—")):
                cell = QTableWidgetItem(value)
                cell.setData(Qt.ItemDataRole.UserRole, entry.id)
                self.table.setItem(row, column, cell)
        self.location_note.setText(
            "Locks by itself after 15 minutes without use, and when you close the app. "
            f"Back up this file, and remember your master passphrase: {self.vault.path}"
        )
        self._update_actions()

    def _update_actions(self) -> None:
        selected = bool(self.table.selectionModel().selectedRows())
        for button in self._selection_buttons:
            button.setEnabled(selected)

    def touch(self) -> None:
        """Restart the auto-lock countdown after the vault is used."""
        if self.vault.unlocked:
            self._lock_timer.start()

    def _after_change(self) -> None:
        self.touch()
        self.refresh()
        self.changed.emit()

    def _gpg_ready(self) -> bool:
        if self.vault.gpg and is_valid_gpg(self.vault.gpg):
            return True
        QMessageBox.warning(self, "GnuPG is required",
                            f"The vault is encrypted by GnuPG. {gnupg_help.for_this_system().vault}")
        return False

    def create_vault(self) -> None:
        if not self._gpg_ready():
            return
        dialog = PassphraseDialog(
            self, "Create a master passphrase",
            f"This one passphrase protects every saved passphrase, so make it strong: at least "
            f"{MIN_MASTER_LENGTH} characters, and ideally five or more random words.\n\n{_NO_RECOVERY}",
            confirm=True, min_length=MIN_MASTER_LENGTH, ok_text="Create vault",
        )
        if not dialog.exec():
            return
        try:
            with WaitCursor():
                self.vault.create(dialog.passphrase())
        except (VaultError, ValueError) as exc:
            QMessageBox.warning(self, "Could not create the vault", str(exc))
            return
        self._after_change()

    def request_unlock(self) -> bool:
        """Prompt until unlocked or cancelled. Returns whether the vault is unlocked."""
        if not self._gpg_ready():
            return False
        message = "Enter your master passphrase."
        while not self.vault.unlocked:
            dialog = PassphraseDialog(self, "Unlock saved passphrases", message, ok_text="Unlock")
            if not dialog.exec():
                return False
            try:
                with WaitCursor():
                    self.vault.unlock(dialog.passphrase())
            except WrongMasterPassphrase:
                message = "That did not open the vault. Check it and try again."
            except (VaultError, ValueError) as exc:
                QMessageBox.warning(self, "Could not open the vault", str(exc))
                return False
        self._after_change()
        return True

    def lock(self) -> None:
        self._lock_timer.stop()
        self.clipboard.clear()
        self.vault.lock()
        self.table.setRowCount(0)
        self.feedback.setText("")
        self.refresh()
        self.changed.emit()

    def _selected(self) -> VaultEntry | None:
        rows = self.table.selectionModel().selectedRows()
        if not rows or not self.vault.unlocked:
            QMessageBox.information(self, "Nothing selected", "Select a passphrase first.")
            return None
        entry_id = self.table.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        self.touch()
        return next((entry for entry in self.vault.entries if entry.id == entry_id), None)

    def add_entry(self) -> None:
        dialog = VaultEntryDialog(self)
        if not dialog.exec():
            return
        label_text, passphrase, note = dialog.values()
        try:
            with WaitCursor():
                self.vault.add(label_text, passphrase, note)
        except (VaultError, ValueError) as exc:
            QMessageBox.warning(self, "Could not save", str(exc))
            return
        self._after_change()

    def copy_selected(self) -> None:
        entry = self._selected()
        if entry:
            self.clipboard.copy(entry.passphrase)
            self.feedback.setText(f"Copied “{entry.label}”. The clipboard clears in 30 seconds.")

    def show_selected(self) -> None:
        entry = self._selected()
        if not entry:
            return
        box = QMessageBox(self)
        box.setWindowTitle(entry.label)
        box.setTextFormat(Qt.TextFormat.PlainText)
        box.setText(entry.passphrase)
        box.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        box.exec()

    def rename_selected(self) -> None:
        entry = self._selected()
        if not entry:
            return
        name, accepted = QInputDialog.getText(self, "Rename", "New name:", QLineEdit.EchoMode.Normal, entry.label)
        if not accepted:
            return
        try:
            with WaitCursor():
                self.vault.rename(entry.id, name)
        except VaultError as exc:
            QMessageBox.warning(self, "Could not rename", str(exc))
            return
        self._after_change()

    def delete_selected(self) -> None:
        entry = self._selected()
        if not entry:
            return
        answer = QMessageBox.warning(
            self, "Delete this passphrase?",
            f"Delete “{entry.label}” from the vault?\n\nAny file encrypted with it can no longer be "
            "opened unless you have another copy of the passphrase. The files themselves are not touched.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            with WaitCursor():
                self.vault.remove(entry.id)
        except VaultError as exc:
            QMessageBox.warning(self, "Could not delete", str(exc))
            return
        self._after_change()

    def open_vault_folder(self) -> None:
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.vault.path.parent)))

    def change_master(self) -> None:
        current = PassphraseDialog(self, "Change master passphrase", "Enter your current master passphrase.",
                                   ok_text="Continue")
        if not current.exec():
            return
        new = PassphraseDialog(
            self, "Change master passphrase", f"Choose a new master passphrase.\n\n{_NO_RECOVERY}",
            confirm=True, min_length=MIN_MASTER_LENGTH, ok_text="Change it",
        )
        if not new.exec():
            return
        try:
            with WaitCursor():
                self.vault.change_master(current.passphrase(), new.passphrase())
        except (VaultError, ValueError) as exc:
            QMessageBox.warning(self, "Could not change it", str(exc))
            return
        self._after_change()
        self.feedback.setText("The vault now uses your new master passphrase.")
