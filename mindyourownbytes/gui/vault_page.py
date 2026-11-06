"""The Passphrases screen: create, unlock, and manage the encrypted vault."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes.core import is_valid_gpg
from mindyourownbytes.gui.dialogs import PassphraseDialog, VaultEntryDialog
from mindyourownbytes.gui.widgets import SecretClipboard, WaitCursor, action_button
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
        layout.setContentsMargins(34, 27, 34, 24)
        layout.setSpacing(16)
        heading = QLabel("Saved passphrases")
        heading.setObjectName("title")
        layout.addWidget(heading)
        subtitle = QLabel("Keep a different passphrase for each kind of document, inside one encrypted file.")
        subtitle.setObjectName("mutedLabel")
        layout.addWidget(subtitle)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, stretch=1)
        self.setup_panel = self._build_setup_panel()
        self.locked_panel = self._build_locked_panel()
        self.unlocked_panel = self._build_unlocked_panel()
        for panel in (self.setup_panel, self.locked_panel, self.unlocked_panel):
            self.stack.addWidget(panel)
        self.refresh()

    def _card(self, title: str, body: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("optionsCard")
        inner = QVBoxLayout(card)
        inner.setContentsMargins(24, 22, 24, 22)
        inner.setSpacing(12)
        headline = QLabel(title)
        headline.setObjectName("dropTitle")
        inner.addWidget(headline)
        text = QLabel(body)
        text.setObjectName("mutedLabel")
        text.setWordWrap(True)
        inner.addWidget(text)
        return card, inner

    def _build_setup_panel(self) -> QWidget:
        panel = QWidget()
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(0, 0, 0, 0)
        card, inner = self._card(
            "Set up your vault",
            "Saved passphrases are optional. They stay on this computer, inside one file that GnuPG "
            "encrypts under a master passphrase of your choice. Nothing is uploaded, and your encrypted "
            "files stay standard .gpg files that open without this app.\n\n" + _NO_RECOVERY,
        )
        self.create_button = action_button("Create vault", "primary")
        self.create_button.clicked.connect(self.create_vault)
        row = QHBoxLayout()
        row.addWidget(self.create_button)
        row.addStretch(1)
        inner.addLayout(row)
        outer.addWidget(card)
        outer.addStretch(1)
        return panel

    def _build_locked_panel(self) -> QWidget:
        panel = QWidget()
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(0, 0, 0, 0)
        card, inner = self._card("Your vault is locked", "Enter your master passphrase to use saved passphrases.")
        self.unlock_button = action_button("Unlock", "primary")
        self.unlock_button.clicked.connect(self.request_unlock)
        row = QHBoxLayout()
        row.addWidget(self.unlock_button)
        row.addStretch(1)
        inner.addLayout(row)
        outer.addWidget(card)
        outer.addStretch(1)
        return panel

    def _build_unlocked_panel(self) -> QWidget:
        panel = QWidget()
        outer = QVBoxLayout(panel)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(12)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["NAME", "NOTE", "CREATED"])
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        outer.addWidget(self.table, stretch=1)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.add_button = action_button("+ Add passphrase", "primary")
        self.add_button.clicked.connect(self.add_entry)
        self.copy_button = action_button("Copy")
        self.copy_button.setToolTip("Copies for 30 seconds, then clears the clipboard")
        self.copy_button.clicked.connect(self.copy_selected)
        self.show_button = action_button("Show")
        self.show_button.clicked.connect(self.show_selected)
        self.rename_button = action_button("Rename", "subtle")
        self.rename_button.clicked.connect(self.rename_selected)
        self.delete_button = action_button("Delete", "subtle")
        self.delete_button.clicked.connect(self.delete_selected)
        for button in (self.add_button, self.copy_button, self.show_button, self.rename_button, self.delete_button):
            actions.addWidget(button)
        actions.addStretch(1)
        outer.addLayout(actions)

        footer = QHBoxLayout()
        footer.setSpacing(8)
        self.location_note = QLabel()
        self.location_note.setObjectName("mutedLabel")
        self.location_note.setWordWrap(True)
        self.location_note.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        footer.addWidget(self.location_note, stretch=1)
        self.change_master_button = action_button("Change master", "subtle")
        self.change_master_button.clicked.connect(self.change_master)
        footer.addWidget(self.change_master_button)
        self.lock_button = action_button("Lock now", "danger")
        self.lock_button.clicked.connect(self.lock)
        footer.addWidget(self.lock_button)
        outer.addLayout(footer)
        return panel

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
            self.table.setRowHeight(row, 34)
        self.location_note.setText(
            f"Back up this file, and remember the master passphrase: {self.vault.path}\n"
            "Locks after 15 minutes without use, and when you close the app. The app can't erase "
            "secrets from memory until then, so lock it before leaving your computer."
        )

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
                            "The vault is encrypted by GnuPG. Install Gpg4win, or click Locate GnuPG, then try again.")
        return False

    def create_vault(self) -> None:
        if not self._gpg_ready():
            return
        dialog = PassphraseDialog(
            self, "Create a master passphrase",
            f"This one passphrase protects every saved passphrase, so make it strong: at least "
            f"{MIN_MASTER_LENGTH} characters, and ideally five or more random words.\n\n{_NO_RECOVERY}",
            confirm=True, min_length=MIN_MASTER_LENGTH,
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
            dialog = PassphraseDialog(self, "Unlock saved passphrases", message)
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
        label, passphrase, note = dialog.values()
        try:
            with WaitCursor():
                self.vault.add(label, passphrase, note)
        except (VaultError, ValueError) as exc:
            QMessageBox.warning(self, "Could not save", str(exc))
            return
        self._after_change()

    def copy_selected(self) -> None:
        entry = self._selected()
        if entry:
            self.clipboard.copy(entry.passphrase)

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
        label, accepted = QInputDialog.getText(self, "Rename", "New name:", QLineEdit.EchoMode.Normal, entry.label)
        if not accepted:
            return
        try:
            with WaitCursor():
                self.vault.rename(entry.id, label)
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

    def change_master(self) -> None:
        current = PassphraseDialog(self, "Change master passphrase", "Enter your current master passphrase.")
        if not current.exec():
            return
        new = PassphraseDialog(
            self, "Change master passphrase", f"Choose a new master passphrase.\n\n{_NO_RECOVERY}",
            confirm=True, min_length=MIN_MASTER_LENGTH,
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
        QMessageBox.information(self, "Master passphrase changed", "The vault now uses the new passphrase.")
