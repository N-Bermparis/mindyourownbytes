"""The Library screen: browse, search, and organize encrypted exports."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QHBoxLayout,
    QInputDialog,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes.core import SourceItem
from mindyourownbytes.gui import icons
from mindyourownbytes.gui.provider_view import ProviderView, from_library
from mindyourownbytes.gui.widgets import (
    EmptyState,
    FileIcons,
    action_button,
    card,
    configure_table,
    human_size,
    label,
    plural,
)
from mindyourownbytes.library import LibraryEntry, create_collection, list_collections, move_to_collection, scan_library

ALL_COLLECTIONS = "\0all"
NO_COLLECTION_LABEL = "No collection"


class LibraryPage(QWidget):
    #: Selected files, as SourceItems, that the user wants to restore.
    restore_requested = Signal(list)
    #: The user has nothing here yet and wants to start encrypting.
    encrypt_requested = Signal()

    def __init__(self, root: Callable[[], Path], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._root = root
        self._file_icons = FileIcons()
        self.entries: list[LibraryEntry] = []
        self.visible: list[LibraryEntry] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 18, 24, 16)
        layout.setSpacing(10)
        layout.addWidget(label("Library", "title"))
        layout.addWidget(label("Your encrypted files, organized into collections.", "muted"))
        layout.addSpacing(4)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, stretch=1)
        encrypt_button = action_button("Encrypt files", "primary", "encrypt")
        encrypt_button.clicked.connect(self.encrypt_requested)
        self.empty_state = EmptyState(
            "library", "Nothing here yet", "Files you encrypt will appear here, ready to organize and restore.",
            (encrypt_button,),
        )
        self.stack.addWidget(self.empty_state)
        self.content = self._build_content()
        self.stack.addWidget(self.content)

    def _build_content(self) -> QWidget:
        content = QWidget()
        columns = QHBoxLayout(content)
        columns.setContentsMargins(0, 0, 0, 0)
        columns.setSpacing(14)

        left = QVBoxLayout()
        left.setSpacing(6)
        left.addWidget(label("Collections", "stepTitle"))
        self.collections = QListWidget()
        self.collections.setFixedWidth(180)
        self.collections.setAccessibleName("Collections")
        self.collections.currentRowChanged.connect(lambda _row: self.render())
        left.addWidget(self.collections, stretch=1)
        self.new_button = action_button("New collection", icon_name="plus")
        self.new_button.clicked.connect(self.new_collection)
        left.addWidget(self.new_button)
        columns.addLayout(left)

        right = QVBoxLayout()
        right.setSpacing(8)
        tools = QHBoxLayout()
        tools.setSpacing(6)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by file name")
        self.search.setClearButtonEnabled(True)
        self.search.setAccessibleName("Search by file name")
        self.search.textChanged.connect(self.render)
        tools.addWidget(self.search, stretch=1)
        self.open_button = action_button("Open folder", icon_name="folder")
        self.open_button.clicked.connect(self.open_folder)
        tools.addWidget(self.open_button)
        self.refresh_button = action_button("Refresh", icon_name="refresh")
        self.refresh_button.setToolTip("Look in the folder again")
        self.refresh_button.clicked.connect(self.refresh)
        tools.addWidget(self.refresh_button)
        right.addLayout(tools)

        frame = card()
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(1, 1, 1, 1)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Name", "Collection", "Size", "Modified"])
        configure_table(self.table, stretch=(0,))
        self.table.setAccessibleName("Encrypted files")
        self.table.itemSelectionChanged.connect(self._update_actions)
        frame_layout.addWidget(self.table)
        right.addWidget(frame, stretch=1)

        self.privacy_line = label(
            "Your cloud provider can see file and collection names, so keep them vague. "
            "Only the contents are encrypted. <a href='#provider'>See what your provider sees</a>",
            "muted", wrap=True,
        )
        self.privacy_line.linkActivated.connect(lambda _link: self.show_provider_view())
        right.addWidget(self.privacy_line)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.count_label = label("", "muted")
        actions.addWidget(self.count_label, stretch=1)
        self.move_button = action_button("Move to…", icon_name="move")
        self.move_button.clicked.connect(self.move_selected)
        actions.addWidget(self.move_button)
        self.restore_button = action_button("Restore", "primary")
        self.restore_button.clicked.connect(self.restore_selected)
        actions.addWidget(self.restore_button)
        right.addLayout(actions)
        columns.addLayout(right, stretch=1)
        return content

    def refresh_theme(self) -> None:
        self.empty_state.refresh_icon()
        self.refresh()

    def refresh(self) -> None:
        root = self._root()
        self.entries = scan_library(root)
        names = list_collections(root)
        self.stack.setCurrentWidget(self.content if self.entries or names else self.empty_state)
        counts = Counter(entry.collection for entry in self.entries)
        previous = self.current_collection()
        self.collections.blockSignals(True)
        self.collections.clear()
        self._add_collection("All files", ALL_COLLECTIONS, "library", len(self.entries))
        if counts[""]:
            self._add_collection(NO_COLLECTION_LABEL, "", "file", counts[""])
        for name in names:
            self._add_collection(name, name, "folder", counts[name])
        self.collections.blockSignals(False)
        self.select_collection(previous if previous is not None else ALL_COLLECTIONS)
        if self.collections.currentRow() < 0:
            self.collections.setCurrentRow(0)
        self.render()

    def _add_collection(self, text: str, data: str, icon_name: str, count: int) -> None:
        item = QListWidgetItem(icons.icon(icon_name), f"{text}  ({count})")
        item.setData(Qt.ItemDataRole.UserRole, data)
        item.setToolTip(text)
        self.collections.addItem(item)

    def current_collection(self) -> str | None:
        item = self.collections.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def select_collection(self, data: str) -> None:
        for row in range(self.collections.count()):
            if self.collections.item(row).data(Qt.ItemDataRole.UserRole) == data:
                self.collections.setCurrentRow(row)
                return

    def render(self) -> None:
        query = self.search.text().strip().casefold()
        wanted = self.current_collection()
        self.visible = [
            entry for entry in self.entries
            if (wanted in (None, ALL_COLLECTIONS) or entry.collection == wanted)
            and (not query or query in str(entry.relative).casefold())
        ]
        self.table.setRowCount(len(self.visible))
        for row, entry in enumerate(self.visible):
            name = QTableWidgetItem(self._file_icons.for_name(entry.path.name), entry.display_name)
            name.setToolTip(str(entry.path))
            self.table.setItem(row, 0, name)
            self.table.setItem(row, 1, QTableWidgetItem(entry.collection or "—"))
            self.table.setItem(row, 2, QTableWidgetItem(human_size(entry.size)))
            modified = datetime.fromtimestamp(entry.modified).strftime("%Y-%m-%d %H:%M")
            self.table.setItem(row, 3, QTableWidgetItem(modified))
        total = sum(entry.size for entry in self.visible)
        self.count_label.setText(f"{plural(len(self.visible))} · {human_size(total)}")
        self._update_actions()

    def _update_actions(self) -> None:
        count = len(self._selected_entries())
        self.move_button.setEnabled(bool(count))
        self.restore_button.setEnabled(bool(count))
        self.restore_button.setText(f"Restore {plural(count)}" if count else "Restore")

    def _selected_entries(self) -> list[LibraryEntry]:
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        return [self.visible[row] for row in rows if row < len(self.visible)]

    def new_collection(self) -> None:
        name, accepted = QInputDialog.getText(
            self, "New collection",
            "Name for this collection. Your cloud provider can see it, so keep it vague:",
        )
        if not accepted:
            return
        try:
            create_collection(self._root(), name)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Could not create the collection", str(exc))
            return
        self.refresh()

    def move_selected(self) -> None:
        selected = self._selected_entries()
        if not selected:
            QMessageBox.information(self, "Nothing selected", "Select one or more files first.")
            return
        options = [NO_COLLECTION_LABEL, *list_collections(self._root())]
        choice, accepted = QInputDialog.getItem(
            self, "Move to collection", f"Move {plural(len(selected))} to, or type a new collection name:",
            options, 0, True,
        )
        if not accepted:
            return
        target = "" if choice == NO_COLLECTION_LABEL else choice
        try:
            move_to_collection(self._root(), [entry.path for entry in selected], target)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Could not move the files", str(exc))
        self.refresh()

    def show_provider_view(self) -> None:
        """The selected files, or every one shown, as you see them and as your provider does."""
        chosen = self._selected_entries() or list(self.visible)
        ProviderView(self, from_library(chosen)).exec()

    def open_folder(self) -> None:
        root = self._root()
        root.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(root)))

    def restore_selected(self) -> None:
        selected = self._selected_entries()
        if not selected:
            QMessageBox.information(self, "Nothing selected", "Select one or more files first.")
            return
        self.restore_requested.emit(
            [SourceItem(entry.path, entry.relative, entry.size) for entry in selected]
        )
