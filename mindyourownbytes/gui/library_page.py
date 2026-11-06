"""The Library screen: browse, search, and organize encrypted exports."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes.core import SourceItem
from mindyourownbytes.gui.widgets import action_button, human_size
from mindyourownbytes.library import LibraryEntry, create_collection, list_collections, move_to_collection, scan_library

ALL_COLLECTIONS = "\0all"
NO_COLLECTION_LABEL = "(no collection)"


class LibraryPage(QWidget):
    #: Selected files, as SourceItems, that the user wants to restore.
    restore_requested = Signal(list)

    def __init__(self, root: Callable[[], Path], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._root = root
        self.entries: list[LibraryEntry] = []
        self.visible: list[LibraryEntry] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(34, 27, 34, 24)
        layout.setSpacing(14)
        heading = QLabel("Library")
        heading.setObjectName("title")
        layout.addWidget(heading)
        subtitle = QLabel("Your encrypted exports, organized into collections.")
        subtitle.setObjectName("mutedLabel")
        layout.addWidget(subtitle)

        filters = QHBoxLayout()
        filters.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by file name")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.render)
        filters.addWidget(self.search, stretch=1)
        self.collection_filter = QComboBox()
        self.collection_filter.setMinimumWidth(190)
        self.collection_filter.currentIndexChanged.connect(self.render)
        filters.addWidget(self.collection_filter)
        self.refresh_button = action_button("↻", "subtle")
        self.refresh_button.setToolTip("Scan the export folder again")
        self.refresh_button.clicked.connect(self.refresh)
        filters.addWidget(self.refresh_button)
        layout.addLayout(filters)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["FILE", "COLLECTION", "SIZE", "MODIFIED"])
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in (1, 2, 3):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        layout.addWidget(self.table, stretch=1)

        note = QLabel("Cloud providers can read file and collection names, so keep them vague. "
                      "File contents stay encrypted.")
        note.setObjectName("mutedLabel")
        note.setWordWrap(True)
        layout.addWidget(note)

        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.count_label = QLabel()
        self.count_label.setObjectName("mutedLabel")
        actions.addWidget(self.count_label, stretch=1)
        self.new_button = action_button("New collection", "subtle")
        self.new_button.clicked.connect(self.new_collection)
        actions.addWidget(self.new_button)
        self.move_button = action_button("Move to…")
        self.move_button.clicked.connect(self.move_selected)
        actions.addWidget(self.move_button)
        self.open_button = action_button("Open folder")
        self.open_button.clicked.connect(self.open_folder)
        actions.addWidget(self.open_button)
        self.restore_button = action_button("Restore selected  →", "primary")
        self.restore_button.clicked.connect(self.restore_selected)
        actions.addWidget(self.restore_button)
        layout.addLayout(actions)

    def refresh(self) -> None:
        root = self._root()
        self.entries = scan_library(root)
        previous = self.collection_filter.currentData()
        self.collection_filter.blockSignals(True)
        self.collection_filter.clear()
        self.collection_filter.addItem("All collections", ALL_COLLECTIONS)
        self.collection_filter.addItem(NO_COLLECTION_LABEL, "")
        for name in list_collections(root):
            self.collection_filter.addItem(name, name)
        index = self.collection_filter.findData(previous)
        self.collection_filter.setCurrentIndex(max(index, 0))
        self.collection_filter.blockSignals(False)
        self.render()

    def render(self) -> None:
        query = self.search.text().strip().casefold()
        wanted = self.collection_filter.currentData()
        self.visible = [
            entry for entry in self.entries
            if (wanted in (None, ALL_COLLECTIONS) or entry.collection == wanted)
            and (not query or query in str(entry.relative).casefold())
        ]
        self.table.setRowCount(len(self.visible))
        for row, entry in enumerate(self.visible):
            modified = datetime.fromtimestamp(entry.modified).strftime("%Y-%m-%d %H:%M")
            values = (entry.display_name, entry.collection or "—", human_size(entry.size), modified)
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                if column == 0:
                    cell.setToolTip(str(entry.path))
                self.table.setItem(row, column, cell)
            self.table.setRowHeight(row, 34)
        total = sum(entry.size for entry in self.visible)
        count = len(self.visible)
        self.count_label.setText(f"{count} file{'s' if count != 1 else ''} · {human_size(total)}")

    def _selected_entries(self) -> list[LibraryEntry]:
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        return [self.visible[row] for row in rows if row < len(self.visible)]

    def new_collection(self) -> None:
        name, accepted = QInputDialog.getText(self, "New collection", "Collection name:")
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
            self, "Move to collection", "Move to, or type a new collection name:", options, 0, True,
        )
        if not accepted:
            return
        target = "" if choice == NO_COLLECTION_LABEL else choice
        try:
            move_to_collection(self._root(), [entry.path for entry in selected], target)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Could not move the files", str(exc))
        self.refresh()

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
