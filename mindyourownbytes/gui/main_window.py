"""Main window: navigation, the encrypt/restore queue, and the background job."""

from __future__ import annotations

import sys
import threading
import traceback
from pathlib import Path

from PySide6.QtCore import QObject, QSettings, Qt, QThread, QUrl, Signal, Slot
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes import __version__
from mindyourownbytes.core import (
    MIN_GPG_VERSION,
    JobResult,
    PublicKey,
    SourceItem,
    collect_files,
    find_gpg,
    is_valid_gpg,
    list_public_keys,
    looks_cloud_synced,
    process_items,
)
from mindyourownbytes.gui.dialogs import PassphraseDialog
from mindyourownbytes.gui.library_page import LibraryPage
from mindyourownbytes.gui.vault_page import VaultPage
from mindyourownbytes.gui.widgets import action_button, human_size, repolish
from mindyourownbytes.library import list_collections, validate_collection_name
from mindyourownbytes.vault import Vault, default_vault_path

STYLESHEET = Path(__file__).resolve().parent.parent / "styles.qss"
DEFAULT_ROOT = Path.home() / "mindyourownbytes"

ENCRYPT_METHODS = (
    ("Passphrase · type once for this batch", "once"),
    ("Passphrase · GnuPG asks for each file", "pinentry"),
    ("Saved passphrase", "saved"),
    ("OpenPGP public key", "public-key"),
)
RESTORE_METHODS = (
    ("GnuPG asks (passphrase or private key)", "pinentry"),
    ("Passphrase · type once for this batch", "once"),
    ("Saved passphrase", "saved"),
)
TRY_ALL_SAVED = "\0all"


class DropZone(QFrame):
    paths_dropped = Signal(list)

    def __init__(self, title: str, subtitle: str, on_click) -> None:
        super().__init__()
        self._on_click = on_click
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(96)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(8)
        symbol = QLabel("⇪")
        symbol.setObjectName("dropIcon")
        symbol.setAlignment(Qt.AlignmentFlag.AlignCenter)
        headline = QLabel(title)
        headline.setObjectName("dropTitle")
        headline.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint = QLabel(subtitle)
        hint.setObjectName("mutedLabel")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        for child in (symbol, headline, hint):
            layout.addWidget(child)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() and all(url.isLocalFile() for url in event.mimeData().urls()):
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        if paths:
            self.paths_dropped.emit(paths)
            event.acceptProposedAction()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self._on_click()
        super().mouseReleaseEvent(event)


class BackupWorker(QObject):
    progress = Signal(int, bool, str, object)
    completed = Signal(object)
    error = Signal(str)
    finished = Signal()

    def __init__(self, gpg: str, files: list[SourceItem], output: Path, operation: str,
                 method: str, fingerprint: str | None, passphrases: list[str]):
        super().__init__()
        self.gpg = gpg
        self.files = files
        self.output = output
        self.operation = operation
        self.method = method
        self.fingerprint = fingerprint
        self.passphrases = passphrases
        self.cancel_event = threading.Event()

    @Slot()
    def run(self):
        try:
            result = process_items(
                self.gpg, self.files, self.output, self.operation, self.method, self.fingerprint,
                self.cancel_event,
                lambda index, ok, message, output: self.progress.emit(index, ok, message, output),
                passphrases=self.passphrases,
            )
            self.completed.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.passphrases = []
            self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self, settings: QSettings | None = None, vault_path: Path | None = None):
        super().__init__()
        self.settings = settings or QSettings("mindyourownbytes", "mindyourownbytes")
        self.operation = "encrypt"
        self.items: list[SourceItem] = []
        self._source_paths: list[str] = []
        self.gpg = self._initial_gpg()
        self._thread: QThread | None = None
        self.worker: BackupWorker | None = None
        self.running = False
        self._keys: dict[str, PublicKey] = {}
        self._failures: list[str] = []
        self._job_output: Path | None = None
        self.vault = Vault(self.gpg, vault_path or default_vault_path())

        self.setWindowTitle("mindyourownbytes")
        available = QGuiApplication.primaryScreen().availableGeometry()
        self.resize(min(1100, available.width()), min(760, available.height()))
        self.setStyleSheet(STYLESHEET.read_text(encoding="utf-8"))

        shell = QWidget()
        shell.setObjectName("shell")
        self.setCentralWidget(shell)
        frame = QHBoxLayout(shell)
        frame.setContentsMargins(0, 0, 0, 0)
        frame.setSpacing(0)
        frame.addWidget(self._build_sidebar())

        self.pages = QStackedWidget()
        self.pages.setObjectName("body")
        self.transfer_page = self._build_transfer_page()
        self.library_page = LibraryPage(lambda: self.current_output("encrypt"))
        self.library_page.restore_requested.connect(self._restore_from_library)
        self.vault_page = VaultPage(self.vault)
        self.vault_page.changed.connect(self._on_vault_changed)
        for page in (self.transfer_page, self.library_page, self.vault_page):
            self.pages.addWidget(page)
        frame.addWidget(self.pages, stretch=1)

        self.update_gpg_status()
        self.refresh_keys()
        self.set_operation("encrypt")

    def _initial_gpg(self) -> str:
        """Use a saved path only while it still works, otherwise look again."""
        saved = str(self.settings.value("gpg_path", "") or "")
        if saved and is_valid_gpg(saved):
            return saved
        return find_gpg() or ""

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(236)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(24, 31, 22, 23)
        side.setSpacing(8)
        logo = QLabel("mind your\nown bytes")
        logo.setObjectName("brand")
        side.addWidget(logo)
        brand_sub = QLabel("ENCRYPT BEFORE UPLOAD")
        brand_sub.setObjectName("brandSub")
        side.addWidget(brand_sub)
        side.addSpacing(24)
        nav_label = QLabel("WORKSPACE")
        nav_label.setObjectName("eyebrow")
        side.addWidget(nav_label)
        self.encrypt_nav = action_button("⇪   Encrypt files", "navActive")
        self.restore_nav = action_button("⇩   Restore files", "nav")
        self.library_nav = action_button("▤   Library", "nav")
        self.vault_nav = action_button("⚿   Passphrases", "nav")
        self.encrypt_nav.clicked.connect(lambda: self.set_operation("encrypt"))
        self.restore_nav.clicked.connect(lambda: self.set_operation("restore"))
        self.library_nav.clicked.connect(self.show_library)
        self.vault_nav.clicked.connect(self.show_vault)
        for button in (self.encrypt_nav, self.restore_nav, self.library_nav, self.vault_nav):
            side.addWidget(button)
        side.addStretch(1)

        self.gpg_status = QLabel()
        self.gpg_status.setWordWrap(True)
        self.gpg_status.setObjectName("sidebarInfo")
        side.addWidget(self.gpg_status)
        choose_gpg = action_button("Locate GnuPG", "subtle")
        choose_gpg.clicked.connect(self.select_gpg)
        side.addWidget(choose_gpg)
        side.addSpacing(14)
        foot = QLabel(f"LOCAL ONLY  ·  v{__version__}\nNo accounts. No telemetry.")
        foot.setObjectName("sidebarFoot")
        side.addWidget(foot)
        return sidebar

    def _build_transfer_page(self) -> QWidget:
        body = QWidget()
        main = QVBoxLayout(body)
        main.setContentsMargins(34, 27, 34, 24)
        main.setSpacing(14)

        top = QHBoxLayout()
        heading_col = QVBoxLayout()
        heading_col.setSpacing(5)
        self.heading = QLabel("Encrypt & prepare")
        self.heading.setObjectName("title")
        self.subtitle = QLabel()
        self.subtitle.setObjectName("mutedLabel")
        heading_col.addWidget(self.heading)
        heading_col.addWidget(self.subtitle)
        top.addLayout(heading_col)
        top.addStretch(1)
        badge = QLabel("●  ALPHA · NOT YET AUDITED")
        badge.setObjectName("badge")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top.addWidget(badge)
        main.addLayout(top)

        self.drop = DropZone("Drop files or folders here", "Or click to choose files", self.select_files)
        self.drop.paths_dropped.connect(self.add_paths)
        main.addWidget(self.drop)

        tools = QHBoxLayout()
        tools.setSpacing(8)
        self.add_files_button = action_button("+ Add files")
        self.add_folder_button = action_button("+ Add folder")
        self.remove_button = action_button("Remove selected", "subtle")
        self.clear_button = action_button("Clear", "subtle")
        self.add_files_button.clicked.connect(self.select_files)
        self.add_folder_button.clicked.connect(self.select_folder)
        self.remove_button.clicked.connect(self.remove_selected)
        self.clear_button.clicked.connect(self.clear_files)
        for button in (self.add_files_button, self.add_folder_button, self.remove_button, self.clear_button):
            tools.addWidget(button)
        tools.addStretch(1)
        self.queue_count = QLabel("0 files")
        self.queue_count.setObjectName("mutedLabel")
        tools.addWidget(self.queue_count)
        main.addLayout(tools)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["FILE", "SIZE", "SUBFOLDER", "STATUS"])
        header = self.table.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(90)
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        main.addWidget(self.table, stretch=1)

        main.addWidget(self._build_options_card())

        bottom = QHBoxLayout()
        self.status_text = QLabel("Ready when you are")
        self.status_text.setObjectName("mutedLabel")
        bottom.addWidget(self.status_text, stretch=1)
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(140)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setVisible(False)
        bottom.addWidget(self.progress_bar)
        self.open_button = action_button("Open output", "secondary")
        self.open_button.clicked.connect(self.open_output)
        bottom.addWidget(self.open_button)
        self.cancel_button = action_button("Cancel", "danger")
        self.cancel_button.clicked.connect(self.cancel)
        self.cancel_button.setVisible(False)
        bottom.addWidget(self.cancel_button)
        self.start_button = action_button("Encrypt files  →", "primary")
        self.start_button.clicked.connect(self.start)
        bottom.addWidget(self.start_button)
        main.addLayout(bottom)
        # Scrolls on small screens instead of forcing the window to outgrow them.
        body.setObjectName("body")
        scroll = QScrollArea()
        scroll.setObjectName("pageScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(body)
        return scroll

    def _build_options_card(self) -> QFrame:
        options = QFrame()
        options.setObjectName("optionsCard")
        layout = QVBoxLayout(options)
        layout.setContentsMargins(18, 15, 18, 16)
        layout.setSpacing(10)

        crypto_row = QHBoxLayout()
        crypto_row.setSpacing(10)
        self.method_label = QLabel("ENCRYPTION")
        self.method_label.setObjectName("eyebrow")
        self.method_label.setFixedWidth(82)
        crypto_row.addWidget(self.method_label)
        self.method_combo = QComboBox()
        self.method_combo.setMinimumWidth(280)
        self.method_combo.currentIndexChanged.connect(self._update_method)
        crypto_row.addWidget(self.method_combo)
        self.key_combo = QComboBox()
        self.key_combo.setMinimumWidth(180)
        self.key_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        crypto_row.addWidget(self.key_combo)
        self.refresh_keys_button = action_button("↻", "subtle")
        self.refresh_keys_button.setToolTip("Refresh OpenPGP keys from Kleopatra / GnuPG")
        self.refresh_keys_button.clicked.connect(self.refresh_keys)
        crypto_row.addWidget(self.refresh_keys_button)
        self.saved_combo = QComboBox()
        self.saved_combo.setMinimumWidth(180)
        self.saved_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        crypto_row.addWidget(self.saved_combo)
        self.vault_button = action_button("Unlock saved passphrases", "secondary")
        self.vault_button.clicked.connect(self._open_vault_for_method)
        crypto_row.addWidget(self.vault_button)
        crypto_row.addStretch(1)
        layout.addLayout(crypto_row)

        self.collection_row = QWidget()
        collection_layout = QHBoxLayout(self.collection_row)
        collection_layout.setContentsMargins(0, 0, 0, 0)
        collection_layout.setSpacing(10)
        collection_label = QLabel("COLLECTION")
        collection_label.setObjectName("eyebrow")
        collection_label.setFixedWidth(82)
        collection_layout.addWidget(collection_label)
        self.collection_combo = QComboBox()
        self.collection_combo.setEditable(True)
        self.collection_combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.collection_combo.lineEdit().setPlaceholderText("None. Type a name to create one, e.g. Taxes")
        collection_layout.addWidget(self.collection_combo, stretch=1)
        layout.addWidget(self.collection_row)

        destination_row = QHBoxLayout()
        destination_row.setSpacing(10)
        folder_label = QLabel("OUTPUT")
        folder_label.setObjectName("eyebrow")
        folder_label.setFixedWidth(82)
        destination_row.addWidget(folder_label)
        self.output_edit = QLineEdit()
        self.output_edit.setReadOnly(True)
        destination_row.addWidget(self.output_edit, stretch=1)
        self.browse_button = action_button("Choose folder", "secondary")
        self.browse_button.clicked.connect(self.select_output)
        destination_row.addWidget(self.browse_button)
        layout.addLayout(destination_row)

        self.privacy_note = QLabel()
        self.privacy_note.setObjectName("mutedLabel")
        self.privacy_note.setWordWrap(True)
        layout.addWidget(self.privacy_note)
        return options

    def current_output(self, operation: str | None = None) -> Path:
        operation = operation or self.operation
        base = DEFAULT_ROOT / ("Encrypted Exports" if operation == "encrypt" else "Restored Files")
        return Path(str(self.settings.value(f"output_{operation}", str(base)))).expanduser()

    def _set_active_nav(self, active: QPushButton) -> None:
        for button in (self.encrypt_nav, self.restore_nav, self.library_nav, self.vault_nav):
            button.setProperty("variant", "navActive" if button is active else "nav")
            repolish(button)

    def set_operation(self, operation: str):
        if self.running:
            return
        if self.operation != operation:
            self.items.clear()
            self._source_paths.clear()
        self.operation = operation
        is_encryption = operation == "encrypt"
        self.pages.setCurrentWidget(self.transfer_page)
        self._set_active_nav(self.encrypt_nav if is_encryption else self.restore_nav)
        self.heading.setText("Encrypt & prepare" if is_encryption else "Restore encrypted files")
        self.subtitle.setText(
            "Protect files locally, then upload the .gpg exports anywhere."
            if is_encryption else "Decrypt downloaded .gpg backups into a local folder."
        )
        self.method_label.setText("ENCRYPTION" if is_encryption else "UNLOCK WITH")
        self.method_combo.blockSignals(True)
        self.method_combo.clear()
        for label, data in (ENCRYPT_METHODS if is_encryption else RESTORE_METHODS):
            self.method_combo.addItem(label, data)
        self.method_combo.blockSignals(False)
        self.collection_row.setVisible(is_encryption)
        self._refresh_collections()
        self._refresh_saved_combo()
        self._update_method()
        self.privacy_note.setText(
            "Only encrypted files go to the output folder. Originals are never changed."
            if is_encryption
            else "Restored files are readable. Choose a folder that no cloud service synchronizes."
        )
        self.output_edit.setText(str(self.current_output()))
        self.start_button.setText("Encrypt files  →" if is_encryption else "Restore files  →")
        self.status_text.setText("Ready when you are")
        self.render_queue()

    def show_library(self):
        if self.running:
            return
        self.pages.setCurrentWidget(self.library_page)
        self._set_active_nav(self.library_nav)
        self.library_page.refresh()

    def show_vault(self):
        if self.running:
            return
        self.pages.setCurrentWidget(self.vault_page)
        self._set_active_nav(self.vault_nav)
        self.vault_page.refresh()

    @Slot(list)
    def _restore_from_library(self, items: list[SourceItem]):
        self.set_operation("restore")
        self.items = list(items)
        self._source_paths = []
        self.render_queue()

    def _refresh_collections(self):
        current = self.collection_combo.currentText()
        self.collection_combo.clear()
        self.collection_combo.addItem("")
        for name in list_collections(self.current_output("encrypt")):
            self.collection_combo.addItem(name)
        self.collection_combo.setCurrentText(current)

    def _refresh_saved_combo(self):
        self.saved_combo.clear()
        if not self.vault.unlocked:
            return
        entries = self.vault.entries
        if self.operation == "restore" and len(entries) > 1:
            self.saved_combo.addItem("Try every saved passphrase", TRY_ALL_SAVED)
        for entry in entries:
            self.saved_combo.addItem(entry.label, entry.id)

    @Slot()
    def _on_vault_changed(self):
        self._refresh_saved_combo()
        self._update_method()

    def _update_method(self):
        method = self.method_combo.currentData()
        self.key_combo.setVisible(method == "public-key")
        self.refresh_keys_button.setVisible(method == "public-key")
        saved = method == "saved"
        self.saved_combo.setVisible(saved and self.vault.unlocked)
        self.vault_button.setVisible(saved and not self.vault.unlocked)
        self.vault_button.setText("Unlock saved passphrases" if self.vault.exists else "Set up saved passphrases")

    def _open_vault_for_method(self):
        if self.vault.exists:
            self.vault_page.request_unlock()
        else:
            self.show_vault()

    def update_gpg_status(self):
        minimum = ".".join(map(str, MIN_GPG_VERSION))
        self.gpg_status.setText(
            "●  GnuPG ready\nEncryption engine detected"
            if self.gpg and is_valid_gpg(self.gpg)
            else f"●  GnuPG {minimum}+ not found\nInstall Gpg4win or select gpg.exe"
        )

    def select_gpg(self):
        selected, _ = QFileDialog.getOpenFileName(
            self, "Select GnuPG executable", str(Path.home()),
            "GnuPG executable (gpg.exe gpg);;All files (*)",
        )
        if not selected:
            return
        if not is_valid_gpg(selected):
            QMessageBox.warning(self, "Invalid executable", "This does not appear to be a working, "
                                f"up-to-date GnuPG ({'.'.join(map(str, MIN_GPG_VERSION))} or newer).")
            return
        self.gpg = selected
        self.vault.gpg = selected
        self.settings.setValue("gpg_path", selected)
        self.update_gpg_status()
        self.refresh_keys()

    def refresh_keys(self):
        self.key_combo.clear()
        self._keys = {}
        if not self.gpg or not is_valid_gpg(self.gpg):
            self.key_combo.addItem("GnuPG not found", "")
            return
        try:
            keys = list_public_keys(self.gpg)
        except Exception:
            keys = []
        if not keys:
            self.key_combo.addItem("No encryption keys found", "")
            return
        for key in keys:
            owner = "your key" if key.has_secret else "someone else's key"
            self.key_combo.addItem(f"{key.uid[:48]} · {key.fingerprint[-10:]} · {owner}", key.fingerprint)
            self._keys[key.fingerprint] = key

    def select_files(self):
        if self.running:
            return
        files, _ = QFileDialog.getOpenFileNames(
            self, "Choose files to encrypt" if self.operation == "encrypt" else "Choose encrypted files",
            str(Path.home()),
            "GnuPG files (*.gpg *.pgp);;All files (*)" if self.operation == "restore" else "All files (*)",
        )
        if files:
            self.add_paths(files)

    def select_folder(self):
        if self.running:
            return
        folder = QFileDialog.getExistingDirectory(self, "Choose a folder", str(Path.home()))
        if folder:
            self.add_paths([folder])

    def _warn_unreadable(self, unreadable: tuple[Path, ...]):
        """A backup that quietly leaves files out is the worst failure, so say so."""
        if not unreadable:
            return
        listed = "\n".join(str(path) for path in unreadable[:8])
        more = f"\n…and {len(unreadable) - 8} more" if len(unreadable) > 8 else ""
        QMessageBox.warning(
            self, "Some items could not be read",
            f"These will NOT be included, because Windows or your filesystem refused access:\n\n{listed}{more}",
        )

    def add_paths(self, new_paths: list[str]):
        if self.running or not new_paths:
            return
        if self.items and not self._source_paths:
            # The queue was curated (rows removed, or sent from the Library).
            # Keep it as it is when adding more files.
            try:
                added, skipped, unreadable = collect_files(new_paths, self.current_output(), self.operation)
            except (ValueError, OSError) as exc:
                QMessageBox.warning(self, "Cannot add files", str(exc))
                return
            existing = {item.source for item in self.items}
            self.items.extend(item for item in added if item.source not in existing)
            self.render_queue()
            if skipped:
                self.status_text.setText(f"Skipped {skipped} links, duplicates or unsupported files")
            self._warn_unreadable(unreadable)
            return
        inputs = self._source_paths + [path for path in new_paths if path not in self._source_paths]
        try:
            items, skipped, unreadable = collect_files(inputs, self.current_output(), self.operation)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Cannot add files", str(exc))
            return
        self._source_paths = inputs
        self.items = items
        self.render_queue()
        if skipped:
            self.status_text.setText(
                f"Added {len(items)} files · skipped {skipped} links, duplicates or unsupported files"
            )
        self._warn_unreadable(unreadable)

    def remove_selected(self):
        if self.running:
            return
        rows = {index.row() for index in self.table.selectedIndexes()}
        if not rows:
            return
        # Rebuild the queue as individual selected files; preserve the intended
        # relative folder layout instead of rescanning removed parent folders.
        self.items = [item for i, item in enumerate(self.items) if i not in rows]
        self._source_paths = []
        self.render_queue()

    def clear_files(self):
        if self.running:
            return
        self.items = []
        self._source_paths = []
        self.render_queue()
        self.status_text.setText("Queue cleared")

    def render_queue(self):
        self.table.setRowCount(len(self.items))
        for row, item in enumerate(self.items):
            values = [item.source.name, human_size(item.size),
                      str(item.relative.parent) if str(item.relative.parent) != "." else "—", "Waiting"]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                if column == 0:
                    cell.setToolTip(str(item.source))
                self.table.setItem(row, column, cell)
            self.table.setRowHeight(row, 34)
        self.queue_count.setText(f"{len(self.items)} file{'s' if len(self.items) != 1 else ''}")

    def select_output(self):
        if self.running:
            return
        selected = QFileDialog.getExistingDirectory(self, "Choose output folder", str(self.current_output()))
        if not selected:
            return
        self.settings.setValue(f"output_{self.operation}", selected)
        self.output_edit.setText(selected)
        self._refresh_collections()

    def open_output(self):
        path = self.current_output()
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _confirm(self, title: str, text: str) -> bool:
        answer = QMessageBox.warning(
            self, title, text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _confirm_locations(self, output: Path) -> bool:
        """Warn when the plaintext is, or is about to be, inside a synced folder."""
        if self.operation == "restore":
            provider = looks_cloud_synced(output)
            if provider:
                return self._confirm(
                    "Restoring into a synced folder?",
                    f"This folder appears to be inside “{provider}”, so your decrypted files may be "
                    "uploaded to a cloud service automatically.\n\nContinue anyway?",
                )
            return True
        for item in self.items:
            provider = looks_cloud_synced(item.source)
            if provider:
                return self._confirm(
                    "These originals may already be in the cloud",
                    f"{item.source.name} appears to be inside “{provider}”. If that folder is synced, "
                    "your provider already has this file in readable form. Encrypting a copy does not "
                    "undo that, it only protects what you upload from now on.\n\nContinue anyway?",
                )
        return True

    def _confirm_recipient(self, fingerprint: str) -> bool:
        key = self._keys.get(fingerprint)
        if key is None or key.has_secret:
            return True
        return self._confirm(
            "You won't be able to restore these files",
            f"The private key for “{key.uid}” is not on this computer, so you could not decrypt these "
            "files yourself. Only the key's owner can.\n\nEncrypt to this key anyway?",
        )

    def _passphrases_for(self, method: str) -> list[str] | None:
        """Return the passphrases for this job, or None if the user backed out."""
        if method in ("pinentry", "public-key"):
            return []
        if method == "once":
            encrypting = self.operation == "encrypt"
            dialog = PassphraseDialog(
                self,
                "Passphrase for this batch" if encrypting else "Passphrase for these files",
                "Every file in this batch will use this passphrase. Nobody can recover it for you, "
                "so make sure you can find it again." if encrypting
                else "This passphrase will be tried on every file in the queue.",
                confirm=encrypting, min_length=8 if encrypting else 1,
            )
            return [dialog.passphrase()] if dialog.exec() else None
        if not self.vault.unlocked:
            # Stop after unlocking, so nobody encrypts with whichever saved
            # passphrase happens to be selected without having seen the list.
            if self.vault.exists:
                if self.vault_page.request_unlock():
                    self.status_text.setText("Vault unlocked. Choose a saved passphrase, then start again.")
            else:
                self.show_vault()
            return None
        entries = self.vault.entries
        if not entries:
            QMessageBox.information(self, "No saved passphrases", "Add a passphrase under Passphrases first.")
            self.show_vault()
            return None
        self.vault_page.touch()
        choice = self.saved_combo.currentData()
        if choice == TRY_ALL_SAVED:
            return [entry.passphrase for entry in entries]
        return [entry.passphrase for entry in entries if entry.id == choice] or None

    def _job_directory(self) -> Path | None:
        root = self.current_output()
        name = self.collection_combo.currentText().strip()
        if self.operation != "encrypt" or not name:
            return root
        try:
            return root / validate_collection_name(name)
        except ValueError as exc:
            QMessageBox.warning(self, "Check the collection name", str(exc))
            return None

    def start(self):
        if self.running:
            return
        if not self.items:
            QMessageBox.information(self, "No files selected", "Drag or select files to begin.")
            return
        if not self.gpg or not is_valid_gpg(self.gpg):
            QMessageBox.warning(
                self, "GnuPG is required",
                "Install Gpg4win (https://gpg4win.org/) and restart this application, "
                "or click 'Locate GnuPG' and select gpg.exe.",
            )
            return
        selection = str(self.method_combo.currentData())
        method = "public-key" if selection == "public-key" else "password"
        fingerprint = str(self.key_combo.currentData() or "") if selection == "public-key" else None
        if selection == "public-key" and not fingerprint:
            QMessageBox.warning(self, "No encryption key", "Create an OpenPGP key in Kleopatra, then refresh the list.")
            return
        output = self._job_directory()
        if output is None or not self._confirm_locations(output):
            return
        if fingerprint and not self._confirm_recipient(fingerprint):
            return
        passphrases = self._passphrases_for(selection)
        if passphrases is None:
            return
        try:
            # Restored plaintext gets a private folder on systems that honor modes.
            output.mkdir(parents=True, exist_ok=True, mode=0o700 if self.operation == "restore" else 0o777)
            if self._source_paths:
                self.items, _, unreadable = collect_files(self._source_paths, output, self.operation)
                self._warn_unreadable(unreadable)
            else:
                # A curated queue: re-check the files before relying on them.
                for item in self.items:
                    if not item.source.is_file() or item.source.is_symlink():
                        raise ValueError(f"A source file is unavailable: {item.source}")
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Cannot start", str(exc))
            return
        self.render_queue()
        self.running = True
        self._failures = []
        self._job_output = output
        self._set_busy(True)
        self.progress_bar.setRange(0, len(self.items))
        self.progress_bar.setValue(0)
        self.status_text.setText(
            "Working locally… GnuPG will ask when it needs a passphrase"
            if selection == "pinentry" else "Working locally…"
        )

        self._thread = QThread(self)
        self.worker = BackupWorker(self.gpg, list(self.items), output, self.operation, method,
                                   fingerprint, passphrases)
        self.worker.moveToThread(self._thread)
        self._thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._progress)
        self.worker.completed.connect(self._completed)
        self.worker.error.connect(self._error)
        self.worker.finished.connect(self._thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self._thread.finished.connect(self._thread.deleteLater)
        self._thread.finished.connect(self._forget_worker)
        self._thread.start()

    @Slot()
    def _forget_worker(self):
        self._thread = None
        self.worker = None

    def _set_busy(self, is_busy: bool):
        for widget in (self.encrypt_nav, self.restore_nav, self.library_nav, self.vault_nav,
                       self.add_files_button, self.add_folder_button, self.remove_button,
                       self.clear_button, self.browse_button, self.method_combo, self.key_combo,
                       self.saved_combo, self.collection_combo, self.refresh_keys_button,
                       self.vault_button, self.start_button):
            widget.setEnabled(not is_busy)
        self.cancel_button.setEnabled(is_busy)
        self.cancel_button.setVisible(is_busy)
        self.progress_bar.setVisible(is_busy)

    @Slot(int, bool, str, object)
    def _progress(self, index: int, ok: bool, message: str, output):
        cancelled = not ok and message == "Cancelled"
        if index < self.table.rowCount():
            cell = self.table.item(index, 3)
            cell.setText("✓ Ready" if ok else "Cancelled" if cancelled else "✕ Error")
            cell.setToolTip(str(output) if ok else message)
            cell.setForeground(QBrush(QColor("#71e3ba" if ok else "#9aaec6" if cancelled else "#ff9d97")))
        self.progress_bar.setValue(index + 1)
        if not ok and not cancelled:
            name = self.items[index].source.name if index < len(self.items) else f"File {index + 1}"
            self._failures.append(f"{name}: {message}")
            self.status_text.setText(f"{name}: {message[:110]}")

    @Slot(object)
    def _completed(self, result: JobResult):
        self.running = False
        self._set_busy(False)
        self._refresh_collections()
        self.status_text.setText(
            f"{result.succeeded} ready · {result.failed} errors" + (" · cancelled" if result.cancelled else "")
        )
        if result.leftovers:
            listed = "\n".join(str(path) for path in result.leftovers[:8])
            QMessageBox.warning(
                self, "Temporary files were left behind",
                "These temporary files could not be removed. After a restore they contain readable data, "
                f"so please delete them yourself:\n\n{listed}",
            )
        if result.failed:
            listed = "\n".join(self._failures[:8])
            more = f"\n…and {len(self._failures) - 8} more" if len(self._failures) > 8 else ""
            QMessageBox.warning(
                self, "Some files failed",
                f"{result.succeeded} succeeded and {result.failed} failed:\n\n{listed}{more}",
            )
        elif result.succeeded:
            QMessageBox.information(
                self, "Finished",
                f"{result.succeeded} file(s) prepared in:\n{self._job_output}\n\n"
                + ("Upload only the .gpg files to your cloud storage."
                   if self.operation == "encrypt" else "The restored files are readable, local copies."),
            )

    @Slot(str)
    def _error(self, message: str):
        self.running = False
        self._set_busy(False)
        self.status_text.setText("Operation failed")
        QMessageBox.critical(self, "Operation failed", message)

    def cancel(self):
        if self.worker and self.running:
            self.worker.cancel_event.set()
            self.cancel_button.setEnabled(False)
            self.status_text.setText("Cancelling safely after GnuPG stops...")

    def closeEvent(self, event):
        if self.running:
            QMessageBox.warning(
                self, "Operation in progress", "Cancel the operation and wait for it to stop before closing."
            )
            event.ignore()
            return
        if self._thread is not None:
            self._thread.wait(3000)
        self.vault_page.clipboard.clear()
        self.vault.lock()
        event.accept()


def _show_unexpected_error(exc_type, exc, tb) -> None:
    """pythonw has no console, so without this any crash would just vanish."""
    if sys.stderr:
        traceback.print_exception(exc_type, exc, tb)
    QMessageBox.critical(
        None, "Unexpected error",
        f"{exc_type.__name__}: {exc}\n\nPlease report this on GitHub, without including any private data.",
    )


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("mindyourownbytes")
    app.setOrganizationName("mindyourownbytes")
    app.setFont(QFont("Segoe UI", 10))
    sys.excepthook = _show_unexpected_error
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
