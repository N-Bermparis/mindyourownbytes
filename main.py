"""mindyourownbytes: a local-only, drag-and-drop GnuPG desktop utility."""

from __future__ import annotations

import sys
import threading
from pathlib import Path

from PySide6.QtCore import QObject, QSettings, Qt, QThread, QUrl, Signal, Slot
from PySide6.QtGui import QBrush, QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QProgressBar, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QHeaderView,
    QAbstractItemView, QSizePolicy,
)

from backup_core import (
    JobResult, SourceItem, collect_files, find_gpg, is_valid_gpg,
    list_public_keys, process_items,
)


APP_VERSION = "0.1.0-alpha.1"
APP_DIR = Path(__file__).resolve().parent
DEFAULT_ROOT = Path.home() / "mindyourownbytes"


def human_size(size: int) -> str:
    count = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if count < 1024 or unit == "TB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1024
    return "0 B"


def action_button(text: str, variant: str = "secondary") -> QPushButton:
    button = QPushButton(text)
    button.setProperty("variant", variant)
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    button.setMinimumHeight(38)
    return button


class DropZone(QFrame):
    paths_dropped = Signal(list)

    def __init__(self, title: str, subtitle: str, on_click) -> None:
        super().__init__()
        self._on_click = on_click
        self.setObjectName("dropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(144)
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

    def __init__(self, gpg: str, files: list[SourceItem], output: Path,
                 operation: str, method: str, fingerprint: str | None):
        super().__init__()
        self.gpg = gpg
        self.files = files
        self.output = output
        self.operation = operation
        self.method = method
        self.fingerprint = fingerprint
        self.cancel_event = threading.Event()

    @Slot()
    def run(self):
        try:
            result = process_items(
                self.gpg, self.files, self.output, self.operation,
                self.method, self.fingerprint, self.cancel_event,
                lambda index, ok, message, output: self.progress.emit(index, ok, message, output),
            )
            self.completed.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))
        finally:
            self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("mindyourownbytes", "mindyourownbytes")
        self.operation = "encrypt"
        self.items: list[SourceItem] = []
        self._source_paths: list[str] = []
        self.gpg = str(self.settings.value("gpg_path", find_gpg() or ""))
        self.thread: QThread | None = None
        self.worker: BackupWorker | None = None
        self.running = False

        self.setWindowTitle("mindyourownbytes")
        self.setMinimumSize(870, 660)
        self.resize(1060, 755)
        self.setStyleSheet((APP_DIR / "styles.qss").read_text(encoding="utf-8"))

        shell = QWidget()
        shell.setObjectName("shell")
        self.setCentralWidget(shell)
        frame = QHBoxLayout(shell)
        frame.setContentsMargins(0, 0, 0, 0)
        frame.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(236)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(24, 31, 22, 23)
        side.setSpacing(14)
        logo = QLabel("◇  MYOB")
        logo.setObjectName("brand")
        side.addWidget(logo)
        brand_sub = QLabel("SECURE BACKUP")
        brand_sub.setObjectName("brandSub")
        side.addWidget(brand_sub)
        side.addSpacing(38)
        nav_label = QLabel("WORKSPACE")
        nav_label.setObjectName("eyebrow")
        side.addWidget(nav_label)
        self.encrypt_nav = action_button("⇪   Encrypt files", "navActive")
        self.restore_nav = action_button("⇩   Restore files", "nav")
        self.encrypt_nav.clicked.connect(lambda: self.set_operation("encrypt"))
        self.restore_nav.clicked.connect(lambda: self.set_operation("restore"))
        side.addWidget(self.encrypt_nav)
        side.addWidget(self.restore_nav)
        side.addStretch(1)

        self.gpg_status = QLabel()
        self.gpg_status.setWordWrap(True)
        self.gpg_status.setObjectName("sidebarInfo")
        side.addWidget(self.gpg_status)
        choose_gpg = action_button("Locate GnuPG", "subtle")
        choose_gpg.clicked.connect(self.select_gpg)
        side.addWidget(choose_gpg)
        side.addSpacing(14)
        foot = QLabel(f"LOCAL ONLY  ·  v{APP_VERSION}\nNo accounts. No telemetry.")
        foot.setObjectName("sidebarFoot")
        side.addWidget(foot)
        frame.addWidget(sidebar)

        body = QWidget()
        body.setObjectName("body")
        main = QVBoxLayout(body)
        main.setContentsMargins(34, 27, 34, 24)
        main.setSpacing(16)

        top = QHBoxLayout()
        heading_col = QVBoxLayout()
        heading_col.setSpacing(5)
        self.heading = QLabel("Encrypt & prepare")
        self.heading.setObjectName("title")
        self.subtitle = QLabel("Protect files locally, then upload the .gpg exports anywhere.")
        self.subtitle.setObjectName("mutedLabel")
        heading_col.addWidget(self.heading)
        heading_col.addWidget(self.subtitle)
        top.addLayout(heading_col)
        top.addStretch(1)
        badge = QLabel("●  OFFLINE-FIRST")
        badge.setObjectName("badge")
        badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        top.addWidget(badge)
        main.addLayout(top)

        self.drop = DropZone(
            "Drop files or folders here",
            "Choose files, or drag multiple items from Windows Explorer",
            self.select_files,
        )
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
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setMinimumHeight(175)
        self.table.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        main.addWidget(self.table, stretch=1)

        options = QFrame()
        options.setObjectName("optionsCard")
        options_layout = QVBoxLayout(options)
        options_layout.setContentsMargins(18, 15, 18, 16)
        options_layout.setSpacing(10)

        self.crypto_row = QWidget()
        crypto_layout = QHBoxLayout(self.crypto_row)
        crypto_layout.setContentsMargins(0, 0, 0, 0)
        crypto_layout.setSpacing(10)
        method_label = QLabel("ENCRYPTION")
        method_label.setObjectName("eyebrow")
        crypto_layout.addWidget(method_label)
        self.method_combo = QComboBox()
        self.method_combo.addItem("Password · AES-256", "password")
        self.method_combo.addItem("OpenPGP public key", "public-key")
        self.method_combo.currentIndexChanged.connect(self._update_method)
        crypto_layout.addWidget(self.method_combo)
        self.key_combo = QComboBox()
        self.key_combo.setMinimumWidth(180)
        self.key_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        crypto_layout.addWidget(self.key_combo)
        self.refresh_keys_button = action_button("↻", "subtle")
        self.refresh_keys_button.setToolTip("Refresh OpenPGP keys from Kleopatra / GnuPG")
        self.refresh_keys_button.clicked.connect(self.refresh_keys)
        crypto_layout.addWidget(self.refresh_keys_button)
        options_layout.addWidget(self.crypto_row)

        destination_row = QHBoxLayout()
        folder_label = QLabel("OUTPUT")
        folder_label.setObjectName("eyebrow")
        destination_row.addWidget(folder_label)
        self.output_edit = QLineEdit()
        self.output_edit.setReadOnly(True)
        destination_row.addWidget(self.output_edit, stretch=1)
        self.browse_button = action_button("Choose folder", "secondary")
        self.browse_button.clicked.connect(self.select_output)
        destination_row.addWidget(self.browse_button)
        options_layout.addLayout(destination_row)
        self.privacy_note = QLabel(
            "Only encrypted files go to the export folder. Originals are never modified."
        )
        self.privacy_note.setObjectName("mutedLabel")
        options_layout.addWidget(self.privacy_note)
        main.addWidget(options)

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
        frame.addWidget(body, stretch=1)

        self.update_gpg_status()
        self.refresh_keys()
        self._update_method()
        self.set_operation("encrypt")

    def current_output(self) -> Path:
        setting_name = f"output_{self.operation}"
        base = DEFAULT_ROOT / ("Encrypted Exports" if self.operation == "encrypt" else "Restored Files")
        return Path(str(self.settings.value(setting_name, str(base)))).expanduser()

    def set_operation(self, operation: str):
        if self.running:
            return
        if self.operation != operation:
            self.items.clear()
            self._source_paths.clear()
        self.operation = operation
        is_encryption = operation == "encrypt"
        self.encrypt_nav.setProperty("variant", "navActive" if is_encryption else "nav")
        self.restore_nav.setProperty("variant", "nav" if is_encryption else "navActive")
        for button in (self.encrypt_nav, self.restore_nav):
            button.style().unpolish(button)
            button.style().polish(button)
        self.heading.setText("Encrypt & prepare" if is_encryption else "Restore encrypted files")
        self.subtitle.setText(
            "Protect files locally, then upload the .gpg exports anywhere."
            if is_encryption else "Decrypt downloaded .gpg backups into your local restore folder."
        )
        self.crypto_row.setVisible(is_encryption)
        self.privacy_note.setText(
            "Only encrypted files go to the export folder. Originals are never modified."
            if is_encryption else "Restored plaintext stays in your chosen local folder. Never choose a cloud-synced folder."
        )
        self.output_edit.setText(str(self.current_output()))
        self.start_button.setText("Encrypt files  →" if is_encryption else "Restore files  →")
        self.status_text.setText("Ready when you are")
        self.render_queue()

    def _update_method(self):
        is_key = self.method_combo.currentData() == "public-key"
        self.key_combo.setVisible(is_key)
        self.refresh_keys_button.setVisible(is_key)

    def update_gpg_status(self):
        self.gpg_status.setText(
            "●  GnuPG ready\nEncryption engine detected"
            if self.gpg and is_valid_gpg(self.gpg)
            else "●  GnuPG not found\nInstall Gpg4win or select gpg.exe"
        )

    def select_gpg(self):
        selected, _ = QFileDialog.getOpenFileName(
            self, "Select GnuPG executable", str(Path.home()),
            "GnuPG executable (gpg.exe gpg);;All files (*)",
        )
        if not selected:
            return
        if not is_valid_gpg(selected):
            QMessageBox.warning(self, "Invalid executable", "This does not appear to be a working GnuPG executable.")
            return
        self.gpg = selected
        self.settings.setValue("gpg_path", selected)
        self.update_gpg_status()
        self.refresh_keys()

    def refresh_keys(self):
        self.key_combo.clear()
        if not self.gpg or not is_valid_gpg(self.gpg):
            self.key_combo.addItem("GnuPG not found", "")
            return
        try:
            keys = list_public_keys(self.gpg)
        except Exception:
            keys = []
        if not keys:
            self.key_combo.addItem("No encryption keys found", "")
        else:
            for fingerprint, uid in keys:
                self.key_combo.addItem(f"{uid[:52]} · {fingerprint[-10:]}", fingerprint)

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

    def add_paths(self, new_paths: list[str]):
        if self.running:
            return
        if not new_paths:
            return
        if self.items and not self._source_paths:
            # The user removed individual rows from a previously expanded
            # folder. Preserve the curated queue when adding more files.
            try:
                added, skipped = collect_files(new_paths, self.current_output(), self.operation)
            except (ValueError, OSError) as exc:
                QMessageBox.warning(self, "Cannot add files", str(exc))
                return
            existing = {item.source for item in self.items}
            self.items.extend(item for item in added if item.source not in existing)
            self.render_queue()
            if skipped:
                self.status_text.setText(f"Skipped {skipped} links, duplicates or unsupported files")
            return
        inputs = self._source_paths + [p for p in new_paths if p not in self._source_paths]
        try:
            items, skipped = collect_files(inputs, self.current_output(), self.operation)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Cannot add files", str(exc))
            return
        self._source_paths = inputs
        self.items = items
        self.render_queue()
        if skipped:
            self.status_text.setText(f"Added {len(items)} files · skipped {skipped} links, duplicates or unsupported files")

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
        if self._source_paths:
            self.add_paths([])

    def open_output(self):
        path = self.current_output()
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _warn_sync_path(self, folder: Path) -> bool:
        if self.operation != "restore":
            return True
        suspicious = {"onedrive", "google drive", "dropbox", "icloud drive", "sync"}
        if not any(any(token in part.lower() for token in suspicious) for part in folder.parts):
            return True
        response = QMessageBox.warning(
            self, "Possible cloud-synced restore folder",
            "This folder may synchronize your decrypted plaintext to a cloud service. "
            "Choose a local-only folder if confidentiality matters.\n\nContinue anyway?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return response == QMessageBox.StandardButton.Yes

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
        method = str(self.method_combo.currentData())
        fingerprint = str(self.key_combo.currentData() or "") if method == "public-key" else None
        if self.operation == "encrypt" and method == "public-key" and not fingerprint:
            QMessageBox.warning(self, "No encryption key", "Create an OpenPGP key in Kleopatra, then refresh the list.")
            return
        output = self.current_output()
        if not self._warn_sync_path(output):
            return
        try:
            output.mkdir(parents=True, exist_ok=True)
            if self._source_paths:
                self.items, _ = collect_files(self._source_paths, output, self.operation)
            else:
                # Items came from the remove-selection operation. Re-check them.
                for item in self.items:
                    if not item.source.is_file() or item.source.is_symlink():
                        raise ValueError(f"A source file is unavailable: {item.source}")
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Cannot start", str(exc))
            return
        self.render_queue()
        self.running = True
        self._set_busy(True)
        self.progress_bar.setRange(0, len(self.items))
        self.progress_bar.setValue(0)
        self.status_text.setText("Working locally... GnuPG may ask for a passphrase")

        self.thread = QThread(self)
        self.worker = BackupWorker(self.gpg, list(self.items), output,
                                   self.operation, method, fingerprint)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._progress)
        self.worker.completed.connect(self._completed)
        self.worker.error.connect(self._error)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()

    def _set_busy(self, is_busy: bool):
        for button in (self.encrypt_nav, self.restore_nav, self.add_files_button,
                       self.add_folder_button, self.remove_button, self.clear_button,
                       self.browse_button, self.method_combo, self.key_combo,
                       self.refresh_keys_button, self.start_button):
            button.setEnabled(not is_busy)
        self.cancel_button.setVisible(is_busy)
        self.progress_bar.setVisible(is_busy)

    @Slot(int, bool, str, object)
    def _progress(self, index: int, ok: bool, message: str, output):
        if index < self.table.rowCount():
            cell = self.table.item(index, 3)
            cell.setText("✓ Ready" if ok else "✕ Error")
            cell.setToolTip(str(output) if ok else message)
            cell.setForeground(QBrush(QColor("#71e3ba" if ok else "#ff9d97")))
        self.progress_bar.setValue(index + 1)
        if not ok:
            self.status_text.setText(f"File {index+1}: {message[:130]}")

    @Slot(object)
    def _completed(self, result: JobResult):
        self.running = False
        self._set_busy(False)
        self.status_text.setText(
            f"{result.succeeded} ready · {result.failed} errors" +
            (" · cancelled" if result.cancelled else "")
        )
        if result.succeeded:
            QMessageBox.information(
                self, "Finished",
                f"{result.succeeded} file(s) prepared in:\n{self.current_output()}\n\n"
                + ("Upload only the .gpg files to your cloud storage."
                   if self.operation == "encrypt" else "The restored files are local plaintext."),
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
            QMessageBox.warning(self, "Operation in progress", "Cancel the operation and wait for it to stop before closing.")
            event.ignore()
            return
        event.accept()


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("mindyourownbytes")
    app.setOrganizationName("mindyourownbytes")
    app.setFont(QFont("Segoe UI", 10))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
