"""Main window: navigation, menus, the encrypt and restore screen, and the background job."""

from __future__ import annotations

import ctypes
import itertools
import re
import sys
import threading
import traceback
from dataclasses import replace
from datetime import date
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QSettings, QSize, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QActionGroup, QBrush, QDesktopServices, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes import __version__, archive, records, safefs, signatures, strength, workspace
from mindyourownbytes.core import (
    CHECKED,
    CIPHERS,
    DEFAULT_CIPHER,
    ENCRYPTED_SUFFIXES,
    MIN_GPG_VERSION,
    UNPACKED,
    Cancelled,
    JobResult,
    PublicKey,
    SourceItem,
    available_ciphers,
    bundled_gpg,
    collect_files,
    encrypt_archive,
    find_gpg,
    find_kleopatra,
    gpg_version,
    is_valid_gpg,
    list_public_keys,
    list_signing_keys,
    looks_cloud_synced,
    peek_protection,
    process_items,
    stop_bundled_gnupg,
)
from mindyourownbytes.gui import gnupg_help, handover, icons, provider_view, theme
from mindyourownbytes.gui.dialogs import PassphraseDialog, ProtectionDialog
from mindyourownbytes.gui.library_page import LibraryPage
from mindyourownbytes.gui.post_quantum import PostQuantumDialog
from mindyourownbytes.gui.recovery_guide import RecoveryGuide
from mindyourownbytes.gui.vault_page import VaultPage
from mindyourownbytes.gui.widgets import (
    EmptyState,
    FileIcons,
    InfoBar,
    SteadyComboBox,
    action_button,
    card,
    configure_table,
    human_size,
    label,
    plural,
    refresh_icons,
    repolish,
    set_icon,
    step_heading,
)
from mindyourownbytes.library import list_collections, validate_collection_name
from mindyourownbytes.records import Finding, Ledger
from mindyourownbytes.vault import Vault, default_vault_path

DEFAULT_ROOT = Path.home() / "mindyourownbytes"
REPOSITORY_URL = "https://github.com/N-Bermparis/mindyourownbytes"
TRY_ALL_SAVED = "\0all"

CIPHER_LABELS = {cipher.name: cipher.label for cipher in CIPHERS}
#: Added to the passphrase's help when the Restore list mixes passphrase files with files for a key.
MIXED_HELP = {
    "one": " One of them is for your key, so it's opened with the key instead, and GnuPG asks for the key's "
           "passphrase if it has one.",
    "many": " {count} of them are for your key, so those are opened with the key instead, and GnuPG asks for "
            "the key's passphrase if it has one.",
}
#: What to say beside each encryption algorithm, because the choice has a real cost.
CIPHER_HELP = {
    "AES256": "The usual choice. Almost every OpenPGP tool can open it.",
    "TWOFISH": "Also very strong. GnuPG opens it, but not every OpenPGP tool can.",
    "CAMELLIA256": "Also very strong. GnuPG opens it, but some other OpenPGP tools can't.",
}
CIPHER_SET_BY_KEY = "The key you choose decides this. Its type is in the list above."

#: Every word that differs between the two modes of this screen.
COPY = {
    "encrypt": {
        "title": "Encrypt files",
        "subtitle": "Protect files on this computer, then upload the encrypted copies anywhere.",
        "files_step": "Choose files",
        "empty_title": "Drop files or folders here",
        "empty_body": "Your originals stay exactly as they are.",
        "method_step": "Choose how to protect them",
        "passphrase_help": "Type one passphrase for all these files. You'll need it to restore them.",
        "saved_help": "Use one from your Passphrases list.",
        "key_title": "OpenPGP key",
        "key_help": "Encrypt to a key from Kleopatra, so there's no passphrase to type.",
        "save_step": "Choose where to save them",
        "save_note": "Upload what lands in this folder. Your cloud provider can see file and collection names.",
        "add_title": "Choose files to encrypt",
        "start": "Encrypt {files}",
        "start_empty": "Encrypt files",
        "working": "Encrypting {done} of {total}…",
        "row_done": "Encrypted",
        "row_working": "Encrypting…",
        "result_title": "{files} encrypted",
        "result_detail": "Upload only the .gpg files in this folder to your cloud.",
    },
    "restore": {
        "title": "Restore files",
        "subtitle": "Turn encrypted .gpg files back into normal files on this computer.",
        "files_step": "Choose encrypted files",
        "empty_title": "Drop .gpg files here",
        "empty_body": "Or pick them from your Library.",
        "method_step": "Choose how to unlock them",
        "passphrase_help": "Type it once, and it's tried on all these files.",
        "saved_help": "Try the ones in your Passphrases list.",
        "key_title": "My OpenPGP key",
        "key_help": "For files encrypted to your key. GnuPG asks for the key's passphrase if it has one.",
        "save_step": "Choose where to save them",
        "save_note": "Restored files are readable, so choose a folder that no cloud service syncs.",
        "add_title": "Choose encrypted files",
        "start": "Restore {files}",
        "start_empty": "Restore files",
        "working": "Restoring {done} of {total}…",
        "row_done": "Restored",
        "row_working": "Restoring…",
        "result_title": "{files} restored",
        "result_detail": "These are readable copies on this computer, so don't keep them in a synced folder.",
    },
}

#: What the screen says about checking each new file. Only encrypting has this step.
CHECK_COPY = {
    "working": "Checking {done} of {total}…",
    "row_working": "Checking…",
    "row_done": "Encrypted and checked",
    "row_tip": "Decrypted again, and it matched the original.",
    "row_skipped": "Encrypted, not checked",
    "result_one": "It was decrypted again and matched the original.",
    "result_many": "Each one was decrypted again and matched its original.",
}
#: What a restored file's row adds, from comparing the download with the checksums saved here.
RECORD_WORDS = {
    "match": "matches your record",
    "older": "but it's an older copy",
    "renamed": "but it was renamed or swapped",
    "changed": "but not the copy you made",
    "match_where": "matches {where}",
    "all_match": "Each one matches the checksum saved when it was made.",
}
#: What restoring says about downloads that aren't the files made here, before any is decrypted.
DOUBTFUL_COPY = {
    "starting": "Comparing with your saved checksums…",
    "working": "Comparing {done} of {total} with your saved checksums…",
    "one_title": "Restore a file that isn't the copy you made?",
    "many_title": "Restore {count} files that aren't the copies you made?",
    "one": "{name}: {reason}\n\nIt hasn't been decrypted. Restore it anyway?",
    "many": "None of these has been decrypted:\n\n{listed}\n\nRestore them anyway?",
    "rest_one": " If not, it's left out, and the other files are still restored.",
    "rest_many": " If not, they're left out, and the other files are still restored.",
    "rest_none": " If not, nothing is restored.",
    "row": "Not restored, {reason}",
    "result_title": "{files} restored, {count} left out",
    "result_none": "Nothing was restored",
    "result_one": "The file left out isn't the copy you made, so it wasn't decrypted. The Status column says why.",
    "result_many": "The files left out aren't the copies you made, so they weren't decrypted. The Status "
                   "column says why.",
}
#: How the worker reports a download that was left out, because it isn't the file made here.
LEFT_OUT = "Left out"
#: Added to a row's tooltip when its file was signed as well as encrypted.
SIGNED_NOTE = "Signed with your key {key}, so restoring it can show that you made it."
#: How a finished restore sums up who made the files, by what their signatures showed.
SIGNATURE_SUMMARY = {
    "verified": "signed by a key you've verified",
    "unverified": "signed with a key you haven't verified",
    "revoked": "signed with a revoked key",
    "expired": "signed with a key that has expired",
    "unsigned": "not signed",
}
#: What restoring does with a file that decrypted with your key, but that no key you've verified signed.
#: Anyone with your public key could have made one, and a file you encrypted without signing looks the same.
SIGNATURE_POLICIES = {
    "ask": "&Ask before restoring them",
    "refuse": "&Never restore them",
    "allow": "&Restore them, and say so",
}
#: What restoring says about such files while it waits for someone to decide.
HELD_COPY = {
    "row": "Not restored yet, {why}",
    "row_tip": "{explanation}\n\nIt was decrypted, then deleted again. Choose Restore anyway below the list to "
               "restore it.",
    "title_one": "1 file wasn't restored: nothing shows who made it",
    "title_many": "{count} files weren't restored: nothing shows who made them",
    "detail_one": "No key you've verified signed it, so anyone who has your public key could have made it. A file "
                  "you encrypted without signing looks the same. Restore it only if you know where it came from.",
    "detail_many": "No key you've verified signed them, so anyone who has your public key could have made them. "
                   "Files you encrypted without signing look the same. Restore them only if you know where they "
                   "came from.",
    "action": "Restore anyway…",
    "confirm_one": "Restore this file anyway?",
    "confirm_many": "Restore these {count} files anyway?",
    "text_one": "{listed}\n\nAnyone who has your public key could have made it, so restore it only if you know where "
                "it came from. It's decrypted again, and restored only if it still shows exactly this.",
    "text_many": "{listed}\n\nAnyone who has your public key could have made them, so restore them only if you know "
                 "where they came from. They're decrypted again, and each is restored only if it still shows "
                 "exactly this.",
    "hint": "To restore files like these without asking, choose “Restore them, and say so” under Files for your key "
            "with no verified signature, in the Tools menu.",
    "hint_simple": "To restore files like these without asking, turn on Show advanced options in the Tools menu, "
                   "then choose “Restore them, and say so” under Files for your key with no verified signature.",
    "row_listed": "• {name}: {why}",
    "key": "{why}, {key}",
    "status": " · {count} not restored yet",
}
#: What restoring says about a destination that looks synced, where readable files would be uploaded.
SYNCED_COPY = {
    "refused_title": "Choose a folder that isn't synced",
    "refused": "This folder appears to be inside “{provider}”, so your restored files, which anyone can read, would "
               "be uploaded to a cloud service.\n\nNothing was restored. Under Save to, choose a folder that no "
               "cloud service syncs, such as {suggestion}.",
    "confirm_title": "Restoring into a synced folder?",
    "confirm": "This folder appears to be inside “{provider}”, so your decrypted files may be uploaded to a cloud "
               "service automatically.\n\nContinue anyway?",
}
#: What a finished restore says when it couldn't delete where it kept decrypted data.
LEFTOVER_COPY = (
    "These hidden folders hold readable data from this restore, and couldn't be deleted. The app offers to delete "
    "them again the next time it starts, or you can delete them yourself:\n\n{listed}"
)
#: What the screen says when every file goes into one archive.
ARCHIVE_COPY = {
    "help": "Hides the names of the files and folders inside. Your provider sees one file and its size. "
            "To change one file later, you encrypt the whole archive again.",
    "save_note": "Upload the one .zip.gpg file this makes. Your provider can see its name and size, "
                 "but not the names inside.",
    "working": "Packing {done} of {total}…",
    "row_working": "Adding to the archive…",
    "checking": "Checking the archive…",
    "row_done": "In the archive",
    "row_checked": "In the archive, checked",
    "row_tip": "The archive was decrypted again, and matched what was packed.",
    "row_skipped": "In the archive, not checked",
    "result_title": "{files} encrypted into one archive",
    "result_checked": "It was decrypted again and matched what was packed.",
    "result_detail": "Upload only {name}. Your provider can't see the names of the files inside.",
    "renamed": "In the archive it's {name}, because another file or folder there already had that name.",
}
#: What a restored archive's row says, since it became a folder rather than one file.
UNPACKED_ROW = "Restored and unpacked"

#: Why a file wasn't checked although checking is on, by how it was protected.
NOT_CHECKED = {
    "pinentry": "Not checked, because GnuPG asked for the passphrase itself, and checking would mean "
                "asking again for every file.",
    "public-key": "Not checked, because that takes the private key, and GnuPG might ask for its passphrase.",
}


class DropArea(QWidget):
    """Accepts files dropped anywhere on it, and reports while they're being dragged."""

    paths_dropped = Signal(list)
    hover_changed = Signal(bool)

    def __init__(self) -> None:
        super().__init__()
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        mime = event.mimeData()
        if mime.hasUrls() and all(url.isLocalFile() for url in mime.urls()):
            event.acceptProposedAction()
            self.hover_changed.emit(True)
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dragLeaveEvent(self, event):
        self.hover_changed.emit(False)

    def dropEvent(self, event):
        self.hover_changed.emit(False)
        paths = [url.toLocalFile() for url in event.mimeData().urls() if url.isLocalFile()]
        if paths:
            self.paths_dropped.emit(paths)
            event.acceptProposedAction()


class DropZone(QFrame):
    """The empty state of the file list. Clicking anywhere opens the file picker."""

    def __init__(self, on_click) -> None:
        super().__init__()
        self._on_click = on_click
        self.setObjectName("dropZone")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(150)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(event.position().toPoint()):
            self._on_click()
        super().mouseReleaseEvent(event)


class BackupWorker(QObject):
    progress = Signal(int, bool, str, object)
    #: The file at this position is encrypted, and is now being checked. -1 means the whole archive.
    checking = Signal(int)
    #: What the record says about the downloaded file at this position, as a records.Finding.
    found = Signal(int, object)
    #: Something worth saying that doesn't change the result, such as a record that couldn't be saved.
    note = Signal(str)
    #: The download at this position is being compared with the record. -1 means that's done for all of
    #: them, and decrypting starts.
    comparing = Signal(int)
    #: These downloads, by position, aren't the files made here. Nothing is decrypted until ``decide``.
    doubtful = Signal(object)
    #: The file at this position is going into the archive.
    packing = Signal(int)
    #: What the file at this position showed about who made it, as a signatures.Verification: a file that
    #: was restored, or one held back because no key you've verified signed it.
    verified = Signal(int, object)
    completed = Signal(object)
    error = Signal(str)
    finished = Signal()

    def __init__(self, gpg: str, files: list[SourceItem], output: Path, operation: str,
                 method: str, fingerprint: str | None, passphrases: list[str], cipher: str, verify: bool,
                 archive_name: str | None = None, ledger: Ledger | None = None, keep_records: bool = False,
                 records_root: Path | None = None, sign_with: str | None = None,
                 journal: workspace.Journal | None = None, require_signature: bool = False,
                 accepted: dict[int, signatures.Verification] | None = None):
        super().__init__()
        self.gpg = gpg
        self.files = files
        self.output = output
        self.operation = operation
        self.method = method
        self.fingerprint = fingerprint
        self.passphrases = passphrases
        self.cipher = cipher
        self.verify = verify
        #: Each file encrypted to a key is signed with this one, if given.
        self.sign_with = sign_with
        #: Notes where decrypted data waits during a restore, until it's gone.
        self.journal = journal
        #: Hold back files for a key that a key you've verified didn't sign.
        self.require_signature = require_signature
        #: Files, by position, that someone agreed to restore anyway, and what they were shown about each.
        #: Each is restored only if it shows exactly that again.
        self.accepted = dict(accepted or {})
        #: Which of ``files`` are being processed, once compared with the record.
        self._keep: list[int] = []
        #: Every file goes into one archive with this name, rather than into a .gpg file of its own.
        self.archive_name = archive_name
        #: Checked against before each restore, and added to after encrypting if ``keep_records``.
        self.ledger = ledger
        self.keep_records = keep_records
        self.records_root = records_root or output
        self.cancel_event = threading.Event()
        #: Set by ``decide``, once someone has said what to do with downloads that aren't the files made here.
        self._decided = threading.Event()
        self._restore_doubtful = False

    def decide(self, restore_them: bool) -> None:
        """The answer to ``doubtful``: restore those downloads too, or leave them out."""
        self._restore_doubtful = restore_them
        self._decided.set()

    def _compare_with_records(self) -> list[int]:
        """Which downloads to restore, by position. Every one is compared with the record before any is
        decrypted, so that one that isn't the file made here is only decrypted if someone says so."""
        everything = list(range(len(self.files)))
        if self.ledger is None:
            return everything
        try:
            self.ledger.load()
        except OSError:
            return everything
        if not self.ledger.records:
            return everything
        doubtful = []
        for index, item in enumerate(self.files):
            self._stop_if_cancelled()
            self.comparing.emit(index)
            try:
                digest = records.sha256_of(item.source, self._stop_if_cancelled)
            except OSError:
                continue  # GnuPG will say what's wrong with it.
            finding = self.ledger.check(item.source, digest)
            self.found.emit(index, finding)
            if finding.is_warning:
                doubtful.append(index)
        if not doubtful:
            return everything
        self.doubtful.emit(doubtful)
        while not self._decided.wait(0.1):
            self._stop_if_cancelled()
        if self._restore_doubtful:
            return everything
        for index in doubtful:
            self.progress.emit(index, False, LEFT_OUT, None)
        return [index for index in everything if index not in doubtful]

    def _stop_if_cancelled(self) -> None:
        if self.cancel_event.is_set():
            raise Cancelled()

    def _accept(self, position: int, verification: signatures.Verification) -> bool:
        """Restore a file no verified key signed only if someone agreed to, after being shown exactly this."""
        shown = self.accepted.get(self._keep[position])
        return shown is not None and signatures.same_report(shown, verification)

    def _keep_records(self, result: JobResult) -> None:
        try:
            self.ledger.add(records.records_for(result.outputs, self.records_root))
        except OSError as exc:
            self.note.emit(f"The checksums of these files couldn't be saved, so downloads of them can't be checked "
                           f"later: {exc.strerror or exc}")

    @Slot()
    def run(self):
        try:
            keep = list(range(len(self.files)))
            if self.operation == "restore":
                try:
                    keep = self._compare_with_records()
                except Cancelled:
                    self.completed.emit(JobResult(0, 0, True, (), ()))
                    return
                self.comparing.emit(-1)
            # Positions in the list that's processed, mapped back to rows.
            self._keep = keep
            report = lambda position, ok, message, output: self.progress.emit(  # noqa: E731
                keep[position], ok, message, output)
            if self.archive_name:
                result = encrypt_archive(
                    self.gpg, self.files, self.output, self.archive_name, self.method, self.fingerprint,
                    self.cancel_event, report, passphrases=self.passphrases, cipher=self.cipher,
                    verify=self.verify, on_packing=self.packing.emit, on_checking=lambda: self.checking.emit(-1),
                    sign_with=self.sign_with,
                )
            else:
                options = {"sign_with": self.sign_with} if self.operation == "encrypt" else {
                    "journal": self.journal, "require_signature": self.require_signature,
                    "on_signature": lambda position, verification: self.verified.emit(keep[position], verification),
                    "accept": self._accept if self.accepted else None,
                }
                result = process_items(
                    self.gpg, [self.files[index] for index in keep], self.output, self.operation, self.method,
                    self.fingerprint, self.cancel_event, report, passphrases=self.passphrases, cipher=self.cipher,
                    verify=self.verify, on_checking=lambda position: self.checking.emit(keep[position]), **options,
                )
                # Held files by position in this list, like everything else the worker reports.
                result = replace(result, held=tuple(keep[position] for position in result.held))
            if self.operation == "encrypt" and self.ledger is not None and self.keep_records and result.outputs:
                self._keep_records(result)
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
        #: The algorithm the current job's files get, if it's a choice people made here.
        self._job_algorithm = ""
        #: Why the current job's files can't be checked although checking is on. Empty if they can.
        self._job_not_checked = ""
        #: Whether the current job puts every file into one archive.
        self._job_archive = False
        #: Each file's name inside that archive, which differs from its own only where names clashed.
        self._archive_names: list[str] = []
        #: None before a job, then "done" or "incomplete" until the list changes.
        self._job_state: str | None = None
        self._unfinished_items: list[SourceItem] = []
        #: What the current restore does with files no verified key signed: see ``signature_policy``.
        self._job_policy = ""
        #: Rows the last restore held back for want of a signature, which can be restored anyway.
        self._held: list[int] = []
        self._method_chosen_by_user = False
        #: How many files in the Restore list are encrypted to a key, as far as their first bytes say.
        self._key_files = 0
        self._file_icons = FileIcons()
        self.vault = Vault(self.gpg, vault_path or default_vault_path())
        #: Checksums of what this computer encrypted, kept beside the vault.
        self.ledger = Ledger(records.default_path(self.vault.path.parent))
        #: Where restores keep decrypted data until it has its name, noted beside the vault, so that any left
        #: behind by a crash can be found when the app next starts.
        self.journal = workspace.Journal(self.vault.path.parent / "unfinished")
        #: What the record said about each file being restored, by row.
        self._findings: dict[int, Finding] = {}
        #: What each restored file's signatures showed, by row.
        self._verifications: dict[int, signatures.Verification] = {}
        #: The key the current job signs with, if any.
        self._job_signer: str | None = None
        #: Problems that didn't change the job's result, to mention once it's done.
        self._notes: list[str] = []
        #: Rows of downloads that weren't restored, because they aren't the files made here.
        self._left_out: set[int] = set()

        self.setWindowTitle("mindyourownbytes")
        self.setWindowIcon(icons.app_icon())
        available = QGuiApplication.primaryScreen().availableGeometry()
        self.resize(min(1080, available.width()), min(800, available.height()))
        self.setStyleSheet(theme.stylesheet())

        shell = QWidget()
        shell.setObjectName("shell")
        self.setCentralWidget(shell)
        frame = QHBoxLayout(shell)
        frame.setContentsMargins(0, 0, 0, 0)
        frame.setSpacing(0)
        frame.addWidget(self._build_sidebar())

        self.pages = QStackedWidget()
        self.transfer_page = self._build_transfer_page()
        self.library_page = LibraryPage(lambda: self.current_output("encrypt"))
        self.library_page.restore_requested.connect(self._restore_from_library)
        self.library_page.encrypt_requested.connect(lambda: self.set_operation("encrypt"))
        self.vault_page = VaultPage(self.vault)
        self.vault_page.changed.connect(self._on_vault_changed)
        for page in (self.transfer_page, self.library_page, self.vault_page):
            self.pages.addWidget(page)
        frame.addWidget(self.pages, stretch=1)

        self._build_menus()
        self.update_gpg_status()
        self.refresh_keys()
        self.refresh_algorithms()
        self.advanced_action.setChecked(self._initial_advanced())
        self.advanced_action.toggled.connect(self._set_advanced)
        self._apply_mode()
        self._show_early_version_notice()
        self.set_operation("encrypt")
        QGuiApplication.styleHints().colorSchemeChanged.connect(self._apply_theme)
        # Once the window is up, say if an earlier restore was interrupted and left readable data behind.
        QTimer.singleShot(0, self.offer_cleanup)

    @Slot()
    def _apply_theme(self):
        """Follow the system when it switches between light and dark."""
        app = QApplication.instance()
        if app is not None:
            theme.apply_palette(app)
        self.setStyleSheet(theme.stylesheet())
        refresh_icons(self)
        self.vault_page.refresh_theme()
        self.library_page.refresh_theme()
        self.empty_state.refresh_icon()
        self.update_gpg_status()
        # Redrawing would reset each row to "Waiting", so leave a finished list alone.
        if not self.running and not self._job_state:
            self.render_queue()

    def _initial_gpg(self) -> str:
        """Use a saved path only while it still works, otherwise look again."""
        saved = str(self.settings.value("gpg_path", "") or "")
        if saved and is_valid_gpg(saved):
            return saved
        return find_gpg() or ""

    # ---------------------------------------------------------------- layout

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(210)
        side = QVBoxLayout(sidebar)
        side.setContentsMargins(12, 16, 12, 12)
        side.setSpacing(3)

        brand = QHBoxLayout()
        brand.setContentsMargins(8, 0, 0, 14)
        brand.setSpacing(9)
        logo = QLabel()
        logo.setPixmap(self.windowIcon().pixmap(26, 26))
        brand.addWidget(logo)
        brand.addWidget(label("mind your own bytes", "brand"))
        brand.addStretch(1)
        side.addLayout(brand)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)
        self.encrypt_nav = self._nav_button("Encrypt", "encrypt", "Ctrl+1")
        self.restore_nav = self._nav_button("Restore", "restore", "Ctrl+2")
        self.library_nav = self._nav_button("Library", "library", "Ctrl+3")
        self.vault_nav = self._nav_button("Passphrases", "key", "Ctrl+4")
        self.encrypt_nav.clicked.connect(lambda: self.set_operation("encrypt"))
        self.restore_nav.clicked.connect(lambda: self.set_operation("restore"))
        self.library_nav.clicked.connect(self.show_library)
        self.vault_nav.clicked.connect(self.show_vault)
        for button in (self.encrypt_nav, self.restore_nav, self.library_nav, self.vault_nav):
            self.nav_group.addButton(button)
            side.addWidget(button)
        side.addStretch(1)

        status = QHBoxLayout()
        status.setContentsMargins(8, 0, 0, 0)
        status.setSpacing(6)
        self.gpg_dot = QLabel()
        status.addWidget(self.gpg_dot)
        self.gpg_status = label("", "sidebarNote")
        status.addWidget(self.gpg_status, stretch=1)
        side.addLayout(status)
        note = label(
            f"Version {__version__}<br>Early version, not audited.<br>"
            "<a href='#protect'>What this protects</a>",
            "sidebarNote", wrap=True,
        )
        note.setContentsMargins(8, 4, 0, 0)
        note.linkActivated.connect(lambda _link: self.show_protection())
        side.addWidget(note)
        return sidebar

    def _nav_button(self, text: str, icon_name: str, shortcut: str) -> QPushButton:
        button = QPushButton(text)
        button.setObjectName("navItem")
        button.setCheckable(True)
        button.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        button.setToolTip(f"{text} ({shortcut})")
        button.setIconSize(QSize(18, 18))
        set_icon(button, icon_name)
        return button

    def _build_transfer_page(self) -> QWidget:
        self.drop_area = DropArea()
        self.drop_area.paths_dropped.connect(self.add_paths)
        self.drop_area.hover_changed.connect(self._show_drag_hover)
        main = QVBoxLayout(self.drop_area)
        main.setContentsMargins(24, 16, 24, 4)
        main.setSpacing(8)

        self.heading = label("", "title")
        main.addWidget(self.heading)
        self.subtitle = label("", "muted", wrap=True)
        main.addWidget(self.subtitle)

        self.gpg_bar = InfoBar()
        main.addWidget(self.gpg_bar)
        self.notice_bar = InfoBar(on_dismiss=self._remember_notice_dismissed)
        main.addWidget(self.notice_bar)
        main.addSpacing(4)

        self.files_step, self.files_step_title, self.files_step_number = step_heading(1, "")
        step_row = QHBoxLayout()
        step_row.setSpacing(6)
        step_row.addWidget(self.files_step)
        step_row.addStretch(1)
        self.queue_count = label("", "muted")
        step_row.addWidget(self.queue_count)
        step_row.addSpacing(6)
        self.add_files_button = action_button("Add files", icon_name="file")
        self.add_folder_button = action_button("Add folder", icon_name="folder_plus")
        self.remove_button = action_button("Remove", icon_name="close")
        self.remove_button.setToolTip("Take the selected files off this list. Nothing is deleted.")
        self.clear_button = action_button("Clear list")
        self.add_files_button.clicked.connect(self.select_files)
        self.add_folder_button.clicked.connect(self.select_folder)
        self.remove_button.clicked.connect(self.remove_selected)
        self.clear_button.clicked.connect(self.clear_files)
        self.queue_tools = (self.queue_count, self.add_files_button, self.add_folder_button,
                            self.remove_button, self.clear_button)
        for button in self.queue_tools[1:]:
            step_row.addWidget(button)
        main.addLayout(step_row)

        self.queue_stack = QStackedWidget()
        self.queue_stack.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.drop_zone = DropZone(self.select_files)
        zone_layout = QVBoxLayout(self.drop_zone)
        zone_layout.setContentsMargins(0, 0, 0, 0)
        self.empty_add_files = action_button("Add files", icon_name="file")
        self.empty_add_folder = action_button("Add folder", icon_name="folder_plus")
        self.empty_library = action_button("Open Library", icon_name="library")
        self.empty_add_files.clicked.connect(self.select_files)
        self.empty_add_folder.clicked.connect(self.select_folder)
        self.empty_library.clicked.connect(self.show_library)
        self.empty_state = EmptyState("drop", "", "", (self.empty_add_files, self.empty_add_folder, self.empty_library))
        zone_layout.addWidget(self.empty_state)
        self.queue_stack.addWidget(self.drop_zone)

        self.queue_card = card()
        queue_layout = QVBoxLayout(self.queue_card)
        queue_layout.setContentsMargins(1, 1, 1, 1)
        self.table = QTableWidget(0, 4)
        self.table.setObjectName("fileTable")
        self.table.setHorizontalHeaderLabels(["Name", "Size", "Folder", "Status"])
        configure_table(self.table, stretch=(0, 3))
        self.table.setMinimumHeight(110)
        self.table.setAccessibleName("Files to process")
        queue_layout.addWidget(self.table)
        self.queue_stack.addWidget(self.queue_card)
        main.addWidget(self.queue_stack, stretch=1)

        self.method_step, self.method_step_title, _ = step_heading(2, "")
        self.method_card = self._build_method_card()
        main.addSpacing(2)
        main.addWidget(self.method_step)
        main.addWidget(self.method_card)

        self.save_step, self.save_step_title, _ = step_heading(3, "")
        self.save_card = self._build_destination_card()
        main.addSpacing(2)
        main.addWidget(self.save_step)
        main.addWidget(self.save_card)

        # Stays pinned below the scrolling area, so the main action is always in view.
        footer = QWidget()
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(24, 8, 24, 14)
        footer_layout.setSpacing(8)
        self.result_bar = InfoBar()
        footer_layout.addWidget(self.result_bar)

        bottom = QHBoxLayout()
        bottom.setSpacing(8)
        self.status_text = label("", "muted")
        bottom.addWidget(self.status_text, stretch=1)
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedWidth(180)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setVisible(False)
        bottom.addWidget(self.progress_bar)
        self.open_button = action_button("Open folder", icon_name="folder")
        self.open_button.setToolTip("Open the folder these files are saved to")
        self.open_button.clicked.connect(self.open_output)
        bottom.addWidget(self.open_button)
        self.cancel_button = action_button("Cancel")
        self.cancel_button.clicked.connect(self.cancel)
        self.cancel_button.setVisible(False)
        bottom.addWidget(self.cancel_button)
        self.start_button = action_button("", "primary")
        self.start_button.clicked.connect(self._primary_clicked)
        bottom.addWidget(self.start_button)
        footer_layout.addLayout(bottom)

        # Scrolls on small screens instead of forcing the window to outgrow them.
        scroll = QScrollArea()
        scroll.setObjectName("pageScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(self.drop_area)
        page = QWidget()
        page_layout = QVBoxLayout(page)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.setSpacing(0)
        page_layout.addWidget(scroll, stretch=1)
        page_layout.addWidget(footer)
        return page

    def _build_method_card(self) -> QFrame:
        frame = card()
        grid = QGridLayout(frame)
        grid.setContentsMargins(14, 10, 14, 10)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(1, 1)

        self.method_group = QButtonGroup(self)
        self.passphrase_radio = QRadioButton("Passphrase")
        self.saved_radio = QRadioButton("Saved passphrase")
        self.key_radio = QRadioButton("OpenPGP key")
        for radio in (self.passphrase_radio, self.saved_radio, self.key_radio):
            self.method_group.addButton(radio)
        self.passphrase_radio.setChecked(True)
        for radio in (self.passphrase_radio, self.saved_radio, self.key_radio):
            radio.toggled.connect(self._update_method)
            radio.clicked.connect(self._remember_method_choice)

        self.passphrase_help = label("", "muted", wrap=True)
        grid.addWidget(self.passphrase_radio, 0, 0)
        grid.addWidget(self.passphrase_help, 0, 1)

        saved_row = QHBoxLayout()
        saved_row.setSpacing(6)
        self.saved_help = label("", "muted", wrap=True)
        saved_row.addWidget(self.saved_help, stretch=1)
        self.saved_combo = SteadyComboBox()
        self.saved_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.saved_combo.setAccessibleName("Saved passphrase to use")
        saved_row.addWidget(self.saved_combo, stretch=1)
        self.vault_button = action_button("Unlock")
        self.vault_button.clicked.connect(self._open_vault_for_method)
        saved_row.addWidget(self.vault_button)
        grid.addWidget(self.saved_radio, 1, 0)
        grid.addLayout(saved_row, 1, 1)

        key_row = QHBoxLayout()
        key_row.setSpacing(6)
        self.key_help = label("", "muted", wrap=True)
        key_row.addWidget(self.key_help, stretch=1)
        self.key_combo = SteadyComboBox()
        self.key_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.key_combo.setAccessibleName("OpenPGP key to encrypt to")
        key_row.addWidget(self.key_combo, stretch=1)
        self.refresh_keys_button = QToolButton()
        self.refresh_keys_button.setAccessibleName("Refresh the list of keys")
        self.refresh_keys_button.setToolTip("Look for new keys from Kleopatra or GnuPG")
        set_icon(self.refresh_keys_button, "refresh")
        self.refresh_keys_button.clicked.connect(self.refresh_keys)
        key_row.addWidget(self.refresh_keys_button)
        grid.addWidget(self.key_radio, 2, 0)
        grid.addLayout(key_row, 2, 1)

        # Encrypting to a key says nothing about who did it, because the key is public. Signing does.
        sign_row = QHBoxLayout()
        sign_row.setSpacing(6)
        self.sign_box = QCheckBox("Also sign them with")
        self.sign_box.setToolTip(
            "Signing lets a restore show that you made these files, rather than anyone else who has the "
            "recipient's public key. Unsigned files for your key aren't restored without asking. GnuPG asks "
            "for your key's passphrase itself, if it has one."
        )
        self.sign_box.setChecked(str(self.settings.value("sign_files", "")).lower() == "true")
        self.sign_box.toggled.connect(self._remember_signing)
        sign_row.addWidget(self.sign_box)
        self.signer_combo = SteadyComboBox()
        self.signer_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.signer_combo.setAccessibleName("Your key to sign with")
        self.signer_combo.activated.connect(self._remember_signing)
        sign_row.addWidget(self.signer_combo, stretch=1)
        self.sign_label = QLabel("Signing")
        self.sign_label.setBuddy(self.sign_box)
        grid.addWidget(self.sign_label, 3, 0)
        grid.addLayout(sign_row, 3, 1)

        self.algorithm_label = QLabel("Algorithm")
        self.algorithm_combo = SteadyComboBox()
        self.algorithm_combo.setAccessibleName("Encryption algorithm")
        self.algorithm_combo.setToolTip(
            "Only affects new files. Restoring never asks, because each file records its own algorithm."
        )
        self.algorithm_label.setBuddy(self.algorithm_combo)
        self.algorithm_combo.currentIndexChanged.connect(self._update_algorithm)
        self.algorithm_combo.activated.connect(self._remember_algorithm)
        self.algorithm_help = label("", "muted", wrap=True)
        algorithm_row = QHBoxLayout()
        algorithm_row.setSpacing(10)
        algorithm_row.addWidget(self.algorithm_combo)
        algorithm_row.addWidget(self.algorithm_help, stretch=1)
        grid.addWidget(self.algorithm_label, 4, 0)
        grid.addLayout(algorithm_row, 4, 1)

        self.more_options = label(
            "<a href='#more'>More options</a>: OpenPGP keys, signing, a choice of algorithm, and GnuPG's own "
            "passphrase prompt.", "muted", wrap=True)
        self.more_options.linkActivated.connect(lambda _link: self.advanced_action.setChecked(True))
        grid.addWidget(self.more_options, 5, 0, 1, 2)
        return frame

    def _remember_signing(self, *_args):
        self.settings.setValue("sign_files", "true" if self.sign_box.isChecked() else "false")
        if self.signer_combo.currentData():
            self.settings.setValue("sign_with", str(self.signer_combo.currentData()))
        self._update_method()

    def signer(self) -> str | None:
        """The key to sign new files with, if signing was chosen and is possible for this job."""
        if self.operation != "encrypt" or self.method() != "public-key" or not self.sign_box.isChecked():
            return None
        return str(self.signer_combo.currentData() or "") or None

    def _build_destination_card(self) -> QFrame:
        frame = card()
        grid = QGridLayout(frame)
        grid.setContentsMargins(14, 10, 14, 10)
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(6)
        grid.setColumnStretch(1, 1)

        self.save_label = QLabel("Save to")
        grid.addWidget(self.save_label, 0, 0)
        self.output_edit = QLineEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setAccessibleName("Folder to save to")
        grid.addWidget(self.output_edit, 0, 1)
        self.browse_button = action_button("Change…")
        self.browse_button.clicked.connect(self.select_output)
        grid.addWidget(self.browse_button, 0, 2)
        self.collection_label = QLabel("Collection")
        grid.addWidget(self.collection_label, 1, 0)
        self.collection_combo = SteadyComboBox()
        self.collection_combo.setEditable(True)
        self.collection_combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.collection_combo.lineEdit().setPlaceholderText("None. Type a name to create one, for example Taxes.")
        self.collection_combo.setAccessibleName("Collection to save into")
        self.collection_combo.setToolTip(
            "A subfolder that keeps related files together. Type a new name to create one."
        )
        grid.addWidget(self.collection_combo, 1, 1, 1, 2)

        self.save_as_label = QLabel("Save as")
        grid.addWidget(self.save_as_label, 2, 0)
        save_as_row = QHBoxLayout()
        save_as_row.setSpacing(10)
        self.save_as_group = QButtonGroup(self)
        self.separate_radio = QRadioButton("Separate files")
        self.archive_radio = QRadioButton("One archive, named")
        for radio in (self.separate_radio, self.archive_radio):
            self.save_as_group.addButton(radio)
            save_as_row.addWidget(radio)
        self.archive_name_edit = QLineEdit()
        self.archive_name_edit.setAccessibleName("Name of the archive")
        self.archive_name_edit.setMaxLength(archive.MAX_NAME)
        self.archive_name_edit.setToolTip("Your provider can see this name, so keep it vague.")
        save_as_row.addWidget(self.archive_name_edit, stretch=1)
        grid.addLayout(save_as_row, 2, 1, 1, 2)
        self.archive_help = label(ARCHIVE_COPY["help"], "muted", wrap=True)
        grid.addWidget(self.archive_help, 3, 1, 1, 2)
        remembered = self.settings.value("save_as", "") == "archive"
        (self.archive_radio if remembered else self.separate_radio).setChecked(True)
        self.archive_radio.toggled.connect(self._update_save_as)
        self.archive_radio.clicked.connect(lambda: self.settings.setValue("save_as", "archive"))
        self.separate_radio.clicked.connect(lambda: self.settings.setValue("save_as", "files"))

        self.privacy_note = label("", "muted", wrap=True)
        grid.addWidget(self.privacy_note, 4, 1, 1, 2)
        self.provider_link = label("<a href='#provider'>See what your provider sees</a>", wrap=True)
        self.provider_link.linkActivated.connect(lambda _link: self.show_provider_view())
        grid.addWidget(self.provider_link, 5, 1, 1, 2)
        return frame

    def archive_chosen(self) -> bool:
        return self.operation == "encrypt" and self.archive_radio.isChecked()

    def _update_save_as(self):
        """Only encrypting can make an archive, and its name only matters when one is chosen."""
        encrypting = self.operation == "encrypt"
        for widget in (self.save_as_label, self.separate_radio, self.archive_radio, self.archive_name_edit):
            widget.setVisible(encrypting)
        self.archive_help.setVisible(self.archive_chosen())
        self.archive_name_edit.setEnabled(self.archive_chosen() and not self.running)
        # A date says little about what's inside, which matters because the provider sees this name.
        self.archive_name_edit.setPlaceholderText(f"Archive {date.today().isoformat()}")
        self.privacy_note.setText(ARCHIVE_COPY["save_note"] if self.archive_chosen()
                                  else COPY[self.operation]["save_note"])

    def archive_name(self) -> str:
        """The name typed, or the suggested one. Raises ValueError if it can't be used."""
        return archive.check_name(self.archive_name_edit.text().strip() or self.archive_name_edit.placeholderText())

    def _build_menus(self) -> None:
        bar = self.menuBar()
        file_menu = bar.addMenu("&File")
        self._add_action(file_menu, "Add &files…", self.select_files, QKeySequence.StandardKey.Open)
        self._add_action(file_menu, "Add f&older…", self.select_folder, "Ctrl+Shift+O")
        self._add_action(file_menu, "Open output &folder", self.open_output)
        file_menu.addSeparator()
        self._add_action(file_menu, "E&xit", self.close, "Ctrl+Q")

        go_menu = bar.addMenu("&Go")
        self._add_action(go_menu, "&Encrypt", lambda: self.set_operation("encrypt"), "Ctrl+1")
        self._add_action(go_menu, "&Restore", lambda: self.set_operation("restore"), "Ctrl+2")
        self._add_action(go_menu, "&Library", self.show_library, "Ctrl+3")
        self._add_action(go_menu, "&Passphrases", self.show_vault, "Ctrl+4")

        tools_menu = bar.addMenu("&Tools")
        # Each switch below has a cost, which its tooltip states.
        tools_menu.setToolTipsVisible(True)
        self.advanced_action = tools_menu.addAction("Show &advanced options")
        self.advanced_action.setCheckable(True)
        self.advanced_action.setToolTip(
            "OpenPGP keys, a choice of algorithm, and the switches below. Without them, files get AES-256, "
            "each one is checked, and this app asks for passphrases."
        )
        tools_menu.addSeparator()
        self.check_action = tools_menu.addAction("&Check each file after encrypting it")
        self.check_action.setCheckable(True)
        # On unless it was turned off here, so that a damaged setting can't quietly stop the checks.
        self.check_action.setChecked(str(self.settings.value("check_after_encrypting", "")).lower() != "false")
        self.check_action.setToolTip(
            "Decrypts each new file again and compares it with the original before calling it done. "
            "Takes longer, and only works when this app has the passphrase."
        )
        self.check_action.toggled.connect(self._set_check_preference)
        self.pinentry_action = tools_menu.addAction("Let &GnuPG ask for each passphrase")
        self.pinentry_action.setCheckable(True)
        self.pinentry_action.setChecked(str(self.settings.value("use_pinentry", "")).lower() == "true")
        self.pinentry_action.setToolTip(
            "This app never sees your passphrase, but you're asked once for every file, and it can't check the "
            "new files."
        )
        self.pinentry_action.toggled.connect(self._set_pinentry_preference)
        tools_menu.addSeparator()
        self.records_action = tools_menu.addAction("Keep checksums to check &downloads")
        self.records_action.setCheckable(True)
        # On unless it was turned off here, like the check after encrypting.
        self.records_action.setChecked(str(self.settings.value("keep_records", "")).lower() != "false")
        self.records_action.setToolTip(
            "Saves each new file's checksum on this computer, so that restoring can tell whether a download is the "
            "file you made, rather than an older or swapped copy. The list includes the files' names."
        )
        self.records_action.toggled.connect(
            lambda on: self.settings.setValue("keep_records", "true" if on else "false"))
        self._add_action(tools_menu, "&Import checksums…", self.import_checksums)
        self._add_action(tools_menu, "&Forget saved checksums…", self.forget_checksums)
        tools_menu.addSeparator()
        self.signature_menu = tools_menu.addMenu("Files for your key with no verified &signature")
        self.signature_menu.setToolTipsVisible(True)
        self.signature_menu.menuAction().setToolTip(
            "Anyone who has your public key can make a file that decrypts with your key, so only a signature from "
            "a key you've verified shows who made it. Files you encrypted without signing look the same. "
            "Passphrase files are never affected."
        )
        self.signature_group = QActionGroup(self)
        self.signature_group.setExclusive(True)
        chosen = self._saved_signature_policy()
        for policy, text in SIGNATURE_POLICIES.items():
            action = self.signature_menu.addAction(text)
            action.setCheckable(True)
            action.setData(policy)
            action.setChecked(policy == chosen)
            action.toggled.connect(lambda on, policy=policy: on and self.settings.setValue("signature_policy", policy))
            self.signature_group.addAction(action)
        self.signature_menu.actions()[0].setToolTip(
            "Such a file is decrypted, then deleted again, and you're asked whether to restore it.")
        #: The strictest choice: such files are refused, and nobody is asked.
        self.signature_action = self.signature_menu.actions()[1]
        self.signature_action.setToolTip(
            "Such a file is never restored, so files you encrypted without signing can't be restored either.")
        self.signature_menu.actions()[2].setToolTip(
            "Such a file is restored, and its row says that nothing shows who made it. Only in advanced mode: "
            "simple mode always asks.")
        self.synced_restore_action = tools_menu.addAction("Allow restoring into s&ynced folders")
        self.synced_restore_action.setCheckable(True)
        self.synced_restore_action.setChecked(str(self.settings.value("allow_synced_restore", "")).lower() == "true")
        self.synced_restore_action.setToolTip(
            "Restored files are readable, so a synced folder uploads them to its provider. While this is off, "
            "restoring into a folder that looks synced is refused. While it's on, you're warned and asked instead. "
            "Only in advanced mode. Folders are recognized by name, so a synced folder can still go unnoticed."
        )
        self.synced_restore_action.toggled.connect(
            lambda on: self.settings.setValue("allow_synced_restore", "true" if on else "false"))
        self._add_action(tools_menu, "Clean &up after an interrupted restore…", lambda: self.offer_cleanup(True))
        tools_menu.addSeparator()
        self.post_quantum_action = self._add_action(tools_menu, "&Post-quantum keys…", self.show_post_quantum)
        self._add_action(tools_menu, "&Locate GnuPG…", self.select_gpg)
        kleopatra = self._add_action(tools_menu, "Open &Kleopatra", self.open_kleopatra)
        kleopatra.setEnabled(find_kleopatra() is not None)
        tools_menu.addSeparator()
        self._add_action(tools_menu, "Loc&k saved passphrases", self.vault_page.lock, "Ctrl+L")

        help_menu = bar.addMenu("&Help")
        self._add_action(help_menu, "&What this protects", self.show_protection, "F1")
        self._add_action(help_menu, "Restore on another &computer…", lambda: RecoveryGuide(self).exec())
        self._add_action(help_menu, "What your &provider sees", self.show_provider_view)
        self._add_action(help_menu, "&Report a problem", lambda: self._open_url(f"{REPOSITORY_URL}/issues"))
        help_menu.addSeparator()
        self._add_action(help_menu, "&About mindyourownbytes", self.show_about)

    def _add_action(self, menu: QMenu, text: str, slot, shortcut=None):
        action = menu.addAction(text)
        action.triggered.connect(lambda _checked=False: slot())
        if shortcut is not None:
            action.setShortcut(shortcut)
        return action

    # ---------------------------------------------------------------- navigation

    def current_output(self, operation: str | None = None) -> Path:
        operation = operation or self.operation
        base = DEFAULT_ROOT / ("Encrypted Exports" if operation == "encrypt" else "Restored Files")
        return Path(str(self.settings.value(f"output_{operation}", str(base)))).expanduser()

    def set_operation(self, operation: str):
        if self.running:
            return
        if self.operation != operation:
            self.items = []
            self._source_paths = []
            self._reset_job_state()
            self.passphrase_radio.setChecked(True)
            self._method_chosen_by_user = False
        self.operation = operation
        copy = COPY[operation]
        is_encryption = operation == "encrypt"
        self.pages.setCurrentWidget(self.transfer_page)
        (self.encrypt_nav if is_encryption else self.restore_nav).setChecked(True)
        self.heading.setText(copy["title"])
        self.subtitle.setText(copy["subtitle"])
        self.files_step_title.setText(copy["files_step"])
        self.method_step_title.setText(copy["method_step"])
        self.save_step_title.setText(copy["save_step"])
        self.empty_state.set_text(copy["empty_title"], copy["empty_body"])
        self.empty_library.setVisible(not is_encryption)
        self._show_passphrase_help()
        self.saved_help.setText(copy["saved_help"])
        self.key_radio.setText(copy["key_title"])
        self.key_help.setText(copy["key_help"])
        for widget in (self.collection_label, self.collection_combo, self.provider_link):
            widget.setVisible(is_encryption)
        self._update_save_as()
        self._refresh_collections()
        self._refresh_saved_combo()
        self._update_method()
        self.output_edit.setText(str(self.current_output()))
        self.status_text.setText("")
        self.render_queue()

    def show_library(self):
        if self.running:
            return
        self.pages.setCurrentWidget(self.library_page)
        self.library_nav.setChecked(True)
        self.library_page.refresh()

    def show_vault(self):
        if self.running:
            return
        self.pages.setCurrentWidget(self.vault_page)
        self.vault_nav.setChecked(True)
        self.vault_page.refresh()

    def show_provider_view(self):
        """Your own files, if there are some to encrypt, or examples."""
        files = []
        if self.operation == "encrypt" and self.items:
            try:
                collection = validate_collection_name(self.collection_combo.currentText())
            except ValueError:
                collection = ""
            files = provider_view.from_items(self.items, collection)
        stored = ""
        if files and self.archive_chosen():
            try:
                name = f"{self.archive_name()}{archive.SUFFIX}.gpg"
            except ValueError:
                name = f"{self.archive_name_edit.placeholderText()}{archive.SUFFIX}.gpg"
            stored = f"{collection}/{name}" if collection else name
        provider_view.ProviderView(self, files, stored).exec()

    def show_protection(self):
        ProtectionDialog(self).exec()

    def show_about(self):
        version = gpg_version(self.gpg) if self.gpg else None
        engine = f"GnuPG {'.'.join(map(str, version))}" if version else "GnuPG not found"
        if version and self.gpg == bundled_gpg():
            engine += " (included with this app)"
        QMessageBox.about(
            self, "About mindyourownbytes",
            f"<p style='font-weight:600'>mindyourownbytes {__version__}</p>"
            "<p>Your files. Your keys. None of their business.</p>"
            f"<p>Encryption by: {engine}<br>License: GPL-3.0-or-later<br>"
            f"<a href='{REPOSITORY_URL}'>Source code on GitHub</a></p>"
            "<p>No accounts, no telemetry, and no network connections.</p>",
        )

    def show_post_quantum(self):
        if self.running:
            return
        dialog = PostQuantumDialog(self, self.gpg)
        dialog.keys_changed.connect(self.refresh_keys)
        dialog.exec()

    def import_checksums(self):
        """Add checksums saved on another computer, so that restoring here checks downloads against them."""
        if self.running:
            return
        chosen, _ = QFileDialog.getOpenFileName(self, "Import checksums", str(Path.home()),
                                                "Checksum files (*.txt *.sha256 SHA256SUMS*);;All files (*)")
        if not chosen:
            return
        try:
            text = Path(chosen).read_text(encoding="utf-8-sig", errors="strict")
            found, unreadable = records.read_checksum_file(text, Path(chosen).name)
            self.ledger.add(found)
        except (OSError, UnicodeDecodeError) as exc:
            QMessageBox.warning(self, "Couldn't import the checksums", str(exc))
            return
        skipped = f" {unreadable} lines weren't checksums, and were skipped." if unreadable else ""
        QMessageBox.information(
            self, "Checksums imported",
            f"Imported {plural(len(found), 'checksum')}. Restoring now checks downloads against them.{skipped}",
        )

    def forget_checksums(self):
        if self.running:
            return
        if not self._confirm(
            "Forget the saved checksums?",
            "Restoring will then no longer be able to tell whether a download is the file you made. "
            "Your encrypted files aren't touched.\n\nForget them?",
        ):
            return
        try:
            self.ledger.clear()
        except OSError as exc:
            QMessageBox.warning(self, "Couldn't forget the checksums", str(exc))
            return
        self.status_text.setText("The saved checksums are gone.")

    def offer_cleanup(self, asked: bool = False) -> None:
        """Offer to delete readable data that an interrupted restore left behind, wherever it was.

        Runs at start, and from the Tools menu (``asked``). Only folders the app can prove it made are ever
        deleted, and only once someone agrees. Anything else is listed, never touched.
        """
        if self.running:
            return
        try:
            leftovers = self.journal.leftovers()
        except OSError as exc:
            if asked:
                QMessageBox.warning(self, "Couldn't check", f"The app couldn't read its notes in "
                                    f"{self.journal.directory}: {exc.strerror or exc}")
            return
        if not leftovers:
            if asked:
                QMessageBox.information(self, "Nothing to clean up",
                                        "No interrupted restore has left anything behind.")
            return
        listed = "\n".join(f"• {leftover.path}" for leftover in leftovers[:8])
        if len(leftovers) > 8:
            listed += f"\n• and {len(leftovers) - 8} more"
        answer = QMessageBox.warning(
            self, "An earlier restore didn't finish",
            f"When it stopped, it left readable copies of files in hidden folders that this app made:\n\n{listed}"
            "\n\nDelete them now? The app first checks that each one is a folder it made. Deleting removes "
            "files the normal way, which doesn't securely erase them from an SSD, a backup, or a synced folder.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.Yes,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return  # They stay noted, and are offered again next time.
        failed, unconfirmed = self.journal.clean(leftovers)
        problems = []
        if failed:
            problems.append("These couldn't be deleted, perhaps because a program has them open. Please delete "
                            "them yourself, or try again later:\n\n" + "\n".join(f"• {path}" for path in failed))
        if unconfirmed:
            problems.append("These weren't touched, because the app couldn't confirm it made them. Please check "
                            "them yourself:\n\n" + "\n".join(f"• {path}" for path in unconfirmed))
        if problems:
            QMessageBox.warning(self, "Some folders are still there", "\n\n".join(problems))
        elif asked:
            QMessageBox.information(self, "Cleaned up", "Those folders were deleted.")

    def open_kleopatra(self):
        path = find_kleopatra()
        if path:
            QProcess.startDetached(path, [])

    def _open_url(self, url: str):
        QDesktopServices.openUrl(QUrl(url))

    def _show_early_version_notice(self):
        if str(self.settings.value("early_version_notice_dismissed", "")).lower() == "true":
            return
        self.notice_bar.show_message(
            "info", "This is an early version",
            "It hasn't been independently audited. Try it with unimportant files first, and keep other backups.",
            actions=[("What this protects", self.show_protection)],
        )

    def _remember_notice_dismissed(self):
        self.settings.setValue("early_version_notice_dismissed", "true")

    @Slot(list)
    def _restore_from_library(self, items: list[SourceItem]):
        self.set_operation("restore")
        self._reset_job_state()
        self.items = list(items)
        self._source_paths = []
        self._choose_restore_method()
        self.render_queue()

    def _show_drag_hover(self, hovering: bool):
        for widget in (self.drop_zone, self.queue_card):
            widget.setProperty("dragging", hovering)
            repolish(widget)

    # ---------------------------------------------------------------- how to protect or unlock

    @Slot()
    def _remember_method_choice(self):
        self._method_chosen_by_user = True

    def advanced(self) -> bool:
        """Whether keys, the algorithm, and GnuPG's own prompt are on offer. Simple mode uses safe defaults."""
        return self.advanced_action.isChecked()

    def _initial_advanced(self) -> bool:
        """Simple mode, unless this person already relies on something only advanced mode offers.

        Decided once, and then remembered, so that nothing they use disappears after an update.
        """
        saved = str(self.settings.value("advanced", "")).lower()
        if saved in ("true", "false"):
            return saved == "true"
        relies = (any(key.has_secret for key in self._keys.values())
                  or self.algorithm_combo.currentData() not in (None, DEFAULT_CIPHER)
                  or self.pinentry_action.isChecked() or not self.check_action.isChecked()
                  or not self.records_action.isChecked() or self._chosen_signature_policy() != "ask"
                  or self.synced_restore_action.isChecked())
        self.settings.setValue("advanced", "true" if relies else "false")
        return relies

    def _saved_signature_policy(self) -> str:
        saved = str(self.settings.value("signature_policy", "") or "")
        if saved in SIGNATURE_POLICIES:
            return saved
        # Before there were three choices, there was one switch, which meant "never".
        return "refuse" if str(self.settings.value("require_signature", "")).lower() == "true" else "ask"

    def _chosen_signature_policy(self) -> str:
        checked = self.signature_group.checkedAction()
        return str(checked.data()) if checked is not None else "ask"

    def signature_policy(self) -> str:
        """What a restore does with a file for your key that no key you've verified signed: ask, refuse, or allow.

        Simple mode asks unless "never" was chosen, because hiding a choice must never quietly weaken a restore.
        """
        chosen = self._chosen_signature_policy()
        return chosen if self.advanced() or chosen == "refuse" else "ask"

    @Slot(bool)
    def _set_advanced(self, enabled: bool):
        self.settings.setValue("advanced", "true" if enabled else "false")
        self._apply_mode()

    def _apply_mode(self):
        advanced = self.advanced()
        # A stricter signature setting still applies when hidden: simple mode never quietly weakens a restore.
        for action in (self.check_action, self.pinentry_action, self.records_action, self.post_quantum_action,
                       self.signature_menu.menuAction(), self.synced_restore_action):
            action.setVisible(advanced)
        if not advanced and self.operation == "encrypt" and self.key_radio.isChecked():
            self.passphrase_radio.setChecked(True)
        self._show_passphrase_help()
        self._update_method()

    def method(self) -> str:
        """The current choice: "once", "pinentry", "saved", or "public-key"."""
        if self.saved_radio.isChecked():
            return "saved"
        if self.key_radio.isChecked() and (self.advanced() or self.operation == "restore"):
            return "public-key" if self.operation == "encrypt" else "pinentry"
        return "pinentry" if self.pinentry_action.isChecked() and self.advanced() else "once"

    def set_method(self, method: str) -> None:
        if method == "saved":
            self.saved_radio.setChecked(True)
        elif method == "public-key" or (method == "pinentry" and self.operation == "restore"):
            self.key_radio.setChecked(True)
        else:
            self.passphrase_radio.setChecked(True)
            self.pinentry_action.setChecked(method == "pinentry")
        self._update_method()

    @Slot(bool)
    def _set_pinentry_preference(self, enabled: bool):
        self.settings.setValue("use_pinentry", "true" if enabled else "false")
        self._show_passphrase_help()

    @Slot(bool)
    def _set_check_preference(self, enabled: bool):
        self.settings.setValue("check_after_encrypting", "true" if enabled else "false")

    def _show_passphrase_help(self):
        text = ("GnuPG will ask for the passphrase once for each file."
                if self.pinentry_action.isChecked() and self.advanced()
                else COPY[self.operation]["passphrase_help"])
        if self.operation == "restore" and self._key_files and len(self.items) > self._key_files:
            text += (MIXED_HELP["one"] if self._key_files == 1
                     else MIXED_HELP["many"].format(count=self._key_files))
        self.passphrase_help.setText(text)

    def _choose_restore_method(self):
        """Open files the way they were protected, without asking the user to remember.

        Only ever a starting point: anything the user picked themselves stays picked.
        """
        if self.operation != "restore" or not self.items:
            self._key_files = 0
            return
        kinds = [peek_protection(item.source) for item in itertools.islice(self.items, 200)]
        self._key_files = kinds.count("key")
        self._show_passphrase_help()
        if self._method_chosen_by_user:
            return
        # Only a list that's all for keys needs the key. In a mix, the passphrase opens the rest.
        all_keys = bool(kinds) and self._key_files == len(kinds)
        (self.key_radio if all_keys else self.passphrase_radio).setChecked(True)
        self._method_chosen_by_user = False

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
        saved = self.saved_radio.isChecked()
        key = self.key_radio.isChecked()
        has_entries = self.vault.unlocked and self.saved_combo.count() > 0
        choosing_key = key and self.operation == "encrypt"
        self.saved_help.setVisible(not (saved and has_entries))
        self.saved_combo.setVisible(saved and has_entries)
        self.vault_button.setVisible(saved and not has_entries)
        if self.vault.unlocked:
            self.vault_button.setText("Add a passphrase")
        else:
            self.vault_button.setText("Unlock" if self.vault.exists else "Set up")
        # Restoring still offers a key when the files need one, which the list's first bytes decide.
        show_key = self.advanced() or (self.operation == "restore" and key)
        self.key_radio.setVisible(show_key)
        self.key_help.setVisible(show_key and not choosing_key)
        self.key_combo.setVisible(show_key and choosing_key)
        self.refresh_keys_button.setVisible(show_key and choosing_key)
        signing = show_key and choosing_key
        for widget in (self.sign_label, self.sign_box, self.signer_combo):
            widget.setVisible(signing)
        can_sign = self.signer_combo.count() > 0 and bool(self.signer_combo.currentData())
        self.sign_box.setEnabled(can_sign and not self.running)
        self.signer_combo.setEnabled(can_sign and self.sign_box.isChecked() and not self.running)
        self.more_options.setVisible(not self.advanced() and self.operation == "encrypt")
        self._update_algorithm()

    def _update_algorithm(self):
        """Only passphrases have a choice: a key decides its own, and a restore reads it from the file."""
        for widget in (self.algorithm_label, self.algorithm_combo, self.algorithm_help):
            widget.setVisible(self.operation == "encrypt" and self.advanced())
        by_key = self.key_radio.isChecked()
        self.algorithm_combo.setEnabled(not by_key and not self.running)
        self.algorithm_help.setText(CIPHER_SET_BY_KEY if by_key else CIPHER_HELP.get(self.chosen_cipher(), ""))

    def chosen_cipher(self) -> str:
        """The algorithm new files get. Simple mode always uses the default, and keeps the choice for later."""
        if not self.advanced():
            return DEFAULT_CIPHER
        return str(self.algorithm_combo.currentData() or DEFAULT_CIPHER)

    def _remember_algorithm(self):
        self.settings.setValue("cipher", self.chosen_cipher())

    def refresh_algorithms(self):
        """Offer what this GnuPG can use, and keep the earlier choice if it still can."""
        wanted = self.algorithm_combo.currentData() or str(self.settings.value("cipher", DEFAULT_CIPHER))
        self.algorithm_combo.blockSignals(True)
        self.algorithm_combo.clear()
        for cipher in available_ciphers(self.gpg):
            recommended = " (recommended)" if cipher.name == DEFAULT_CIPHER else ""
            self.algorithm_combo.addItem(f"{cipher.label}{recommended}", cipher.name)
        self.algorithm_combo.setCurrentIndex(max(self.algorithm_combo.findData(wanted), 0))
        self.algorithm_combo.blockSignals(False)
        self._update_algorithm()

    def _open_vault_for_method(self):
        if self.vault.exists and not self.vault.unlocked:
            self.vault_page.request_unlock()
        else:
            self.show_vault()

    def update_gpg_status(self):
        version = gpg_version(self.gpg) if self.gpg else None
        ready = version is not None and version >= MIN_GPG_VERSION
        self.gpg_dot.setPixmap(icons.pixmap("check" if ready else "alert", 14, theme.color("ok" if ready else "warn")))
        if ready:
            self.gpg_status.setText(f"GnuPG {'.'.join(map(str, version))} ready")
            self.gpg_bar.hide()
            return
        minimum = ".".join(map(str, MIN_GPG_VERSION))
        self.gpg_status.setText("GnuPG not found")
        get = gnupg_help.for_this_system()
        self.gpg_bar.show_message(
            "warning", "This app needs GnuPG to encrypt and restore files",
            f"It's free and does all the encryption here. {get.banner.format(minimum=minimum)}",
            actions=[(get.button, lambda: self._open_url(get.url)), ("Locate GnuPG…", self.select_gpg)],
            dismissable=False,
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
        self.refresh_algorithms()

    def refresh_keys(self):
        self.key_combo.clear()
        self._keys = {}
        self._refresh_signers()
        if not self.gpg or not is_valid_gpg(self.gpg):
            self.key_combo.addItem("GnuPG not found", "")
            return
        try:
            keys = list_public_keys(self.gpg)
        except Exception:
            keys = []
        if not keys:
            self.key_combo.addItem(gnupg_help.for_this_system().no_keys, "")
            return
        for key in keys:
            owner = "your key" if key.has_secret else "someone else's key"
            parts = (key.uid[:48], key.algorithm, key.fingerprint[-10:], owner)
            self.key_combo.addItem(" · ".join(part for part in parts if part), key.fingerprint)
            self._keys[key.fingerprint] = key

    def _refresh_signers(self):
        """Your keys that can sign, with the full fingerprint in the tooltip, since names prove nothing."""
        wanted = self.signer_combo.currentData() or str(self.settings.value("sign_with", "") or "")
        self.signer_combo.clear()
        signers = []
        if self.gpg and is_valid_gpg(self.gpg):
            try:
                signers = list_signing_keys(self.gpg)
            except Exception:
                signers = []
        for key in signers:
            parts = (key.uid[:48], key.algorithm, key.fingerprint[-10:])
            self.signer_combo.addItem(" · ".join(part for part in parts if part), key.fingerprint)
            self.signer_combo.setItemData(self.signer_combo.count() - 1, signatures.spaced(key.fingerprint),
                                          Qt.ItemDataRole.ToolTipRole)
        if not signers:
            self.signer_combo.addItem("You have no key that can sign", "")
        self.signer_combo.setCurrentIndex(max(self.signer_combo.findData(wanted), 0))
        if self.settings.value("sign_files") is None and hasattr(self, "sign_box"):
            # Signed unless someone chose otherwise, so that restoring them can show who made them. Not
            # remembered as a choice, so that it follows whether there's a key to sign with.
            blocked = self.sign_box.blockSignals(True)
            self.sign_box.setChecked(bool(signers))
            self.sign_box.blockSignals(blocked)
        if hasattr(self, "sign_label"):
            self._update_method()

    # ---------------------------------------------------------------- the file list

    def select_files(self):
        if self.running:
            return
        files, _ = QFileDialog.getOpenFileNames(
            self, COPY[self.operation]["add_title"], str(Path.home()),
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
        if self._job_state:
            # A new batch. Finished rows make way, and anything unfinished stays.
            self.items = list(self._unfinished_items)
            self._source_paths = []
            self._reset_job_state()
        if self.items and not self._source_paths:
            # The list was curated (rows removed, or sent from the Library).
            # Keep it as it is when adding more files.
            try:
                added, skipped, unreadable = collect_files(new_paths, self.current_output(), self.operation)
            except (ValueError, OSError) as exc:
                QMessageBox.warning(self, "Cannot add files", str(exc))
                return
            existing = {item.source for item in self.items}
            self.items.extend(item for item in added if item.source not in existing)
        else:
            inputs = self._source_paths + [path for path in new_paths if path not in self._source_paths]
            try:
                items, skipped, unreadable = collect_files(inputs, self.current_output(), self.operation)
            except (ValueError, OSError) as exc:
                QMessageBox.warning(self, "Cannot add files", str(exc))
                return
            self._source_paths = inputs
            self.items = items
        self._choose_restore_method()
        self.render_queue()
        if skipped:
            self.status_text.setText(f"Left out {skipped} links, duplicates, or files of the wrong type.")
        self._warn_unreadable(unreadable)

    def remove_selected(self):
        if self.running:
            return
        rows = {index.row() for index in self.table.selectedIndexes()}
        if not rows:
            return
        # Rebuild the list as individual selected files; preserve the intended
        # relative folder layout instead of rescanning removed parent folders.
        self.items = [item for i, item in enumerate(self.items) if i not in rows]
        self._source_paths = []
        self._reset_job_state()
        self._choose_restore_method()
        self.render_queue()

    def clear_files(self):
        if self.running:
            return
        self.items = []
        self._source_paths = []
        self._reset_job_state()
        self.status_text.setText("")
        self.render_queue()

    def _display_name(self, item: SourceItem) -> str:
        name = item.source.name
        return name[:-4] if name.lower().endswith(ENCRYPTED_SUFFIXES) else name

    def render_queue(self):
        count = len(self.items)
        self.queue_stack.setCurrentWidget(self.queue_card if count else self.drop_zone)
        self.queue_count.setVisible(bool(count))
        for widget in self.queue_tools[1:]:
            widget.setVisible(bool(count) and self._job_state != "done")
        self.table.setRowCount(count)
        for row, item in enumerate(self.items):
            name = QTableWidgetItem(self._file_icons.for_name(item.source.name), self._display_name(item))
            name.setToolTip(str(item.source))
            self.table.setItem(row, 0, name)
            self.table.setItem(row, 1, QTableWidgetItem(human_size(item.size)))
            folder = str(item.relative.parent)
            self.table.setItem(row, 2, QTableWidgetItem("—" if folder == "." else folder))
            self._set_row_status(row, "Waiting", "clock", "muted")
        total = sum(item.size for item in self.items)
        self.queue_count.setText(f"{plural(count)} · {human_size(total)}")
        self._update_primary()

    def _set_row_status(self, row: int, text: str, icon_name: str, color_name: str, tooltip: str = "") -> None:
        color = theme.color(color_name)
        cell = QTableWidgetItem(icons.icon(icon_name, color), text)
        cell.setForeground(QBrush(color))
        cell.setToolTip(tooltip or text)
        self.table.setItem(row, 3, cell)

    def _update_primary(self):
        copy = COPY[self.operation]
        count = len(self.items)
        if self._job_state == "done":
            text = "Start over"
        elif self._job_state == "incomplete":
            text = "Try these again"
        else:
            text = copy["start"].format(files=plural(count)) if count else copy["start_empty"]
        self.start_button.setText(text)
        self.start_button.setEnabled(bool(count))

    def _reset_job_state(self):
        self._job_state = None
        self._unfinished_items = []
        self._held = []
        self._job_output = None
        self.result_bar.hide()
        self.open_button.show()
        self._show_results_view(False)

    def _show_results_view(self, finished: bool):
        """Once everything has succeeded, the steps have nothing left to ask."""
        for widget in (self.method_step, self.method_card, self.save_step, self.save_card):
            widget.setVisible(not finished)
        self.files_step_number.setVisible(not finished)
        self.files_step_title.setText("Your files" if finished else COPY[self.operation]["files_step"])

    def _primary_clicked(self):
        if self._job_state == "done":
            self.clear_files()
            return
        if self._job_state == "incomplete":
            self.items = list(self._unfinished_items)
            self._source_paths = []
        self.start()

    def select_output(self):
        if self.running:
            return
        selected = QFileDialog.getExistingDirectory(self, "Choose where to save", str(self.current_output()))
        if not selected:
            return
        self.settings.setValue(f"output_{self.operation}", selected)
        self.output_edit.setText(selected)
        self._refresh_collections()

    def open_output(self):
        path = self._job_output or self.current_output()
        path.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # ---------------------------------------------------------------- safety checks

    def _confirm(self, title: str, text: str) -> bool:
        answer = QMessageBox.warning(
            self, title, text, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return answer == QMessageBox.StandardButton.Yes

    def _confirm_locations(self, output: Path) -> bool:
        """Refuse, or warn, when the plaintext is, or is about to be, inside a synced folder."""
        if self.operation == "restore":
            provider = looks_cloud_synced(output)
            if not provider:
                return True
            if not (self.advanced() and self.synced_restore_action.isChecked()):
                # Refused rather than asked: a click-through question is easy to answer without reading it.
                local = DEFAULT_ROOT / "Restored Files"
                suggestion = str(local) if not looks_cloud_synced(local) else "a folder on this computer only"
                QMessageBox.warning(self, SYNCED_COPY["refused_title"],
                                    SYNCED_COPY["refused"].format(provider=provider, suggestion=suggestion))
                return False
            return self._confirm(SYNCED_COPY["confirm_title"], SYNCED_COPY["confirm"].format(provider=provider))
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
            count = plural(len(self.items))
            dialog = PassphraseDialog(
                self,
                "Choose a passphrase" if encrypting else "Enter the passphrase",
                f"This passphrase will protect {count}. Nobody can recover it for you, so keep it somewhere safe."
                if encrypting else f"This passphrase will be tried on {count}.",
                confirm=encrypting, min_length=strength.MIN_LENGTH if encrypting else 1,
                ok_text="Encrypt" if encrypting else "Restore",
            )
            return [dialog.passphrase()] if dialog.exec() else None
        if not self.vault.unlocked:
            # Stop after unlocking, so nobody encrypts with whichever saved
            # passphrase happens to be selected without having seen the list.
            if self.vault.exists:
                if self.vault_page.request_unlock():
                    self.status_text.setText("Unlocked. Choose a saved passphrase, then start again.")
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
        chosen = [entry for entry in entries if entry.id == choice]
        if chosen and self.operation == "encrypt":
            # New files get the same rule as a passphrase typed for them. Opening old files never does.
            rating = strength.assess(chosen[0].passphrase)
            if not rating.acceptable:
                QMessageBox.warning(
                    self, "Choose a stronger passphrase",
                    f"“{chosen[0].label}” is too easy to guess to protect new files. {rating.message}\n\n"
                    "It still opens the files it already protects. Add a new passphrase under Passphrases, "
                    "and let your computer pick it.")
                return None
        return [entry.passphrase for entry in chosen] or None

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

    # ---------------------------------------------------------------- the job

    def start(self, accepted: dict[int, signatures.Verification] | None = None):
        """Encrypt or restore the files in the list.

        ``accepted`` restores files again that were held back because no key you've verified signed them,
        once someone has agreed to restore them anyway: by row, what they were shown about each one.
        """
        if self.running:
            return
        if not self.items:
            QMessageBox.information(self, "No files selected", "Drag or select files to begin.")
            return
        if not self.gpg or not is_valid_gpg(self.gpg):
            self.update_gpg_status()
            QMessageBox.warning(self, "GnuPG is required", gnupg_help.for_this_system().required)
            return
        selection = self.method()
        method = "public-key" if selection == "public-key" else "password"
        fingerprint = str(self.key_combo.currentData() or "") if selection == "public-key" else None
        if selection == "public-key" and not fingerprint:
            QMessageBox.warning(
                self, "No encryption key",
                f"{gnupg_help.for_this_system().make_key} If you don't use keys, choose Passphrase instead.",
            )
            return
        output = self._job_directory()
        if output is None:
            return
        archive_name = None
        if self.archive_chosen():
            try:
                archive_name = self.archive_name()
            except ValueError as exc:
                QMessageBox.warning(self, "Check the archive name", str(exc))
                return
        if not self._confirm_locations(output):
            return
        if fingerprint and not self._confirm_recipient(fingerprint):
            return
        sign_with = self.signer()
        if self.operation == "encrypt" and selection == "public-key" and self.sign_box.isChecked() and not sign_with:
            QMessageBox.warning(self, "No key to sign with",
                                "You have no key that can sign. Untick “Also sign them with” to encrypt without "
                                "signing, or make a key in Kleopatra.")
            return
        # Files held back for want of a signature all decrypted with a key, which needs no passphrase from here.
        passphrases = [] if accepted else self._passphrases_for(selection)
        if passphrases is None:
            return
        try:
            # Restored plaintext gets a private folder on systems that honor modes.
            output.mkdir(parents=True, exist_ok=True, mode=0o700 if self.operation == "restore" else 0o777)
            if self._source_paths:
                self.items, _, unreadable = collect_files(self._source_paths, output, self.operation)
                self._warn_unreadable(unreadable)
            else:
                # A curated list: re-check the files before relying on them.
                for item in self.items:
                    if not item.source.is_file() or item.source.is_symlink():
                        raise ValueError(f"A source file is unavailable: {item.source}")
                # Trying again means the files as they are now. From here on, each one must stay that file.
                self.items = [replace(item, identity=safefs.identity_of(item.source)) for item in self.items]
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Cannot start", str(exc))
            return
        self._reset_job_state()
        self.render_queue()
        self.running = True
        self._failures = []
        self._job_output = output
        cipher = self.chosen_cipher()
        self._job_algorithm = CIPHER_LABELS[cipher] if self.operation == "encrypt" and method == "password" else ""
        # Simple mode always checks: turning that off is an advanced choice.
        verify = self.operation == "encrypt" and (self.check_action.isChecked() or not self.advanced())
        self._job_not_checked = NOT_CHECKED.get(selection, "") if verify else ""
        self._job_archive = archive_name is not None
        self._archive_names = (archive.member_names([item.relative.as_posix() for item in self.items])
                               if self._job_archive else [])
        self._succeeded_rows: set[int] = set()
        self._findings = {}
        self._verifications = {}
        self._job_policy = self.signature_policy() if self.operation == "restore" else ""
        self._job_signer = sign_with
        self._notes = []
        self._left_out = set()
        self._set_busy(True)
        self.progress_bar.setRange(0, len(self.items))
        self.progress_bar.setValue(0)
        if self.operation == "restore":
            # Every download is compared with the saved checksums before anything is decrypted.
            self.status_text.setText(DOUBTFUL_COPY["starting"])
        else:
            self._mark_working(0)
            self._show_progress(0)

        self._thread = QThread(self)
        self.worker = BackupWorker(self.gpg, list(self.items), output, self.operation, method,
                                   fingerprint, passphrases, cipher, verify, archive_name, ledger=self.ledger,
                                   keep_records=self.records_action.isChecked() or not self.advanced(),
                                   records_root=self.current_output("encrypt"), sign_with=sign_with,
                                   journal=self.journal, require_signature=self._job_policy in ("ask", "refuse"),
                                   accepted=accepted if self._job_policy == "ask" else None)
        self.worker.moveToThread(self._thread)
        self._thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._progress)
        self.worker.verified.connect(self._verified)
        self.worker.checking.connect(self._checking)
        self.worker.found.connect(self._found)
        self.worker.note.connect(self._note)
        self.worker.comparing.connect(self._comparing)
        self.worker.doubtful.connect(self._ask_about_doubtful)
        self.worker.packing.connect(self._packing)
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
                       self.clear_button, self.browse_button, self.passphrase_radio, self.saved_radio,
                       self.key_radio, self.key_combo, self.saved_combo,
                       self.collection_combo, self.refresh_keys_button, self.vault_button, self.menuBar(),
                       self.separate_radio, self.archive_radio):
            widget.setEnabled(not is_busy)
        self._update_method()  # Signing's controls follow the job, and whether there's a key to sign with.
        self.start_button.setVisible(not is_busy)
        self.open_button.setVisible(not is_busy)
        self.cancel_button.setEnabled(is_busy)
        self.cancel_button.setVisible(is_busy)
        self.progress_bar.setVisible(is_busy)
        self.drop_area.setAcceptDrops(not is_busy)
        self._update_algorithm()
        self._update_save_as()

    def _words(self, key: str) -> str:
        """This screen's wording, or the archive's when the job makes one."""
        return ARCHIVE_COPY[key] if self._job_archive and key in ARCHIVE_COPY else COPY[self.operation][key]

    def _mark_working(self, row: int):
        if row < self.table.rowCount():
            self._set_row_status(row, self._words("row_working"), "clock", "text")
            self.table.scrollToItem(self.table.item(row, 0))

    def _show_progress(self, done: int):
        text = self._words("working").format(done=min(done + 1, len(self.items)), total=len(self.items))
        if self.method() == "pinentry" or (self.operation == "restore" and self._key_files):
            text += " GnuPG may ask for a passphrase."
        self.status_text.setText(text)

    @Slot(int)
    def _packing(self, index: int):
        if self.worker is None or self.worker.cancel_event.is_set():
            return
        self._mark_working(index)
        self.progress_bar.setValue(index)
        self._show_progress(index)

    @Slot(int)
    def _checking(self, index: int):
        if self.worker is None or self.worker.cancel_event.is_set():
            return
        if index < 0:  # The whole archive.
            self.progress_bar.setValue(len(self.items))
            self.status_text.setText(ARCHIVE_COPY["checking"])
            return
        if index < self.table.rowCount():
            self._set_row_status(index, CHECK_COPY["row_working"], "clock", "text")
        self.status_text.setText(CHECK_COPY["working"].format(done=index + 1, total=len(self.items)))

    @Slot(int, object)
    def _found(self, index: int, finding: Finding):
        self._findings[index] = finding

    @Slot(int, object)
    def _verified(self, index: int, verification: signatures.Verification):
        self._verifications[index] = verification

    @Slot(str)
    def _note(self, message: str):
        self._notes.append(message)

    @Slot(int)
    def _comparing(self, index: int):
        if self.worker is None or self.worker.cancel_event.is_set():
            return
        if index >= 0:
            self.status_text.setText(DOUBTFUL_COPY["working"].format(done=index + 1, total=len(self.items)))
            return
        # Compared and decided: decrypting starts with the first download that wasn't left out.
        first = next((row for row in range(len(self.items)) if row not in self._left_out), None)
        if first is not None:
            self._mark_working(first)
            self._show_progress(first)

    @Slot(object)
    def _ask_about_doubtful(self, rows: list[int]):
        """Before any of them is decrypted, ask whether to restore downloads that aren't the files made here."""
        def reason(row: int) -> str:
            return RECORD_WORDS[self._findings[row].verdict].removeprefix("but ")

        if len(rows) == 1:
            title = DOUBTFUL_COPY["one_title"]
            text = DOUBTFUL_COPY["one"].format(name=self.items[rows[0]].source.name,
                                               reason=self._findings[rows[0]].message)
        else:
            listed = [f"• {self.items[row].source.name}: {reason(row)}" for row in rows[:8]]
            if len(rows) > 8:
                listed.append(f"• and {len(rows) - 8} more")
            title = DOUBTFUL_COPY["many_title"].format(count=len(rows))
            text = DOUBTFUL_COPY["many"].format(listed="\n".join(listed))
        rest = ("rest_none" if len(rows) == len(self.items) else "rest_one" if len(rows) == 1 else "rest_many")
        restore_them = self._confirm(title, text + DOUBTFUL_COPY[rest])
        if self.worker is not None:
            self.worker.decide(restore_them)

    def _show_row_done(self, row: int, checked: bool, output):
        """Only a file the job really checked may say so."""
        if self._job_archive:
            words = ARCHIVE_COPY
            done = ARCHIVE_COPY["row_done"]
        else:
            words = {**CHECK_COPY, "row_checked": CHECK_COPY["row_done"]}
            done = COPY[self.operation]["row_done"]
        if checked:
            text, note = words["row_checked"], words["row_tip"]
        elif self._job_not_checked:
            text, note = words["row_skipped"], self._job_not_checked
        else:
            text, note = done, ""
        if self._job_archive and row < len(self._archive_names):
            inside = self._archive_names[row]
            if inside != self.items[row].relative.as_posix():
                note = " ".join(filter(None, (note, ARCHIVE_COPY["renamed"].format(name=inside))))
        if self._job_signer:
            if not self._job_archive:
                text = text.replace("Encrypted", "Signed and encrypted", 1)
            note = " ".join(filter(None, (note, SIGNED_NOTE.format(key=signatures.spaced(self._job_signer)))))
        self._show_finished_row(row, text, note, output)

    def _show_finished_row(self, row: int, text: str, note: str, output):
        """A finished row, with what the record and any signature say if it was a download being restored."""
        finding = self._findings.get(row)
        verification = self._verifications.get(row)
        level = ("check", "ok")
        if verification is not None:
            # Who made it, as far as signatures can tell, which decrypting alone never shows.
            who = signatures.headline(verification)
            text = f"{text}, {who}" if who else text
            note = " ".join(filter(None, (note, signatures.explanation(verification))))
            if verification.status in ("unverified", "revoked", "expired"):
                level = ("alert", "warn")
        if finding is not None and finding.is_warning:
            # Restored, because it decrypted, but not the file that was made here.
            self._set_row_status(row, f"{text}, {RECORD_WORDS[finding.verdict]}", "alert", "warn",
                                 "\n".join(filter(None, (str(output), finding.message, note))))
            return
        if finding is not None and finding.verdict == "match":
            words = (RECORD_WORDS["match_where"].format(where=finding.where) if finding.where
                     else RECORD_WORDS["match"])
            text, note = f"{text}, {words}", " ".join(filter(None, (finding.message, note)))
        self._set_row_status(row, text, *level, f"{output}\n{note}" if note else str(output))

    def _signature_summary(self) -> tuple[str, bool]:
        """What the restored files' signatures showed, in one sentence, and whether any deserves a warning.

        Only said when it matters: when a file was opened with a key, which anyone could have made with
        the public key, or when a file carried a signature at all.
        """
        found = [self._verifications[row] for row in sorted(self._succeeded_rows) if row in self._verifications]
        relevant = [verification for verification in found if verification.encrypted_to_key or verification.signatures]
        if not relevant:
            return "", False
        counts: dict[str, int] = {}
        for verification in relevant:
            counts[verification.status] = counts.get(verification.status, 0) + 1
        parts = [f"{counts[status]} {words}" for status, words in SIGNATURE_SUMMARY.items() if counts.get(status)]
        caution = bool(counts.get("unverified") or counts.get("revoked") or counts.get("expired"))
        sentence = f"Who made them: {', '.join(parts)}."
        if caution or counts.get("unsigned"):
            sentence += " Only a signature from a key you've verified shows who made a file."
        return sentence, caution

    @Slot(int, bool, str, object)
    def _progress(self, index: int, ok: bool, message: str, output):
        if not ok and message == LEFT_OUT:
            # Not decrypted at all, so this is neither a failure nor progress.
            self._left_out.add(index)
            finding = self._findings[index]
            self._set_row_status(index, DOUBTFUL_COPY["row"].format(
                reason=RECORD_WORDS[finding.verdict].removeprefix("but ")), "alert", "warn", finding.message)
            return
        cancelled = not ok and message == "Cancelled"
        if index < self.table.rowCount():
            if ok and message == UNPACKED:
                self._show_finished_row(index, UNPACKED_ROW, "", output)
                self._succeeded_rows.add(index)
            elif ok:
                self._show_row_done(index, message == CHECKED, output)
                self._succeeded_rows.add(index)
            elif cancelled:
                self._set_row_status(index, "Cancelled", "close", "muted")
            elif index in self._verifications and self._job_policy == "ask":
                # Held back for want of a signature, until someone says whether to restore it.
                verification = self._verifications[index]
                self._set_row_status(
                    index, HELD_COPY["row"].format(why=signatures.headline(verification)), "alert", "warn",
                    HELD_COPY["row_tip"].format(explanation=signatures.explanation(verification)))
            else:
                short = re.split(r"[,:.]", message, maxsplit=1)[0]
                self._set_row_status(index, short, "alert", "error", message)
        self.progress_bar.setValue(index + 1)
        if not ok and not cancelled:
            self._failures.append(message)
        upcoming = next((row for row in range(index + 1, len(self.items)) if row not in self._left_out), None)
        if not cancelled and upcoming is not None:
            self._mark_working(upcoming)
            self._show_progress(upcoming)

    @Slot(object)
    def _completed(self, result: JobResult):
        self.running = False
        self._set_busy(False)
        self._refresh_collections()
        held = len(result.held) if self._job_policy == "ask" else 0
        self.status_text.setText(
            f"{result.succeeded} finished · {result.failed - held} failed"
            + (HELD_COPY["status"].format(count=held) if held else "")
            + (f" · {len(self._left_out)} left out" if self._left_out else "")
            + (" · cancelled" if result.cancelled else "")
        )
        self._unfinished_items = [item for row, item in enumerate(self.items) if row not in self._succeeded_rows]
        self._job_state = "incomplete" if self._unfinished_items else "done"
        self._show_results_view(self._job_state == "done")
        for widget in self.queue_tools[1:]:
            widget.setVisible(self._job_state != "done")
        self._show_result(result)
        self._update_primary()
        if self._notes:
            QMessageBox.warning(self, "Checksums weren't saved", "\n\n".join(self._notes))
        if result.leftovers:
            listed = "\n".join(str(path) for path in result.leftovers[:8])
            QMessageBox.warning(
                self, "Temporary files were left behind",
                LEFTOVER_COPY.format(listed=listed) if self.operation == "restore" else
                f"These temporary files, which hold only encrypted data, could not be removed:\n\n{listed}",
            )

    def _show_result(self, result: JobResult):
        copy = COPY[self.operation]
        open_folder = ("Open folder", self.open_output)
        total = len(self.items)
        if result.cancelled:
            self.result_bar.show_message(
                "warning", "Cancelled", f"{plural(result.succeeded)} finished before you stopped.",
                actions=[open_folder] if result.succeeded else [],
            )
        elif result.failed:
            # Files held back for want of a signature can still be restored, if someone agrees to.
            self._held = list(result.held) if self._job_policy == "ask" else []
            actions = ([(HELD_COPY["action"], self._restore_held)] if self._held else []) + (
                [open_folder] if result.succeeded else [])
            if self._held and len(self._held) == result.failed:
                one = len(self._held) == 1
                title = HELD_COPY["title_one"] if one else HELD_COPY["title_many"].format(count=len(self._held))
                self.result_bar.show_message("warning", title, HELD_COPY["detail_one" if one else "detail_many"],
                                             actions=actions)
                self.open_button.setVisible(not result.succeeded)
                return
            reasons = set(self._failures)
            detail = self._failures[0] if len(reasons) == 1 else "See the Status column for the reason for each file."
            title = (f"{result.failed} of {plural(total)} failed" if result.succeeded
                     else "The archive wasn't made" if self._job_archive
                     else f"{'That file' if total == 1 else f'All {total} files'} failed")
            self.result_bar.show_message("error", title, detail, actions=actions)
        elif self._left_out:
            left = len(self._left_out)
            title = (DOUBTFUL_COPY["result_title"].format(files=plural(result.succeeded), count=left)
                     if result.succeeded else DOUBTFUL_COPY["result_none"])
            detail = DOUBTFUL_COPY["result_one" if left == 1 else "result_many"]
            self.result_bar.show_message("warning", title, detail, actions=[open_folder] if result.succeeded else [])
        elif result.succeeded:
            if self._job_archive:
                title = ARCHIVE_COPY["result_title"].format(files=plural(result.succeeded))
                detail = ARCHIVE_COPY["result_detail"].format(name=result.outputs[0].name)
                checked_words = ARCHIVE_COPY["result_checked"]
            else:
                title = copy["result_title"].format(files=plural(result.succeeded))
                detail = copy["result_detail"]
                checked_words = CHECK_COPY["result_one" if result.succeeded == 1 else "result_many"]
            if self._job_algorithm:
                title += f" with {self._job_algorithm}"
            if self._job_signer:
                # Both titles say "encrypted" once.
                title = title.replace("encrypted", "signed and encrypted", 1)
            if result.checked == result.succeeded:
                title += " and checked"
                detail = f"{checked_words} {detail}"
            elif self._job_not_checked:
                detail = f"{self._job_not_checked} {detail}"
            restored = [self._findings[row] for row in self._succeeded_rows if row in self._findings]
            doubtful = [finding for finding in restored if finding.is_warning]
            if doubtful:
                self.result_bar.show_message(
                    "warning", f"{title}, but {len(doubtful)} {'is' if len(doubtful) == 1 else 'are'} not the "
                               f"{'copy' if len(doubtful) == 1 else 'copies'} you made",
                    f"{doubtful[0].message} Compare with your other copies before relying on "
                    f"{'it' if len(doubtful) == 1 else 'them'}. The Status column says which.",
                    actions=[open_folder],
                )
                self.open_button.setVisible(False)
                return
            if restored and len(restored) == result.succeeded and all(f.verdict == "match" for f in restored):
                detail = f"{RECORD_WORDS['all_match']} {detail}"
            who, caution = self._signature_summary()
            if who:
                detail = f"{who} {detail}"
            self.result_bar.show_message("warning" if caution else "success", title, detail, actions=[open_folder])
        self.open_button.setVisible(not result.succeeded)

    def _restore_held(self):
        """Restore the files held back for want of a signature, once someone has seen what each showed and agreed."""
        rows = [row for row in self._held if row < len(self.items) and row in self._verifications]
        if self.running or not rows:
            return

        def why(row: int) -> str:
            verification = self._verifications[row]
            words = signatures.headline(verification)
            signer = verification.signer
            if signer is not None and signer.primary_fingerprint:
                # A key's name proves nothing, so it's the fingerprint that's shown.
                words = HELD_COPY["key"].format(why=words, key=signatures.spaced(signer.primary_fingerprint))
            return words

        listed = [HELD_COPY["row_listed"].format(name=self.items[row].source.name, why=why(row)) for row in rows[:8]]
        if len(rows) > 8:
            listed.append(f"• and {len(rows) - 8} more")
        one = len(rows) == 1
        title = HELD_COPY["confirm_one"] if one else HELD_COPY["confirm_many"].format(count=len(rows))
        text = HELD_COPY["text_one" if one else "text_many"].format(listed="\n".join(listed))
        text += "\n\n" + HELD_COPY["hint" if self.advanced() else "hint_simple"]
        if not self._confirm(title, text):
            return
        shown = {position: self._verifications[row] for position, row in enumerate(rows)}
        previous = self.items, self._source_paths
        self.items, self._source_paths = [self.items[row] for row in rows], []
        self.start(accepted=shown)
        if not self.running:
            # It didn't start, such as when a file has gone, so the list stays as it was.
            self.items, self._source_paths = previous

    @Slot(str)
    def _error(self, message: str):
        self.running = False
        self._set_busy(False)
        self.status_text.setText("")
        self._update_primary()
        self.result_bar.show_message("error", "That didn't work", message)
        QMessageBox.critical(self, "Operation failed", message)

    def cancel(self):
        if self.worker and self.running:
            self.worker.cancel_event.set()
            self.cancel_button.setEnabled(False)
            self.status_text.setText("Cancelling after the current file…")

    def open_paths(self, paths: list[str]) -> bool:
        """Put files chosen in File Explorer on the Encrypt screen. Nothing is encrypted yet.

        Returns False while a job is running, because the list can't change then.
        """
        if self.running:
            return False
        self.set_operation("encrypt")
        self.add_paths([path for path in paths if Path(path).exists()])
        if self.isMinimized():
            self.showNormal()
        self.raise_()
        self.activateWindow()
        return True

    def nativeEvent(self, event_type, message):
        """Receive files handed over by another copy of the app. See gui/handover.py.

        While a job runs, this says no, and the other copy opens a window of its own, so that
        right-clicking a file still does something straight away.
        """
        if handover.IS_WINDOWS and bytes(event_type) == b"windows_generic_MSG":
            paths = handover.read_message(int(message))
            if paths is not None:
                if self.running or not paths:
                    return True, 0
                # Answer first: the sender is waiting, and adding files can show a message box.
                QTimer.singleShot(0, lambda: self._open_when_ready(paths))
                return True, 1
        return super().nativeEvent(event_type, message)

    def _open_when_ready(self, paths: list[str]) -> None:
        """Add handed-over files once no dialog is open and no job is running.

        Files must never join a list that someone is already confirming or encrypting, such as
        while the passphrase dialog is open. Waiting, rather than refusing, also keeps a burst of
        files from Explorer from opening a window each while one message box is showing.
        """
        if self.running or QApplication.activeModalWidget() is not None:
            QTimer.singleShot(250, lambda: self._open_when_ready(paths))
            return
        self.open_paths(paths)

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
        self.journal.close()
        stop_bundled_gnupg(self.gpg)
        event.accept()


def _show_unexpected_error(exc_type, exc, tb) -> None:
    """pythonw has no console, so without this any crash would just vanish."""
    if sys.stderr:
        traceback.print_exception(exc_type, exc, tb)
    QMessageBox.critical(
        None, "Unexpected error",
        f"{exc_type.__name__}: {exc}\n\nPlease report this on GitHub, without including any private data.",
    )


def _use_own_taskbar_icon() -> None:
    """Without this, Windows groups the app under Python and shows Python's icon."""
    if sys.platform == "win32":
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("mindyourownbytes.app")



def create_application() -> QApplication:
    _use_own_taskbar_icon()
    app = QApplication(sys.argv)
    app.setApplicationName("mindyourownbytes")
    app.setOrganizationName("mindyourownbytes")
    app.setWindowIcon(icons.app_icon())
    theme.configure_application(app)
    return app


def main():
    # Files chosen with "Encrypt with mindyourownbytes" in File Explorer arrive here.
    paths = handover.paths_from(sys.argv[1:])
    if handover.mark_as_running() and handover.hand_over(paths):
        return
    app = create_application()
    sys.excepthook = _show_unexpected_error
    window = MainWindow()
    window.show()
    handover.announce_window(int(window.winId()))
    if paths:
        window.open_paths(paths)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
