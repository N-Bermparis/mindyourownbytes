"""The post-quantum assistant: what this GnuPG can do, which keys are ready, and what it costs.

GnuPG does all the work. Any passphrase a key needs is asked for in GnuPG's own window, so this
app never sees it, and nothing here reads or exports a private key.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QProcess, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes.core import (
    KEY_VALIDITY,
    POST_QUANTUM_GPG_VERSION,
    GpgFailure,
    PublicKey,
    add_post_quantum_subkey,
    create_post_quantum_key,
    find_kleopatra,
    gpg_version,
    is_post_quantum,
    list_public_keys,
    supports_post_quantum,
    user_id,
)
from mindyourownbytes.gui.widgets import configure_table, label

NEEDED = ".".join(map(str, POST_QUANTUM_GPG_VERSION[:2]))
YEARS = KEY_VALIDITY.removesuffix("y")

#: What to know before using a post-quantum key, in plain words.
EXPLANATIONS = (
    ("Why", "A powerful enough quantum computer could one day break the ordinary keys most people use. "
            "Someone could save your files now and open them then, which is why it matters today. A "
            "post-quantum key adds a part designed to resist that, combined with an ordinary part, so it's "
            "at least as strong as an ordinary key."),
    ("Who can open the files", f"Only GnuPG {NEEDED} or later, on every computer where you'll restore them, "
                               "like the one included with this app's Windows download. Older GnuPG can't. "
                               "As of this writing, other OpenPGP apps use a different post-quantum design, or "
                               "none, so don't count on them opening these files."),
    ("Back it up", "Files encrypted to a key can only be opened with its private key. Export a backup of it "
                   "in Kleopatra, and keep it somewhere other than your cloud."),
    ("Passphrases don't need this", "Files protected with a passphrase use AES-256, which is already "
                                    "considered safe against quantum computers. Only keys need a "
                                    "post-quantum part."),
)


class _KeyJob(QThread):
    """Runs one GnuPG key command away from the window, which stays responsive while GnuPG asks."""

    done = Signal(object, object)

    def __init__(self, work: Callable[[], str]) -> None:
        super().__init__()
        self._work = work

    def run(self) -> None:
        try:
            self.done.emit(self._work(), None)
        except (GpgFailure, ValueError, OSError) as exc:
            self.done.emit(None, exc)


class NewKeyDialog(QDialog):
    """Ask for the name, and optionally the email, that a new key will carry."""

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Create a post-quantum key")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)
        layout.addWidget(label(
            "Others will see this name and email when they encrypt files for you. They're stored in the key, "
            f"not checked by anyone. The key lasts {YEARS} years, and Kleopatra can extend it.", wrap=True))
        form = QFormLayout()
        self.name = QLineEdit()
        self.name.setPlaceholderText("For example: Alex Example")
        form.addRow("Name", self.name)
        self.email = QLineEdit()
        self.email.setPlaceholderText("Optional")
        form.addRow("Email", self.email)
        layout.addLayout(form)
        layout.addWidget(label("Next, GnuPG asks for a passphrase to protect the new key, in its own window.",
                               "muted", wrap=True))
        self.problem = label("", "hintLabel", wrap=True)
        layout.addWidget(self.problem)
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Create key")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("variant", "primary")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.name.textChanged.connect(self._validate)
        self.email.textChanged.connect(self._validate)
        self._validate()

    def _validate(self) -> None:
        try:
            user_id(self.name.text(), self.email.text())
            message, acceptable = "", True
        except ValueError as exc:
            message, acceptable = (str(exc) if self.name.text().strip() else ""), False
        self.problem.setText(message)
        self.problem.setVisible(bool(message))
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(acceptable)

    def uid(self) -> str:
        return user_id(self.name.text(), self.email.text())


class PostQuantumDialog(QDialog):
    #: Keys were added or changed, so lists of keys elsewhere need refreshing.
    keys_changed = Signal()

    def __init__(self, parent: QWidget | None, gpg: str) -> None:
        super().__init__(parent)
        self.gpg = gpg
        self.keys: list[PublicKey] = []
        self._job: _KeyJob | None = None
        self.setWindowTitle("Post-quantum keys")
        self.setMinimumWidth(640)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)

        self.status = label("", "stepTitle", wrap=True)
        layout.addWidget(self.status)
        self.status_detail = label("", "muted", wrap=True)
        layout.addWidget(self.status_detail)

        layout.addWidget(label("Your keys", "stepTitle"))
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Key", "Type", "Post-quantum"])
        configure_table(self.table, stretch=(0,), multi_select=False)
        self.table.setAccessibleName("Your keys")
        self.table.setMinimumHeight(120)
        self.table.itemSelectionChanged.connect(self._update_buttons)
        layout.addWidget(self.table)
        actions = QHBoxLayout()
        actions.setSpacing(8)
        self.add_button = QPushButton("Add a post-quantum part")
        self.add_button.setToolTip("Files you encrypt to the selected key from then on get a post-quantum part")
        self.add_button.clicked.connect(self.add_to_selected)
        actions.addWidget(self.add_button)
        self.create_button = QPushButton("Create a new key…")
        self.create_button.clicked.connect(self.create_key)
        actions.addWidget(self.create_button)
        actions.addStretch(1)
        self.kleopatra_button = QPushButton("Open Kleopatra to back up keys")
        self.kleopatra_button.clicked.connect(self._open_kleopatra)
        self.kleopatra_button.setVisible(find_kleopatra() is not None)
        actions.addWidget(self.kleopatra_button)
        layout.addLayout(actions)
        self.working = label("", "muted", wrap=True)
        layout.addWidget(self.working)

        layout.addWidget(label("Before you use one", "stepTitle"))
        for title, text in EXPLANATIONS:
            item = QLabel(f"<b>{title}.</b> {text}")
            item.setWordWrap(True)
            item.setTextFormat(Qt.TextFormat.RichText)
            layout.addWidget(item)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.refresh()

    def refresh(self) -> None:
        self.supported = bool(self.gpg) and supports_post_quantum(self.gpg)
        version = gpg_version(self.gpg) if self.gpg else None
        shown = ".".join(map(str, version)) if version else "not found"
        if self.supported:
            self.status.setText(f"This GnuPG ({shown}) can make post-quantum keys.")
            self.status_detail.setText("You can create a new key, or add a post-quantum part to one of yours. "
                                       "Encrypting to it then works like any other key.")
        else:
            self.status.setText(f"This GnuPG ({shown}) can't make post-quantum keys.")
            self.status_detail.setText(f"GnuPG {NEEDED} or later can, like the one included with this app's "
                                       "Windows download. You can still read about them below.")
        try:
            self.keys = [key for key in list_public_keys(self.gpg) if key.has_secret] if self.gpg else []
        except (OSError, ValueError):
            self.keys = []
        self.table.setRowCount(len(self.keys))
        for row, key in enumerate(self.keys):
            name = QTableWidgetItem(key.uid)
            name.setToolTip(key.fingerprint)
            self.table.setItem(row, 0, name)
            self.table.setItem(row, 1, QTableWidgetItem(key.algorithm or "Unknown"))
            self.table.setItem(row, 2, QTableWidgetItem("Yes" if is_post_quantum(key) else "No"))
        self._update_buttons()

    def selected_key(self) -> PublicKey | None:
        rows = {index.row() for index in self.table.selectedIndexes()}
        return self.keys[min(rows)] if rows else None

    def _update_buttons(self) -> None:
        busy = self._job is not None
        key = self.selected_key()
        self.create_button.setEnabled(self.supported and not busy)
        self.add_button.setEnabled(self.supported and not busy and key is not None and not is_post_quantum(key))

    def create_key(self) -> None:
        dialog = NewKeyDialog(self)
        if not dialog.exec():
            return
        uid = dialog.uid()
        self._start(lambda: create_post_quantum_key(self.gpg, uid),
                    "GnuPG is making the key. It asks for a passphrase to protect it in its own window.",
                    "Key created", f"Created a post-quantum key for “{uid}”. Choose it under OpenPGP key when you "
                    "encrypt. Back it up in Kleopatra before you rely on it.")

    def add_to_selected(self) -> None:
        key = self.selected_key()
        if key is None:
            return
        answer = QMessageBox.question(
            self, "Add a post-quantum part?",
            f"Files you encrypt to “{key.uid}” from now on will only open with GnuPG {NEEDED} or later, on every "
            "computer where you restore them. Files you've already encrypted don't change.\n\nAnyone else who "
            "encrypts files for you needs your updated public key to use the new part. GnuPG will ask for "
            "this key's passphrase in its own window.\n\nAdd it?",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self._start(lambda: add_post_quantum_subkey(self.gpg, key.fingerprint),
                    "GnuPG is adding the post-quantum part, and may ask for the key's passphrase in its own window.",
                    "Post-quantum part added",
                    f"“{key.uid}” now has a post-quantum part, which GnuPG uses for files you encrypt to it from "
                    "now on. Back up the key again in Kleopatra, because the backup you have doesn't include it.")

    def _start(self, work: Callable[[], str], waiting: str, title: str, success: str) -> None:
        self._job = _KeyJob(work)
        self._job.done.connect(lambda result, problem: self._finished(result, problem, title, success))
        self.working.setText(waiting)
        self._update_buttons()
        self._job.start()

    def _finished(self, result: str | None, problem: Exception | None, title: str, success: str) -> None:
        job, self._job = self._job, None
        if job is not None:
            job.wait(5000)
        self.working.setText("")
        self.refresh()
        if problem is not None:
            QMessageBox.warning(self, "No key was made" if "key" in title.lower() else "Nothing was added",
                                str(problem))
            return
        self.keys_changed.emit()
        QMessageBox.information(self, title, success)

    def _open_kleopatra(self) -> None:
        path = find_kleopatra()
        if path:
            QProcess.startDetached(path, [])

    def reject(self) -> None:
        if self._job is not None:
            QMessageBox.information(self, "GnuPG is still working", "Finish or cancel GnuPG's window first.")
            return
        super().reject()
