"""What your cloud provider can and can't see: the same files, as you see them and as they do."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from PySide6.QtGui import QBrush
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes.core import SourceItem, output_relative
from mindyourownbytes.gui import icons, theme
from mindyourownbytes.gui.widgets import configure_table, human_size, label
from mindyourownbytes.library import LibraryEntry

#: How many of an encrypted file's bytes to show. Enough to see that they mean nothing.
SAMPLE_BYTES = 16


@dataclass(frozen=True)
class Shown:
    """One file, both ways."""

    #: The file as you know it, and its folder, "" for none.
    name: str
    folder: str
    size: int
    #: Where your provider gets it, with its folders, such as "Taxes/return.pdf.gpg".
    stored_as: str
    #: The encrypted file, if it exists already, so that its real first bytes can be shown.
    encrypted: Path | None = None

    @property
    def stored_name(self) -> str:
        return PurePosixPath(self.stored_as).name

    @property
    def stored_folder(self) -> str:
        parent = str(PurePosixPath(self.stored_as).parent)
        return "" if parent == "." else parent


#: Shown when there's nothing of yours to show yet.
EXAMPLES = (
    Shown("divorce-settlement.pdf", "Legal", 482_100, "Legal/divorce-settlement.pdf.gpg"),
    Shown("scan-001.jpg", "Medical", 1_153_434, "Medical/scan-001.jpg.gpg"),
    Shown("notes.txt", "", 2_048, "notes.txt.gpg"),
)

CAN_SEE = (
    "File names, exactly as they are, with .gpg added",
    "Folder and collection names",
    "Roughly how big each file is",
    "Which algorithm protects a passphrase file, such as AES-256",
    "How many files there are, and when you upload or change them",
    "With an OpenPGP key, which key the files are for, by its ID",
    "Your account, and the internet address you upload from",
)
CANNOT_SEE = (
    "What's inside any file: its text, pictures, or anything else",
    "Your passphrase or your private key, which never leave this computer",
    "Your saved passphrases, which are encrypted again under your master passphrase",
)


def from_items(items: Iterable[SourceItem], collection: str = "") -> list[Shown]:
    """Files about to be encrypted, from the Encrypt screen's list."""
    shown = []
    for item in items:
        stored = output_relative(item, "encrypt").as_posix()
        folder = item.relative.parent.as_posix()
        shown.append(Shown(item.source.name, "" if folder == "." else folder, item.size,
                           f"{collection}/{stored}" if collection else stored))
    return shown


def from_library(entries: Iterable[LibraryEntry]) -> list[Shown]:
    """Files already encrypted, from the Library."""
    shown = []
    for entry in entries:
        folder = entry.relative.parent.as_posix()
        shown.append(Shown(entry.display_name, "" if folder == "." else folder, entry.size,
                           entry.relative.as_posix(), entry.path))
    return shown


def sample_bytes(path: Path | None) -> str:
    """Real bytes from the middle of an encrypted file, in hex, which is all its contents look like to others.

    From the middle, because every file starts with the same short header, which only says how it's
    protected, and would make the contents look less random than they are.
    """
    if path is None:
        return ""
    try:
        with open(path, "rb") as file:
            size = file.seek(0, 2)
            file.seek(size // 2 if size > 4 * SAMPLE_BYTES else 0)
            data = file.read(SAMPLE_BYTES)
    except OSError:
        return ""
    return "… " + " ".join(f"{byte:02x}" for byte in data) + " …" if data else ""


class ProviderView(QDialog):
    def __init__(self, parent: QWidget | None, files: Sequence[Shown] = ()) -> None:
        super().__init__(parent)
        self.examples = not files
        self.files = list(files or EXAMPLES)
        self.setWindowTitle("What your provider sees")
        self.setMinimumSize(720, 520)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)

        layout.addWidget(label("The same files, two ways", "stepTitle"))
        layout.addWidget(label(
            ("Some example files" if self.examples else "Your files") + ". Switch between your view and your "
            "provider's, and see what changes and what doesn't.", "muted", wrap=True))
        switch = QHBoxLayout()
        switch.setSpacing(0)
        self.views = QButtonGroup(self)
        self.yours = QPushButton("As you see them")
        self.theirs = QPushButton("As your provider sees them")
        for button in (self.yours, self.theirs):
            button.setCheckable(True)
            self.views.addButton(button)
            switch.addWidget(button)
        switch.addStretch(1)
        layout.addLayout(switch)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Name", "Folder", "Size", "What's inside"])
        configure_table(self.table, stretch=(0, 3), multi_select=False)
        self.table.setAccessibleName("Files")
        layout.addWidget(self.table, stretch=1)
        self.caption = label("", "muted", wrap=True)
        layout.addWidget(self.caption)

        lists = QHBoxLayout()
        lists.setSpacing(24)
        for title, lines, icon, color in (("Your provider can see", CAN_SEE, "alert", "warn"),
                                          ("Your provider can't see", CANNOT_SEE, "encrypt", "ok")):
            column = QVBoxLayout()
            column.setSpacing(4)
            column.addWidget(label(title, "stepTitle"))
            for line in lines:
                column.addWidget(self._point(line, icon, color))
            column.addStretch(1)
            lists.addLayout(column, stretch=1)
        layout.addLayout(lists)
        layout.addWidget(label("Names say a lot, so keep them vague. Encryption hides what's inside, not what "
                               "a file is called.", wrap=True))

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.views.buttonToggled.connect(lambda _button, checked: checked and self.render())
        self.theirs.setChecked(True)

    @staticmethod
    def _point(text: str, icon_name: str, color_name: str) -> QWidget:
        row = QWidget()
        line = QHBoxLayout(row)
        line.setContentsMargins(0, 0, 0, 0)
        line.setSpacing(6)
        mark = QLabel()
        mark.setPixmap(icons.pixmap(icon_name, 14, theme.color(color_name)))
        line.addWidget(mark)
        words = QLabel(text)
        words.setWordWrap(True)
        line.addWidget(words, stretch=1)
        return row

    def providers_view(self) -> bool:
        return self.theirs.isChecked()

    def render(self) -> None:
        theirs = self.providers_view()
        visible, hidden = theme.color("warn"), theme.color("ok")
        self.table.setRowCount(len(self.files))
        for row, shown in enumerate(self.files):
            if theirs:
                sample = sample_bytes(shown.encrypted)
                cells = (
                    (shown.stored_name, visible, "Your provider can see this name."),
                    (shown.stored_folder or "—", visible, "Your provider can see this folder."),
                    (f"about {human_size(shown.size)}", visible, "Your provider can see roughly how big it is."),
                    (f"{sample} (unreadable)" if sample else "Unreadable once encrypted", hidden,
                     "Encrypted: your provider can't read this. These are real bytes from the middle of the file."
                     if sample else "Encrypted: your provider can't read this."),
                )
            else:
                cells = ((shown.name, None, ""), (shown.folder or "—", None, ""), (human_size(shown.size), None, ""),
                         ("Readable, on this computer", None, ""))
            for column, (text, color, tip) in enumerate(cells):
                cell = QTableWidgetItem(text)
                if color is not None:
                    cell.setForeground(QBrush(color))
                cell.setToolTip(tip or text)
                self.table.setItem(row, column, cell)
        self.caption.setText(
            "Orange is what they can see. Green is what they can't." if theirs
            else "This is how they look on your computer, before they're encrypted or after they're restored.")
