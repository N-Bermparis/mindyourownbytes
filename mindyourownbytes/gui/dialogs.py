"""Dialogs. The ones that collect secrets never store or log what is typed."""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes import generator
from mindyourownbytes.core import encode_passphrase

#: Below this, a typed passphrase gets a warning. Not a hard rule, because length
#: alone says little, but it catches the most common mistake.
RECOMMENDED_LENGTH = 14

THREAT_MODEL_URL = "https://github.com/N-Bermparis/mindyourownbytes/blob/main/docs/THREAT_MODEL.md"


def _password_field() -> QLineEdit:
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    return field


class GeneratorRow(QWidget):
    """Pick words or characters, generate, and say exactly how strong the result is."""

    def __init__(self, on_generated: Callable[[str], None]) -> None:
        super().__init__()
        self._on_generated = on_generated
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        row = QHBoxLayout()
        row.setSpacing(6)
        row.addWidget(QLabel("Or let your computer pick one:"))
        self.kind = QComboBox()
        self.kind.setAccessibleName("Kind of passphrase to generate")
        self.kind.addItem("Random words, easy to type", "words")
        self.kind.addItem("Random letters and digits, strongest", "characters")
        row.addWidget(self.kind, stretch=1)
        self.button = QPushButton("Generate")
        self.button.setToolTip("Uses your computer's secure random numbers")
        self.button.clicked.connect(self.generate)
        row.addWidget(self.button)
        layout.addLayout(row)
        self.strength = QLabel()
        # Muted, not a warning: it's good news.
        self.strength.setObjectName("muted")
        self.strength.setWordWrap(True)
        self.strength.hide()
        layout.addWidget(self.strength)

    def generate(self) -> None:
        kind = self.kind.currentData()
        try:
            passphrase = generator.generate(kind)
        except (OSError, RuntimeError) as exc:
            QMessageBox.warning(self, "Couldn't generate a passphrase", str(exc))
            return
        self.strength.setText(generator.describe(kind))
        self.strength.show()
        self._on_generated(passphrase)

    def forget(self) -> None:
        """The passphrase was changed by hand, so its strength is no longer known."""
        self.strength.hide()


class PassphraseDialog(QDialog):
    """Ask for a passphrase once, optionally twice to catch typing mistakes."""

    def __init__(self, parent: QWidget | None, title: str, message: str, *,
                 confirm: bool = False, min_length: int = 1, ok_text: str = "OK") -> None:
        super().__init__(parent)
        self._confirm = confirm
        self._min_length = min_length
        self.setWindowTitle(title)
        self.setMinimumWidth(480)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)
        text = QLabel(message)
        text.setWordWrap(True)
        layout.addWidget(text)

        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)
        self.first = _password_field()
        self.first.setAccessibleName("Passphrase")
        form.addRow("Passphrase", self.first)
        self.second = _password_field()
        self.second.setAccessibleName("Repeat passphrase")
        if confirm:
            form.addRow("Repeat it", self.second)
        else:
            self.second.hide()
        layout.addLayout(form)

        self.show_box = QCheckBox("Show what I type")
        self.show_box.toggled.connect(self._toggle_echo)
        layout.addWidget(self.show_box)

        #: The passphrase the generator filled in, while it's still what the fields hold.
        self._generated = ""
        self.generator: GeneratorRow | None = None
        self.saved_box = QCheckBox("I've saved this passphrase somewhere safe, such as my Passphrases list or on paper")
        self.saved_box.hide()
        if confirm:
            # Only when choosing a new passphrase. There's nothing to generate when entering one.
            self.generator = GeneratorRow(self._use_generated)
            layout.addWidget(self.generator)
            self.saved_box.toggled.connect(self._validate)
            layout.addWidget(self.saved_box)

        self.hint = QLabel()
        self.hint.setObjectName("hintLabel")
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText(ok_text)
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setProperty("variant", "primary")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.first.textChanged.connect(self._validate)
        self.second.textChanged.connect(self._validate)
        self._validate()
        self.first.setFocus()

    def _use_generated(self, passphrase: str) -> None:
        self._generated = passphrase
        self.first.setText(passphrase)
        self.second.setText(passphrase)
        self.show_box.setChecked(True)
        self.saved_box.setChecked(False)
        self._validate()

    def _toggle_echo(self, visible: bool) -> None:
        mode = QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
        self.first.setEchoMode(mode)
        self.second.setEchoMode(mode)

    def _problem(self) -> tuple[bool, str]:
        """Return (acceptable, message to show)."""
        value = self.first.text()
        if not value:
            return False, ""
        try:
            encode_passphrase(value)
        except ValueError as exc:
            return False, str(exc)
        if len(value) < self._min_length:
            return False, f"Use at least {self._min_length} characters."
        if self._confirm and value != self.second.text():
            return False, "Type the same passphrase in both boxes." if self.second.text() else ""
        if self._is_generated() and not self.saved_box.isChecked():
            return False, "Save it before you continue. Nobody can recover it for you, including this app."
        if value != value.strip():
            return True, "Note: this starts or ends with a space, which you will need to type every time."
        if self._confirm and len(value) < RECOMMENDED_LENGTH:
            return True, "This is short enough to be guessed. Five or more random words is far stronger."
        return True, ""

    def _is_generated(self) -> bool:
        return bool(self._generated) and self.first.text() == self._generated

    def _validate(self) -> None:
        generated = self._is_generated()
        self.saved_box.setVisible(generated)
        if self.generator is not None and not generated:
            self.generator.forget()
        acceptable, message = self._problem()
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(acceptable)
        self.hint.setText(message)
        self.hint.setVisible(bool(message))

    def passphrase(self) -> str:
        return self.first.text()


class VaultEntryDialog(QDialog):
    """Name a passphrase, then type it or generate a strong random one."""

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add a passphrase")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)
        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(8)
        self.label = QLineEdit()
        self.label.setPlaceholderText("For example: Taxes, Medical, Work")
        form.addRow("Name", self.label)

        self.passphrase_field = _password_field()
        self.passphrase_field.setAccessibleName("Passphrase")
        form.addRow("Passphrase", self.passphrase_field)
        self._generated = ""
        self.generator = GeneratorRow(self._use_generated)
        self.generate_button = self.generator.button
        form.addRow("", self.generator)

        self.note = QLineEdit()
        self.note.setPlaceholderText("Optional. Stored inside the encrypted vault.")
        form.addRow("Note", self.note)
        layout.addLayout(form)

        self.show_box = QCheckBox("Show passphrase")
        self.show_box.toggled.connect(self._toggle_echo)
        layout.addWidget(self.show_box)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.button(QDialogButtonBox.StandardButton.Save).setProperty("variant", "primary")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.label.textChanged.connect(self._validate)
        self.passphrase_field.textChanged.connect(self._validate)
        self._validate()

    def _toggle_echo(self, visible: bool) -> None:
        self.passphrase_field.setEchoMode(QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password)

    def _use_generated(self, passphrase: str) -> None:
        self._generated = passphrase
        self.passphrase_field.setText(passphrase)
        self.show_box.setChecked(True)

    def _validate(self) -> None:
        if self.passphrase_field.text() != self._generated:
            self.generator.forget()
        self.buttons.button(QDialogButtonBox.StandardButton.Save).setEnabled(
            bool(self.label.text().strip()) and bool(self.passphrase_field.text())
        )

    def values(self) -> tuple[str, str, str]:
        return self.label.text(), self.passphrase_field.text(), self.note.text()


class ProtectionDialog(QDialog):
    """What this tool does and doesn't protect, in plain language."""

    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setWindowTitle("What this protects")
        self.setMinimumWidth(540)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)
        text = QLabel(
            "<p style='font-weight:600'>Protected</p>"
            "<p>The contents of your files, from your cloud provider and from anyone who gets a copy of "
            "your cloud data, as long as your passphrase is strong.</p>"
            "<p style='font-weight:600'>Not protected</p>"
            "<ul style='margin-left:-20px'>"
            "<li><b>File and folder names, and approximate sizes.</b> Your provider can still see these, "
            "so keep names vague.</li>"
            "<li><b>Files already in a synced folder.</b> If your originals are in OneDrive or Dropbox, "
            "your provider probably has them already.</li>"
            "<li><b>Old or deleted copies.</b> A provider could delete a file, or show you an old version. "
            "Keep other backups.</li>"
            "<li><b>A computer with malware.</b> It can read whatever you can.</li>"
            "</ul>"
            "<p style='font-weight:600'>If you lose your passphrase or key</p>"
            "<p>Nobody can recover your files. Keep a copy somewhere safe that isn't the cloud you're "
            "protecting against.</p>"
            "<p style='font-weight:600'>How far to trust this</p>"
            "<p>This is an early version that hasn't been independently audited, so don't make it the only "
            "protection for anything important yet. All the encryption is done by GnuPG, and your files "
            "open with plain GnuPG, with or without this app.</p>"
            f"<p><a href='{THREAT_MODEL_URL}'>Read the full threat model</a></p>"
        )
        text.setWordWrap(True)
        text.setOpenExternalLinks(True)
        layout.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
