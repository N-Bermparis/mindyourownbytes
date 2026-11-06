"""Dialogs that collect secrets. Nothing here stores or logs what is typed."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes.core import encode_passphrase
from mindyourownbytes.vault import generate_passphrase

#: Below this, a typed passphrase gets a warning. Not a hard rule, because length
#: alone says little, but it catches the most common mistake.
RECOMMENDED_LENGTH = 14


def _password_field(placeholder: str = "") -> QLineEdit:
    field = QLineEdit()
    field.setEchoMode(QLineEdit.EchoMode.Password)
    field.setPlaceholderText(placeholder)
    return field


class PassphraseDialog(QDialog):
    """Ask for a passphrase once, optionally twice to catch typing mistakes."""

    def __init__(self, parent: QWidget | None, title: str, message: str, *,
                 confirm: bool = False, min_length: int = 1) -> None:
        super().__init__(parent)
        self._confirm = confirm
        self._min_length = min_length
        self.setWindowTitle(title)
        self.setMinimumWidth(460)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        text = QLabel(message)
        text.setWordWrap(True)
        layout.addWidget(text)

        self.first = _password_field("Passphrase")
        layout.addWidget(self.first)
        self.second = _password_field("Repeat passphrase")
        self.second.setVisible(confirm)
        layout.addWidget(self.second)

        self.show_box = QCheckBox("Show what I type")
        self.show_box.toggled.connect(self._toggle_echo)
        layout.addWidget(self.show_box)

        self.hint = QLabel()
        self.hint.setObjectName("hintLabel")
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.first.textChanged.connect(self._validate)
        self.second.textChanged.connect(self._validate)
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
        if value != value.strip():
            return True, "Note: this starts or ends with a space, which you will need to type every time."
        if self._confirm and len(value) < RECOMMENDED_LENGTH:
            return True, "This is short enough to be guessed. Five or more random words is far stronger."
        return True, ""

    def _validate(self) -> None:
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
        self.setWindowTitle("Save a passphrase")
        self.setMinimumWidth(500)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.label = QLineEdit()
        self.label.setPlaceholderText("e.g. Taxes, Medical, Work")
        form.addRow("Name", self.label)

        row = QHBoxLayout()
        self.passphrase_field = _password_field()
        row.addWidget(self.passphrase_field)
        self.generate_button = QPushButton("Generate")
        self.generate_button.setToolTip("Create a strong random passphrase (about 147 bits)")
        self.generate_button.clicked.connect(self._generate)
        row.addWidget(self.generate_button)
        form.addRow("Passphrase", row)

        self.note = QLineEdit()
        self.note.setPlaceholderText("Optional. Stored inside the encrypted vault.")
        form.addRow("Note", self.note)
        layout.addLayout(form)

        self.show_box = QCheckBox("Show passphrase")
        self.show_box.toggled.connect(self._toggle_echo)
        layout.addWidget(self.show_box)

        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        self.label.textChanged.connect(self._validate)
        self.passphrase_field.textChanged.connect(self._validate)
        self._validate()

    def _toggle_echo(self, visible: bool) -> None:
        self.passphrase_field.setEchoMode(QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password)

    def _generate(self) -> None:
        self.passphrase_field.setText(generate_passphrase())
        self.show_box.setChecked(True)

    def _validate(self) -> None:
        self.buttons.button(QDialogButtonBox.StandardButton.Save).setEnabled(
            bool(self.label.text().strip()) and bool(self.passphrase_field.text())
        )

    def values(self) -> tuple[str, str, str]:
        return self.label.text(), self.passphrase_field.text(), self.note.text()
