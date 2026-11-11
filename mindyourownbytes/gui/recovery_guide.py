"""Help > Restore on another computer: the recovery steps, one at a time, and a copy to keep."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtGui import QFont, QGuiApplication
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes import recovery
from mindyourownbytes.gui.widgets import action_button, label


def this_platform() -> recovery.Platform:
    if sys.platform == "win32":
        return "windows"
    return "macos" if sys.platform == "darwin" else "linux"


class RecoveryGuide(QDialog):
    def __init__(self, parent: QWidget | None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Restore on another computer")
        self.setMinimumSize(620, 460)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)

        top = QHBoxLayout()
        top.addWidget(label("Your files are standard OpenPGP files, so GnuPG opens them with or without this app. "
                            "The other computer runs:", wrap=True), stretch=1)
        self.platform = QComboBox()
        self.platform.setAccessibleName("The other computer's system")
        for key, name in recovery.PLATFORMS.items():
            self.platform.addItem(name, key)
        self.platform.setCurrentIndex(self.platform.findData(this_platform()))
        self.platform.currentIndexChanged.connect(self._build_pages)
        top.addWidget(self.platform)
        layout.addLayout(top)

        self.position = label("", "muted")
        layout.addWidget(self.position)
        self.pages = QStackedWidget()
        layout.addWidget(self.pages, stretch=1)

        buttons = QHBoxLayout()
        self.save_button = action_button("Save these steps…")
        self.save_button.setToolTip("A text file with every step, to keep beside your backups. It holds no secrets.")
        self.save_button.clicked.connect(self.save)
        buttons.addWidget(self.save_button)
        buttons.addStretch(1)
        self.back_button = action_button("Back")
        self.back_button.clicked.connect(lambda: self.go(-1))
        buttons.addWidget(self.back_button)
        self.next_button = action_button("Next", "primary")
        self.next_button.clicked.connect(self._next_or_close)
        buttons.addWidget(self.next_button)
        layout.addLayout(buttons)
        self._build_pages()

    def chosen(self) -> recovery.Platform:
        return self.platform.currentData()

    def _build_pages(self) -> None:
        current = self.pages.currentIndex()
        while self.pages.count():
            page = self.pages.widget(0)
            self.pages.removeWidget(page)
            page.deleteLater()
        for step in recovery.steps(self.chosen()):
            self.pages.addWidget(self._page(step))
        self.pages.setCurrentIndex(max(current, 0))
        self._update_buttons()

    def _page(self, step: recovery.Step) -> QWidget:
        page = QWidget()
        column = QVBoxLayout(page)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(8)
        column.addWidget(label(step.title, "stepTitle"))
        for paragraph in step.text:
            text = QLabel(paragraph)
            text.setWordWrap(True)
            column.addWidget(text)
        mono = QFont("Consolas" if sys.platform == "win32" else "monospace")
        for command in step.commands:
            row = QHBoxLayout()
            shown = QLineEdit(command)
            shown.setReadOnly(True)
            shown.setFont(mono)
            shown.setAccessibleName("Command")
            shown.setCursorPosition(0)
            row.addWidget(shown, stretch=1)
            copy = QPushButton("Copy")
            copy.setToolTip("Copy this command")
            copy.clicked.connect(lambda _checked=False, text=command: QGuiApplication.clipboard().setText(text))
            row.addWidget(copy)
            column.addLayout(row)
        column.addStretch(1)
        return page

    def go(self, by: int) -> None:
        self.pages.setCurrentIndex(min(max(self.pages.currentIndex() + by, 0), self.pages.count() - 1))
        self._update_buttons()

    def _next_or_close(self) -> None:
        if self.pages.currentIndex() == self.pages.count() - 1:
            self.accept()
        else:
            self.go(1)

    def _update_buttons(self) -> None:
        index, count = self.pages.currentIndex(), self.pages.count()
        self.position.setText(f"Step {index + 1} of {count}")
        self.back_button.setEnabled(index > 0)
        self.next_button.setText("Done" if index == count - 1 else "Next")

    def save(self) -> None:
        name = f"How to restore my files ({recovery.PLATFORMS[self.chosen()]}).txt"
        target, _ = QFileDialog.getSaveFileName(self, "Save these steps", str(Path.home() / name),
                                                "Text files (*.txt)")
        if not target:
            return
        try:
            Path(target).write_text(recovery.as_text(self.chosen()), encoding="utf-8",
                                    newline="\r\n" if self.chosen() == "windows" else "\n")
        except OSError as exc:
            QMessageBox.warning(self, "Couldn't save the steps", str(exc))
            return
        QMessageBox.information(self, "Steps saved", "Saved. Keep a copy where you keep your backups, so that the "
                                                     "steps are there when this app isn't. It holds no secrets.")
