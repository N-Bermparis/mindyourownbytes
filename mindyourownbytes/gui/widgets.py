"""Small helpers shared by the pages."""

from __future__ import annotations

from PySide6.QtCore import QByteArray, QMimeData, Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QApplication, QPushButton, QWidget

CLIPBOARD_CLEAR_MS = 30_000

#: Keeps a copied secret out of Windows clipboard history (Win+V) and, because
#: this tool exists to keep data away from cloud services, out of cloud clipboard
#: sync. Ignored on other platforms.
_WINDOWS_CLIPBOARD_EXCLUSIONS = (
    "ExcludeClipboardContentFromMonitorProcessing",
    "CanIncludeInClipboardHistory",
    "CanUploadToCloudClipboard",
)


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


def repolish(widget: QWidget) -> None:
    """Re-apply the stylesheet after a dynamic property changes."""
    widget.style().unpolish(widget)
    widget.style().polish(widget)


class WaitCursor:
    """Shows that the UI is briefly busy while gpg runs its key derivation."""

    def __enter__(self) -> None:
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)

    def __exit__(self, *_exc) -> None:
        QApplication.restoreOverrideCursor()


class SecretClipboard:
    """Copies a secret, then removes it again after a short time."""

    def __init__(self) -> None:
        self._secret: str | None = None
        self._timer = QTimer()
        self._timer.setSingleShot(True)
        self._timer.setInterval(CLIPBOARD_CLEAR_MS)
        self._timer.timeout.connect(self.clear)

    def copy(self, secret: str) -> None:
        mime = QMimeData()
        mime.setText(secret)
        for name in _WINDOWS_CLIPBOARD_EXCLUSIONS:
            mime.setData(f'application/x-qt-windows-mime;value="{name}"', QByteArray(b"\x00\x00\x00\x00"))
        QGuiApplication.clipboard().setMimeData(mime)
        self._secret = secret
        self._timer.start()

    def clear(self) -> None:
        """Clear only our secret, never something the user has copied since."""
        self._timer.stop()
        if self._secret is not None and QGuiApplication.clipboard().text() == self._secret:
            QGuiApplication.clipboard().clear()
        self._secret = None
