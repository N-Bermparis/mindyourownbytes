"""Building blocks shared by the screens."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path

from PySide6.QtCore import QByteArray, QFileInfo, QMimeData, QSize, Qt, QTimer
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileIconProvider,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from mindyourownbytes.core import ENCRYPTED_SUFFIXES
from mindyourownbytes.gui import icons, theme

CLIPBOARD_CLEAR_MS = 30_000

#: Keeps a copied secret out of Windows clipboard history (Win+V) and, because
#: this tool exists to keep data away from cloud services, out of cloud clipboard
#: sync. Ignored on other platforms.
_WINDOWS_CLIPBOARD_EXCLUSIONS = (
    "ExcludeClipboardContentFromMonitorProcessing",
    "CanIncludeInClipboardHistory",
    "CanUploadToCloudClipboard",
)

_INFOBAR_ICONS = {"success": ("check", "ok"), "error": ("alert", "error"), "warning": ("alert", "warn"),
                  "info": ("info", "info")}


class SteadyComboBox(QComboBox):
    """Ignores the mouse wheel, so that it only changes when someone means to change it.

    Scrolling the page with the pointer over a normal combo box quietly picks another
    item. Here that could mean a different key, passphrase, or algorithm.
    """

    def wheelEvent(self, event) -> None:
        event.ignore()


def human_size(size: int) -> str:
    count = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if count < 1024 or unit == "TB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1024
    return "0 B"


def plural(count: int, noun: str = "file") -> str:
    return f"{count} {noun}{'' if count == 1 else 's'}"


def action_button(text: str, variant: str = "secondary", icon_name: str | None = None) -> QPushButton:
    """A button. Only "primary" and "danger" are styled; others are drawn natively."""
    button = QPushButton(text)
    button.setProperty("variant", variant)
    set_icon(button, icon_name)
    return button


def set_icon(button: QAbstractButton, icon_name: str | None) -> None:
    """Remember the icon's name, so it can be redrawn when the theme changes."""
    button.setProperty("iconName", icon_name)
    if icon_name:
        primary = button.property("variant") == "primary"
        button.setIcon(icons.icon(icon_name, theme.color("on_accent") if primary else None))


def refresh_icons(root: QWidget) -> None:
    for button in root.findChildren(QAbstractButton):
        name = button.property("iconName")
        if name:
            set_icon(button, name)


def repolish(widget: QWidget) -> None:
    """Re-apply the stylesheet after a dynamic property changes."""
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def label(text: str = "", name: str | None = None, wrap: bool = False) -> QLabel:
    widget = QLabel(text)
    if name:
        widget.setObjectName(name)
    widget.setWordWrap(wrap)
    return widget


def card() -> QFrame:
    frame = QFrame()
    frame.setObjectName("card")
    return frame


def step_heading(number: int, text: str) -> tuple[QWidget, QLabel, QLabel]:
    """A numbered step title. Returns the row, its title, and its number."""
    row = QWidget()
    layout = QHBoxLayout(row)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(8)
    badge = label(str(number), "stepNumber")
    badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
    layout.addWidget(badge)
    title = label(text, "stepTitle")
    layout.addWidget(title)
    layout.addStretch(1)
    return row, title, badge


class RowSelectionDelegate(QStyledItemDelegate):
    """Selects a table row as one band. Native styles draw a separate pill per column."""

    def paint(self, painter, option, index) -> None:
        style_option = QStyleOptionViewItem(option)
        if style_option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(style_option.rect, theme.color("nav_active"))
        style_option.state &= ~(QStyle.StateFlag.State_Selected | QStyle.StateFlag.State_HasFocus
                                | QStyle.StateFlag.State_MouseOver)
        super().paint(painter, style_option, index)


def configure_table(table: QTableWidget, stretch: Sequence[int], *, multi_select: bool = True) -> None:
    """The settings every file list shares."""
    header = table.horizontalHeader()
    header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    header.setHighlightSections(False)
    for column in range(table.columnCount()):
        mode = QHeaderView.ResizeMode.Stretch if column in stretch else QHeaderView.ResizeMode.ResizeToContents
        header.setSectionResizeMode(column, mode)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(30)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(
        QAbstractItemView.SelectionMode.ExtendedSelection if multi_select
        else QAbstractItemView.SelectionMode.SingleSelection
    )
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setShowGrid(False)
    table.setIconSize(QSize(18, 18))
    table.setTextElideMode(Qt.TextElideMode.ElideMiddle)
    table.setWordWrap(False)
    table.setFrameShape(QFrame.Shape.NoFrame)
    table.setItemDelegate(RowSelectionDelegate(table))


class FileIcons:
    """The system's own icon for each file type, as File Explorer would show it."""

    def __init__(self) -> None:
        self._provider = QFileIconProvider()
        self._by_suffix: dict[str, QIcon] = {}

    def for_name(self, name: str) -> QIcon:
        """Icon for a file name. A ``.gpg`` file shows the type it will restore to."""
        lowered = name.lower()
        if lowered.endswith(ENCRYPTED_SUFFIXES):
            name = name[:-4]
        suffix = Path(name).suffix.lower()
        if suffix not in self._by_suffix:
            self._by_suffix[suffix] = self._provider.icon(QFileInfo(f"example{suffix}"))
        return self._by_suffix[suffix]


class InfoBar(QFrame):
    """A message inside the page, with optional buttons. Hidden until there is news."""

    def __init__(self, on_dismiss: Callable[[], None] | None = None) -> None:
        super().__init__()
        self.setObjectName("infoBar")
        self._on_dismiss = on_dismiss
        self._actions: list[QPushButton] = []
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 9, 8, 9)
        layout.setSpacing(10)
        self._icon = QLabel()
        self._icon.setFixedSize(20, 20)
        layout.addWidget(self._icon, alignment=Qt.AlignmentFlag.AlignTop)
        column = QVBoxLayout()
        column.setSpacing(1)
        self.title_label = label("", "infoTitle", wrap=True)
        self.detail_label = label("", "infoDetail", wrap=True)
        column.addWidget(self.title_label)
        column.addWidget(self.detail_label)
        layout.addLayout(column, stretch=1)
        self._action_row = QHBoxLayout()
        self._action_row.setSpacing(6)
        layout.addLayout(self._action_row)
        self.dismiss_button = QToolButton()
        self.dismiss_button.setAutoRaise(True)
        self.dismiss_button.setAccessibleName("Dismiss this message")
        self.dismiss_button.setToolTip("Dismiss")
        set_icon(self.dismiss_button, "close")
        self.dismiss_button.clicked.connect(self.dismiss)
        layout.addWidget(self.dismiss_button, alignment=Qt.AlignmentFlag.AlignTop)
        self.hide()

    def show_message(self, kind: str, title: str, detail: str = "",
                     actions: Sequence[tuple[str, Callable[[], None]]] = (), dismissable: bool = True) -> None:
        self.setProperty("kind", kind)
        repolish(self)
        icon_name, color_name = _INFOBAR_ICONS[kind]
        self._icon.setPixmap(icons.pixmap(icon_name, 20, theme.color(color_name)))
        self.title_label.setText(title)
        self.detail_label.setText(detail)
        self.detail_label.setVisible(bool(detail))
        for button in self._actions:
            self._action_row.removeWidget(button)
            button.deleteLater()
        self._actions = []
        for text, callback in actions:
            button = QPushButton(text)
            button.clicked.connect(callback)
            self._action_row.addWidget(button)
            self._actions.append(button)
        self.dismiss_button.setVisible(dismissable)
        self.show()

    def text(self) -> str:
        return f"{self.title_label.text()} {self.detail_label.text()}".strip()

    def dismiss(self) -> None:
        self.hide()
        if self._on_dismiss:
            self._on_dismiss()


class EmptyState(QWidget):
    """What a screen shows before it has anything in it."""

    def __init__(self, icon_name: str, title: str, body: str = "", buttons: Sequence[QPushButton] = ()) -> None:
        super().__init__()
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 16, 24, 16)
        layout.setSpacing(6)
        layout.addStretch(1)
        self._icon = QLabel()
        self._icon_name = icon_name
        self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._icon)
        self.title_label = label(title, "emptyTitle", wrap=True)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.title_label)
        self.body_label = label(body, "muted", wrap=True)
        self.body_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.body_label.setVisible(bool(body))
        layout.addWidget(self.body_label)
        row = QHBoxLayout()
        row.setSpacing(8)
        row.addStretch(1)
        for button in buttons:
            row.addWidget(button)
        row.addStretch(1)
        if buttons:
            layout.addSpacing(8)
            layout.addLayout(row)
        layout.addStretch(1)
        self.refresh_icon()

    def refresh_icon(self) -> None:
        self._icon.setPixmap(icons.pixmap(self._icon_name, 40, theme.color("muted")))

    def set_text(self, title: str, body: str = "") -> None:
        self.title_label.setText(title)
        self.body_label.setText(body)
        self.body_label.setVisible(bool(body))


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
