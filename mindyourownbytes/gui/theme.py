"""Look and feel: native controls, one brand color, and the system's light or dark mode.

Controls are drawn by the platform's own style, so buttons, dialogs, and menus look
like every other app on the computer. The stylesheet only adds what a native style
has no concept of, such as the primary button, cards, and status colors.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication

STYLESHEET = Path(__file__).resolve().parent.parent / "styles.qss"

_LIGHT = {
    "accent": "#0F766E", "accent_hover": "#115E59", "accent_pressed": "#134E4A", "on_accent": "#FFFFFF",
    "card": "#FFFFFF", "border": "#E2E2E2", "text": "#1B1B1B", "muted": "#5C5C5C",
    "nav_hover": "#E8E8E8", "nav_active": "#E2EEEC",
    "drop": "#FBFBFB", "drop_border": "#ADADAD", "drop_active": "#E4F2F0",
    "ok": "#0B7A4B", "ok_bg": "#E7F5EE", "ok_border": "#BFE3D0",
    "warn": "#8A5200", "warn_bg": "#FFF4E0", "warn_border": "#F0D9A8",
    "error": "#B3261E", "error_bg": "#FCEBEA", "error_border": "#F2C4C0",
    "info": "#1F5F8B", "info_bg": "#EAF2F8", "info_border": "#C6DCEB",
    "disabled_bg": "#E4E4E4", "disabled_fg": "#8A8A8A",
}
_DARK = {
    "accent": "#2DD4BF", "accent_hover": "#5EEAD4", "accent_pressed": "#14B8A6", "on_accent": "#04211E",
    "card": "#2B2B2B", "border": "#3D3D3D", "text": "#F3F3F3", "muted": "#ABABAB",
    "nav_hover": "#2F2F2F", "nav_active": "#2C3B39",
    "drop": "#262626", "drop_border": "#6A6A6A", "drop_active": "#233634",
    "ok": "#5FD39A", "ok_bg": "#1E3229", "ok_border": "#2F5543",
    "warn": "#F2B65A", "warn_bg": "#3A2E1B", "warn_border": "#5E4A28",
    "error": "#FF8A80", "error_bg": "#3B2321", "error_border": "#633A36",
    "info": "#8CC4EC", "info_bg": "#1F2D38", "info_border": "#35506A",
    "disabled_bg": "#3A3A3A", "disabled_fg": "#858585",
}


def is_dark() -> bool:
    scheme = QGuiApplication.styleHints().colorScheme()
    if scheme == Qt.ColorScheme.Unknown:
        return QGuiApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128
    return scheme == Qt.ColorScheme.Dark


def tokens() -> dict[str, str]:
    return _DARK if is_dark() else _LIGHT


def color(name: str) -> QColor:
    return QColor(tokens()[name])


def stylesheet() -> str:
    text = STYLESHEET.read_text(encoding="utf-8")
    for name, value in tokens().items():
        text = text.replace(f"@{name}@", value)
    return text


def apply_palette(app: QApplication) -> None:
    """Use the brand color wherever the native style would use the system accent."""
    values = tokens()
    palette = app.palette()
    palette.setColor(QPalette.ColorRole.Accent, QColor(values["accent"]))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(values["accent"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(values["on_accent"]))
    palette.setColor(QPalette.ColorRole.Link, QColor(values["accent"]))
    app.setPalette(palette)


def configure_application(app: QApplication) -> None:
    # The Windows 10 default style has no dark mode. Fusion follows the system's.
    if app.style().objectName().lower() == "windowsvista":
        app.setStyle("Fusion")
    font = app.font()
    font.setPointSize(10)
    app.setFont(font)
    apply_palette(app)
