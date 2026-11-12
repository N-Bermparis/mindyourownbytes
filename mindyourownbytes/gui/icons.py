"""Line icons drawn from small inline SVGs, so they stay sharp and match the theme."""

from __future__ import annotations

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer

from mindyourownbytes.gui import theme

_SHAPES = {
    "encrypt": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "restore": '<rect x="5" y="12" width="14" height="9" rx="2"/><path d="M8 12V6.5a4 4 0 0 1 8 0"/>',
    "library": '<rect x="3" y="4" width="18" height="5" rx="1"/>'
               '<path d="M5 9v10a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V9"/><path d="M10 13h4"/>',
    "key": '<circle cx="8" cy="15" r="4"/><path d="M11 12l8-8M16 7l3 3M13.5 9.5l2 2"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "file": '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
    "folder_plus": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'
                   '<path d="M12 10.5v5M9.5 13h5"/>',
    "close": '<path d="M6 6l12 12M18 6L6 18"/>',
    "check": '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "alert": '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17.5v.01"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.01"/>',
    "shield": '<path d="M12 3l7 3v5c0 5-3 8.5-7 10-4-1.5-7-5-7-10V6z"/>',
    "refresh": '<path d="M20 11a8 8 0 0 0-14-4L4 9M4 4v5h5M4 13a8 8 0 0 0 14 4l2-2M20 20v-5h-5"/>',
    "trash": '<path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13"/>',
    "copy": '<rect x="9" y="9" width="11" height="11" rx="2"/>'
            '<path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3"/>',
    "eye": '<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/>',
    "edit": '<path d="M4 20l1-4L16 5l3 3L8 19z"/>',
    "drop": '<path d="M12 4v11M7 11l5 5 5-5M4 20h16"/>',
    "move": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'
            '<path d="M9 13h6M12.5 10.5L15 13l-2.5 2.5"/>',
}

_ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 96)

_APP_ICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    '<defs><linearGradient id="g" x1="0" y1="0" x2="0" y2="1">'
    '<stop offset="0" stop-color="#14A08F"/><stop offset="1" stop-color="#0B5F58"/></linearGradient></defs>'
    '<rect x="3" y="3" width="58" height="58" rx="14" fill="url(#g)"/>'
    '<path d="M22 29v-7a10 10 0 0 1 20 0v7" fill="none" stroke="#FFFFFF" stroke-width="5" stroke-linecap="round"/>'
    '<rect x="16" y="28" width="32" height="24" rx="5" fill="#FFFFFF"/>'
    '<circle cx="32" cy="38" r="3.4" fill="#0B5F58"/>'
    '<rect x="30.4" y="39" width="3.2" height="7" rx="1.6" fill="#0B5F58"/>'
    "</svg>"
)


def _render(svg: str, size: int) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    QSvgRenderer(QByteArray(svg.encode())).render(painter)
    painter.end()
    return pixmap


def pixmap(name: str, size: int, color: QColor | str | None = None) -> QPixmap:
    shade = QColor(color) if color is not None else theme.color("text")
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{shade.name()}" '
        f'stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">{_SHAPES[name]}</svg>'
    )
    return _render(svg, size)


def icon(name: str, color: QColor | str | None = None) -> QIcon:
    result = QIcon()
    for size in _ICON_SIZES:
        result.addPixmap(pixmap(name, size, color))
    return result


def app_pixmap(size: int) -> QPixmap:
    """The app's icon at any size, drawn rather than scaled, for the icons of the Mac and Linux downloads."""
    return _render(_APP_ICON, size)


def app_icon() -> QIcon:
    result = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        result.addPixmap(_render(_APP_ICON, size))
    return result
