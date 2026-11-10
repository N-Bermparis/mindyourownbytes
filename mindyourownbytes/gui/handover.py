"""Hand files from File Explorer's right-click menu to the window that is already open.

Explorer starts the app once for every selected file. Without this, selecting five files
would open five windows. The first copy to start keeps its window, and the others pass
their file to it and exit.

Everything here stays on this computer and uses no network code. The open window publishes
its handle in a small piece of shared memory, and a later copy sends it a WM_COPYDATA
message. Only file paths are ever sent. They land in the list on the Encrypt screen, exactly
as if they had been dropped there, and nothing happens to them until someone clicks Encrypt.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
import time

IS_WINDOWS = sys.platform == "win32"

#: Held by every open copy. The Windows installer looks for it too.
RUNNING_MUTEX = "mindyourownbytes-running"
#: Per sign-in session, so one person's files never reach another person's window.
_WINDOW_MEMORY = "Local\\mindyourownbytes-window"
#: Marks a message as one of ours. Anything else is left for Qt.
_MAGIC = 0x6D796F62
#: A sanity limit. Explorer hands over one path at a time.
_MAX_BYTES = 256 * 1024
_WM_COPYDATA = 0x004A
_ERROR_ALREADY_EXISTS = 183
_PAGE_READWRITE = 0x04
_FILE_MAP_ALL_ACCESS = 0x000F001F
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SMTO_ABORTIFHUNG = 0x0002

#: Kept open for as long as the app runs. Windows frees them when it exits.
_handles: list[int] = []


class _CopyData(ctypes.Structure):
    _fields_ = [("dwData", ctypes.c_size_t), ("cbData", ctypes.c_uint32), ("lpData", ctypes.c_void_p)]


def _libraries():
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CreateFileMappingW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                            wintypes.DWORD, wintypes.LPCWSTR]
    kernel32.CreateFileMappingW.restype = wintypes.HANDLE
    kernel32.OpenFileMappingW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.OpenFileMappingW.restype = wintypes.HANDLE
    kernel32.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                                       ctypes.c_size_t]
    kernel32.MapViewOfFile.restype = ctypes.c_void_p
    kernel32.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                                    ctypes.POINTER(wintypes.DWORD)]
    user32.IsWindow.argtypes = [wintypes.HWND]
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, ctypes.c_void_p,
                                           wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)]
    user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t
    return kernel32, user32


def paths_from(arguments: list[str]) -> list[str]:
    """The files and folders named on the command line. Anything else is ignored.

    Made absolute here, because the window that receives them may have another current folder.
    An empty argument would otherwise mean the current folder, and everything in it. Options,
    such as Qt's own ``-style``, start with a dash, which no path from File Explorer does.
    """
    paths = []
    for argument in arguments:
        if not argument.strip() or argument.startswith("-"):
            continue
        path = os.path.abspath(argument)
        if os.path.lexists(path) and path not in paths:
            paths.append(path)
    return paths


def mark_as_running() -> bool:
    """Tell the installer, and later copies of the app, that the app is open.

    Returns whether another copy had already done so. The installer and uninstaller ask
    people to close the app first, rather than replacing files in the middle of a batch.
    """
    if not IS_WINDOWS:
        return False
    kernel32, _ = _libraries()
    # Never closed on purpose: Windows releases it when the app exits.
    handle = kernel32.CreateMutexW(None, False, RUNNING_MUTEX)
    already = ctypes.get_last_error() == _ERROR_ALREADY_EXISTS
    if handle:
        _handles.append(handle)
    return already


def announce_window(window_handle: int) -> None:
    """Publish the open window's handle, so that a later copy can find it."""
    if not IS_WINDOWS:
        return
    kernel32, _ = _libraries()
    mapping = kernel32.CreateFileMappingW(ctypes.c_void_p(-1).value, None, _PAGE_READWRITE, 0, 8, _WINDOW_MEMORY)
    if not mapping:
        return
    view = kernel32.MapViewOfFile(mapping, _FILE_MAP_ALL_ACCESS, 0, 0, 8)
    if view:
        ctypes.c_uint64.from_address(view).value = window_handle
        kernel32.UnmapViewOfFile(view)
    _handles.append(mapping)


def _announced_window() -> int:
    kernel32, _ = _libraries()
    mapping = kernel32.OpenFileMappingW(_FILE_MAP_ALL_ACCESS, False, _WINDOW_MEMORY)
    if not mapping:
        return 0
    try:
        view = kernel32.MapViewOfFile(mapping, _FILE_MAP_ALL_ACCESS, 0, 0, 8)
        if not view:
            return 0
        try:
            return ctypes.c_uint64.from_address(view).value
        finally:
            kernel32.UnmapViewOfFile(view)
    finally:
        kernel32.CloseHandle(mapping)


def _program_of(process_id: int) -> str:
    """The full path of the program a process is running, or nothing if it can't be read."""
    from ctypes import wintypes

    kernel32, _ = _libraries()
    process = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, process_id)
    if not process:
        return ""
    try:
        path = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(path))
        if not kernel32.QueryFullProcessImageNameW(process, 0, path, ctypes.byref(size)):
            return ""
        return os.path.normcase(path.value)
    finally:
        kernel32.CloseHandle(process)


def _is_this_app(window_handle: int) -> bool:
    """Whether a window belongs to this same program, so paths never go to anything else."""
    from ctypes import wintypes

    _, user32 = _libraries()
    if not user32.IsWindow(window_handle):
        return False
    process_id = wintypes.DWORD()
    user32.GetWindowThreadProcessId(window_handle, ctypes.byref(process_id))
    program = _program_of(process_id.value)
    return bool(program) and program == _program_of(os.getpid())


def encode(paths: list[str]) -> bytes:
    return json.dumps(paths).encode("utf-8")


def decode(data: bytes) -> list[str]:
    """The paths in a message, or nothing at all if it isn't exactly a list of text."""
    try:
        paths = json.loads(data.decode("utf-8"))
    except ValueError:
        return []
    if not isinstance(paths, list) or not all(isinstance(path, str) and path for path in paths):
        return []
    return paths


def hand_over(paths: list[str], wait: float = 15.0) -> bool:
    """Give these paths to the window that is already open. Returns whether it took them.

    The other copy may have started a moment ago and not have a window yet, so this waits
    a while for one. If none turns up, or it says no, the caller opens its own window.
    """
    if not IS_WINDOWS or not paths:
        return False
    _, user32 = _libraries()
    data = encode(paths)
    buffer = ctypes.create_string_buffer(data, len(data))
    message = _CopyData(_MAGIC, len(data), ctypes.cast(buffer, ctypes.c_void_p))
    deadline = time.monotonic() + wait
    while True:
        window = _announced_window()
        if window and _is_this_app(window):
            answer = ctypes.c_size_t(0)
            sent = user32.SendMessageTimeoutW(window, _WM_COPYDATA, 0, ctypes.addressof(message),
                                              _SMTO_ABORTIFHUNG, 5000, ctypes.byref(answer))
            return bool(sent) and answer.value == 1
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def read_message(address: int) -> list[str] | None:
    """The paths in a Windows message, given the address of its MSG. None if it isn't one of ours."""
    from ctypes import wintypes

    message = wintypes.MSG.from_address(address)
    if message.message != _WM_COPYDATA or not message.lParam:
        return None
    data = _CopyData.from_address(message.lParam)
    if data.dwData != _MAGIC or not data.lpData or not 0 < data.cbData <= _MAX_BYTES:
        return None
    return decode(ctypes.string_at(data.lpData, data.cbData))
