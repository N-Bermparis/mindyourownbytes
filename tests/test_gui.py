"""Construct the UI on headless CI when PySide6 is available."""

import importlib.util
import os
import unittest


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
class GuiSmokeTest(unittest.TestCase):
    def test_main_window_construction(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
        from main import MainWindow

        app = QApplication.instance() or QApplication([])
        window = MainWindow()
        self.assertIn("mindyourownbytes", window.windowTitle())
        self.assertEqual(window.operation, "encrypt")
        window.set_operation("restore")
        self.assertEqual(window.operation, "restore")
        window.close()
        del app
