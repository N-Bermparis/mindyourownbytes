"""Files chosen in File Explorer: reading them from the command line, and passing them to an open window."""

import ctypes
import os
import sys
import tempfile
import unittest
from pathlib import Path

from mindyourownbytes.gui import handover

WINDOWS = sys.platform == "win32"


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="myobtest")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        (self.root / "report.pdf").write_bytes(b"x")
        (self.root / "Taxes 2026").mkdir()

    def test_takes_files_and_folders_that_exist(self):
        given = [str(self.root / "report.pdf"), str(self.root / "Taxes 2026")]
        self.assertEqual(handover.paths_from(given), given)

    def test_ignores_options_and_anything_that_is_not_there(self):
        given = ["--self-test", "-style", "fusion", str(self.root / "missing.txt"), str(self.root / "report.pdf")]
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.root.parent)
        self.assertEqual(handover.paths_from(given), [str(self.root / "report.pdf")])

    def test_an_empty_argument_never_means_the_current_folder(self):
        # Regression: it became the current folder, which would have listed everything in it.
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.root.parent)
        self.assertEqual(handover.paths_from(["", " ", "\t"]), [])

    def test_an_option_is_never_read_as_a_file_even_if_one_has_that_name(self):
        for name in ("--self-test", "-style"):
            (self.root / name).write_bytes(b"x")
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.root.parent)
        self.assertEqual(handover.paths_from(["--self-test", "-style"]), [])

    def test_makes_paths_absolute_and_drops_repeats(self):
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.root.parent)
        self.assertEqual(handover.paths_from(["report.pdf", str(self.root / "report.pdf")]),
                         [str(self.root / "report.pdf")])

    def test_nothing_given_means_nothing_to_open(self):
        self.assertEqual(handover.paths_from([]), [])


class MessageContentTests(unittest.TestCase):
    def test_paths_survive_the_trip_including_other_alphabets(self):
        paths = [r"C:\Users\me\Έγγραφα\φορολογικά 2026.txt", r"D:\a b\c.pdf"]
        self.assertEqual(handover.decode(handover.encode(paths)), paths)

    def test_anything_but_a_list_of_text_is_thrown_away_whole(self):
        for data in (b"", b"not json", b"\xff\xfe", b'"a string"', b'{"a": 1}', b"[1, 2]", b'["ok", 5]', b'[""]',
                     b'[["nested"]]', b"null"):
            with self.subTest(data):
                self.assertEqual(handover.decode(data), [])


class HandOverTests(unittest.TestCase):
    def test_with_nothing_to_hand_over_it_says_no_at_once(self):
        self.assertFalse(handover.hand_over([]))

    def test_with_no_window_open_it_gives_up_so_the_caller_opens_one(self):
        self.assertFalse(handover.hand_over([__file__], wait=0))

    @unittest.skipIf(WINDOWS, "only other systems have nothing to do here")
    def test_other_systems_do_nothing(self):
        self.assertFalse(handover.mark_as_running())
        handover.announce_window(1)
        self.assertFalse(handover.hand_over([__file__], wait=0))


@unittest.skipUnless(WINDOWS, "Windows messages")
class WindowsMessageTests(unittest.TestCase):
    def message(self, data: bytes, magic: int = handover._MAGIC, kind: int = handover._WM_COPYDATA,
                size: int | None = None) -> int:
        from ctypes import wintypes

        buffer = ctypes.create_string_buffer(data, max(len(data), 1))
        copy = handover._CopyData(magic, len(data) if size is None else size, ctypes.cast(buffer, ctypes.c_void_p))
        message = wintypes.MSG()
        message.message = kind
        message.lParam = ctypes.addressof(copy)
        self.kept = (buffer, copy, message)  # ctypes doesn't keep these alive by itself.
        return ctypes.addressof(message)

    def test_reads_the_paths_from_a_message_of_ours(self):
        paths = [r"C:\Users\me\report.pdf", r"C:\Users\me\Έγγραφα"]
        self.assertEqual(handover.read_message(self.message(handover.encode(paths))), paths)

    def test_leaves_every_other_message_to_the_window(self):
        data = handover.encode([r"C:\a.txt"])
        self.assertIsNone(handover.read_message(self.message(data, kind=0x0010)))
        self.assertIsNone(handover.read_message(self.message(data, magic=12345)))
        self.assertIsNone(handover.read_message(self.message(data, size=0)))
        self.assertIsNone(handover.read_message(self.message(data, size=handover._MAX_BYTES + 1)))

    def test_a_message_of_ours_with_nonsense_inside_carries_no_paths(self):
        self.assertEqual(handover.read_message(self.message(b"not json")), [])

    def test_a_window_of_another_program_is_never_sent_anything(self):
        desktop = ctypes.WinDLL("user32").GetDesktopWindow()
        self.assertFalse(handover._is_this_app(desktop))
        self.assertFalse(handover._is_this_app(0))

    def test_this_program_is_recognized_by_its_own_file(self):
        self.assertTrue(handover._program_of(os.getpid()))


if __name__ == "__main__":
    unittest.main()
