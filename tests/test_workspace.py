"""Private workspaces for decrypted data, and finding the ones an interrupted restore left behind.

Real files, real locks, and real processes: a child process stands in for a copy of the app that is
still running, or that died without cleaning up.
"""

import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from mindyourownbytes import workspace
from tests.test_safefs import make_junction, make_symlink

REPOSITORY = Path(__file__).resolve().parent.parent


class WorkspaceCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="myobtest", ignore_cleanup_errors=True)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.restored = self.root / "Restored Files"
        self.restored.mkdir()
        self.journal = workspace.Journal(self.root / "app" / "unfinished")
        self.addCleanup(self.journal.close)

    def notes(self) -> list[Path]:
        folder = self.journal.directory
        return sorted(folder.glob("*.json")) if folder.is_dir() else []

    def child(self, script: str) -> subprocess.Popen:
        """Another copy of the app, as a separate process, running ``script`` with ``journal`` and ``restored``."""
        prelude = textwrap.dedent(f"""
            import os, sys, time
            from pathlib import Path
            sys.path.insert(0, {str(REPOSITORY)!r})
            from mindyourownbytes import workspace
            journal = workspace.Journal(Path({str(self.journal.directory)!r}))
            restored = Path({str(self.restored)!r})
        """)
        return subprocess.Popen([sys.executable, "-c", prelude + textwrap.dedent(script)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class CreateAndRemoveTests(WorkspaceCase):
    def test_a_workspace_is_hidden_private_marked_and_noted_before_use(self):
        space = workspace.create(self.restored, self.journal)
        self.assertRegex(space.path.name, r"^\.myob-[0-9a-f]{16}\.partial$")
        self.assertTrue(space.path.is_dir())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(space.path.stat().st_mode), 0o700, "no other account may look inside")
        self.assertEqual((space.path / workspace.MARKER).read_bytes(), space.token.encode())
        self.assertEqual([note.stem for note in self.notes()], [space.token], "noted before anything goes in")
        self.assertTrue(workspace.owned(space.path, space.token))
        self.assertNotIn(space.token, repr(space), "the token stays out of logs")

    def test_removing_deletes_everything_and_then_the_note(self):
        space = workspace.create(self.restored, self.journal)
        (space.path / "decrypted-0").write_bytes(b"plaintext")
        (space.path / "unpacked" / "inner").mkdir(parents=True)
        (space.path / "unpacked" / "inner" / "a.txt").write_bytes(b"plaintext")
        self.assertTrue(workspace.remove(space, self.journal))
        self.assertEqual(list(self.restored.iterdir()), [])
        self.assertEqual(self.notes(), [])

    def test_a_workspace_that_cant_be_removed_keeps_its_note(self):
        space = workspace.create(self.restored, self.journal)
        from unittest.mock import patch
        with patch("mindyourownbytes.workspace.shutil.rmtree", side_effect=PermissionError(13, "in use")):
            self.assertFalse(workspace.remove(space, self.journal))
        self.assertEqual([note.stem for note in self.notes()], [space.token], "so it can be found again")

    def test_a_note_that_cant_be_written_stops_the_restore_and_leaves_nothing(self):
        blocker = self.root / "app"
        blocker.write_bytes(b"a file where the app's folder should be")
        with self.assertRaisesRegex(workspace.WorkspaceError, "couldn't note where"):
            workspace.create(self.restored, self.journal)
        self.assertEqual(list(self.restored.iterdir()), [])

    def test_workspaces_never_share_a_name(self):
        spaces = [workspace.create(self.restored, self.journal) for _ in range(20)]
        self.assertEqual(len({space.path for space in spaces}), 20)


class OwnershipTests(WorkspaceCase):
    """Nothing is deleted unless it's beyond doubt a workspace the app made."""

    def test_only_the_exact_token_proves_ownership(self):
        space = workspace.create(self.restored, self.journal)
        self.assertFalse(workspace.owned(space.path, "0" * 32))
        (space.path / workspace.MARKER).write_bytes(space.token.encode() + b"\n")
        self.assertFalse(workspace.owned(space.path, space.token))

    def test_a_folder_named_like_a_workspace_but_without_the_marker_is_not_the_apps(self):
        lookalike = self.restored / ".myob-0123456789abcdef.partial"
        lookalike.mkdir()
        (lookalike / "mine.txt").write_bytes(b"someone's own file")
        self.assertFalse(workspace.owned(lookalike, "a" * 32))

    def test_a_folder_with_another_name_is_not_the_apps_even_with_the_marker(self):
        space = workspace.create(self.restored, self.journal)
        renamed = self.restored / "Taxes"
        space.path.rename(renamed)
        self.assertFalse(workspace.owned(renamed, space.token))

    def swap_for_link(self, make_link) -> tuple[Path, Path]:
        """Replace a workspace with a link to someone's own folder, which holds a copy of the marker."""
        space = workspace.create(self.restored, self.journal)
        theirs = self.root / "Documents"
        theirs.mkdir()
        (theirs / "precious.txt").write_bytes(b"irreplaceable")
        (theirs / workspace.MARKER).write_bytes(space.token.encode())
        (space.path / workspace.MARKER).unlink()
        space.path.rmdir()
        if not make_link(space.path, theirs):
            self.skipTest("links of this kind can't be made here")
        return space, theirs

    def assert_never_followed(self, space, theirs) -> None:
        self.assertFalse(workspace.owned(space.path, space.token))
        failed, unconfirmed = self.journal.clean([workspace.Leftover(space.path, space.token)])
        self.assertEqual((failed, unconfirmed), ([], [space.path]))
        self.assertEqual((theirs / "precious.txt").read_bytes(), b"irreplaceable")
        self.assertTrue(os.path.lexists(space.path), "not even the link is removed: it wasn't the app's")

    def test_a_symbolic_link_swapped_in_is_never_followed(self):
        self.assert_never_followed(*self.swap_for_link(make_symlink))

    def test_a_junction_swapped_in_is_never_followed(self):
        self.assert_never_followed(*self.swap_for_link(make_junction))

    def test_a_link_inside_a_workspace_is_removed_without_touching_what_it_points_to(self):
        space = workspace.create(self.restored, self.journal)
        theirs = self.root / "Documents"
        theirs.mkdir()
        (theirs / "precious.txt").write_bytes(b"irreplaceable")
        made = make_symlink(space.path / "link", theirs) or make_junction(space.path / "link", theirs)
        if not made:
            self.skipTest("no kind of link can be made here")
        self.assertTrue(workspace.remove(space, self.journal))
        self.assertEqual((theirs / "precious.txt").read_bytes(), b"irreplaceable")


class LeftoverTests(WorkspaceCase):
    def test_a_copy_that_died_leaves_a_workspace_that_the_next_start_finds_and_can_delete(self):
        # The child makes a workspace, writes plaintext into it, and dies without any cleanup at all.
        child = self.child("""
            space = workspace.create(restored, journal)
            (space.path / "decrypted-0").write_bytes(b"plaintext")
            print(space.path, flush=True)
            os._exit(9)
        """)
        out, err = child.communicate(timeout=60)
        self.assertEqual(child.returncode, 9, err)
        left = Path(out.decode().strip())
        self.assertTrue((left / "decrypted-0").is_file(), "the crash left readable data behind")
        found = self.journal.leftovers()
        self.assertEqual([leftover.path for leftover in found], [left])
        self.assertEqual(self.journal.clean(found), ([], []))
        self.assertFalse(os.path.lexists(left))
        self.assertEqual(self.notes(), [])
        self.assertEqual(self.journal.leftovers(), [])

    def test_a_copy_that_is_still_running_keeps_its_workspaces(self):
        child = self.child("""
            space = workspace.create(restored, journal)
            print(space.path, flush=True)
            sys.stdin.readline()
            workspace.remove(space, journal)
            journal.close()
        """)
        try:
            left = Path(child.stdout.readline().decode().strip())
            self.assertTrue(left.is_dir())
            self.assertEqual(self.journal.leftovers(), [], "never another running copy's workspace")
        finally:
            out, err = child.communicate(b"\n", timeout=60)
        self.assertEqual(child.returncode, 0, err)
        self.assertFalse(left.exists())
        self.assertEqual(self.journal.leftovers(), [])

    def test_this_copys_own_workspaces_are_not_leftovers(self):
        workspace.create(self.restored, self.journal)
        self.assertEqual(self.journal.leftovers(), [])

    def test_a_leftover_that_is_already_gone_is_simply_forgotten(self):
        other = workspace.Journal(self.journal.directory)
        space = workspace.create(self.restored, other)
        other.close()
        workspace.remove(space)  # Deleted by hand, say, without the note going.
        self.assertEqual(len(self.notes()), 1)
        self.assertEqual(self.journal.leftovers(), [])
        self.assertEqual(self.notes(), [])

    def test_a_leftover_that_cant_be_deleted_is_offered_again(self):
        other = workspace.Journal(self.journal.directory)
        space = workspace.create(self.restored, other)
        other.close()
        from unittest.mock import patch
        with patch("mindyourownbytes.workspace.shutil.rmtree", side_effect=PermissionError(13, "in use")):
            failed, unconfirmed = self.journal.clean(self.journal.leftovers())
        self.assertEqual((failed, unconfirmed), ([space.path], []))
        self.assertEqual([leftover.path for leftover in self.journal.leftovers()], [space.path])

    def test_damaged_notes_are_ignored(self):
        self.journal.directory.mkdir(parents=True)
        (self.journal.directory / f"{'b' * 32}.json").write_text("not json")
        (self.journal.directory / "unrelated.json").write_text('{"path": "/", "session": "x"}')
        self.assertEqual(self.journal.leftovers(), [])

    def test_session_files_of_copies_that_stopped_are_tidied(self):
        other = workspace.Journal(self.journal.directory)
        workspace.remove(workspace.create(self.restored, other), other)
        lock = self.journal.directory / f"session-{other.session}.lock"
        other._lock.close()  # As if it had crashed: the file stays, but nobody holds it.
        other._lock = None
        self.assertTrue(lock.exists())
        self.journal.leftovers()
        self.assertFalse(lock.exists())

    def test_closing_a_session_ends_it_cleanly(self):
        workspace.remove(workspace.create(self.restored, self.journal), self.journal)
        self.journal.close()
        time.sleep(0.01)
        self.assertEqual(list(self.journal.directory.glob("session-*.lock")), [])


if __name__ == "__main__":
    unittest.main()
