"""The record of what this computer encrypted, and the checks of downloads against it. No GnuPG needed."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from mindyourownbytes import records
from mindyourownbytes.records import Ledger, Record

EARLIER = "2026-11-01T10:00:00+00:00"
LATER = "2026-11-08T10:00:00+00:00"


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class LedgerCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="myobtest")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.ledger = Ledger(self.root / "app" / "records.jsonl")

    def made(self, name: str, content: bytes, when: str = EARLIER, path: str = "") -> Record:
        record = Record(digest(content), name, path or name, len(content), when)
        self.ledger.add([record])
        return record

    def download(self, name: str, content: bytes) -> Path:
        path = self.root / "Downloads" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def check(self, name: str, content: bytes) -> records.Finding:
        path = self.download(name, content)
        # A fresh read of the file each time, as the app does when restoring.
        return Ledger(self.ledger.path).check(path, records.sha256_of(path))


class CheckTests(LedgerCase):
    def test_the_file_made_here_matches(self):
        self.made("report.pdf.gpg", b"v1")
        finding = self.check("report.pdf.gpg", b"v1")
        self.assertEqual(finding.verdict, "match")
        self.assertFalse(finding.is_warning)
        self.assertIn("Matches the copy made here on 2026-11-01", finding.message)

    def test_a_browser_numbering_a_download_is_not_a_difference(self):
        self.made("report.pdf.gpg", b"v1")
        for name in ("report (1).pdf.gpg", "report (2).pdf.gpg", "REPORT.pdf.gpg"):
            with self.subTest(name):
                self.assertEqual(self.check(name, b"v1").verdict, "match")

    def test_an_older_version_of_the_same_file_is_flagged(self):
        self.made("report.pdf.gpg", b"v1", EARLIER)
        self.made("report.pdf.gpg", b"v2", LATER)
        old = self.check("report.pdf.gpg", b"v1")
        self.assertEqual(old.verdict, "older")
        self.assertTrue(old.is_warning)
        self.assertIn("older copy", old.message)
        self.assertEqual(self.check("report.pdf.gpg", b"v2").verdict, "match")

    def test_two_files_that_this_app_numbered_are_not_versions_of_each_other(self):
        # "report (2)" was made because "report" already existed. Both are current.
        self.made("report.pdf.gpg", b"first", EARLIER)
        self.made("report (2).pdf.gpg", b"second", LATER)
        self.assertEqual(self.check("report.pdf.gpg", b"first").verdict, "match")
        self.assertEqual(self.check("report (2).pdf.gpg", b"second").verdict, "match")

    def test_a_file_under_another_name_is_flagged_as_renamed_or_swapped(self):
        self.made("taxes.pdf.gpg", b"taxes")
        self.made("medical.pdf.gpg", b"medical")
        swapped = self.check("taxes.pdf.gpg", b"medical")
        self.assertEqual(swapped.verdict, "renamed")
        self.assertIn("saved as medical.pdf.gpg", swapped.message)

    def test_unknown_content_under_a_known_name_is_flagged(self):
        self.made("report.pdf.gpg", b"v1")
        changed = self.check("report.pdf.gpg", b"something else")
        self.assertEqual(changed.verdict, "changed")
        self.assertIn("isn't the report.pdf.gpg made here", changed.message)

    def test_a_file_never_recorded_is_simply_unknown(self):
        self.made("report.pdf.gpg", b"v1")
        finding = self.check("holiday.jpg.gpg", b"photo")
        self.assertEqual((finding.verdict, finding.message, finding.is_warning), ("unknown", "", False))

    def test_with_no_record_at_all_everything_is_unknown(self):
        self.assertEqual(self.check("report.pdf.gpg", b"v1").verdict, "unknown")


class StorageTests(LedgerCase):
    def test_records_survive_and_lines_that_cant_be_read_are_skipped(self):
        self.made("a.gpg", b"a")
        with self.ledger.path.open("a", encoding="utf-8") as file:
            file.write("not json\n")
            file.write(json.dumps({"sha256": "nothex", "name": "x", "path": "x", "size": 1}) + "\n")
            file.write(json.dumps({"name": "missing a checksum"}) + "\n")
            file.write("\n")
        self.made("b.gpg", b"b")
        loaded = Ledger(self.ledger.path).load()
        self.assertEqual([record.name for record in loaded.records], ["a.gpg", "b.gpg"])
        self.assertEqual(loaded.unreadable, 3)

    def test_each_record_is_one_line_with_names_kept_readable(self):
        self.made("Τεστ résumé.txt.gpg", b"x", path="Φάκελος/Τεστ résumé.txt.gpg")
        line = self.ledger.path.read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(json.loads(line)["path"], "Φάκελος/Τεστ résumé.txt.gpg")
        self.assertIn("Τεστ", line)

    def test_clearing_forgets_everything(self):
        self.made("a.gpg", b"a")
        self.ledger.clear()
        self.assertFalse(self.ledger.path.exists())
        self.assertEqual(Ledger(self.ledger.path).load().records, [])
        self.ledger.clear()  # Clearing nothing is fine.

    def test_records_for_new_files_say_where_they_went(self):
        exports = self.root / "exports"
        (exports / "Taxes").mkdir(parents=True)
        inside = exports / "Taxes" / "a.pdf.gpg"
        inside.write_bytes(b"cipher")
        outside = self.root / "elsewhere.gpg"
        outside.write_bytes(b"other")
        made = records.records_for([inside, outside], exports)
        self.assertEqual([(r.name, r.path, r.size, r.sha256) for r in made],
                         [("a.pdf.gpg", "Taxes/a.pdf.gpg", 6, digest(b"cipher")),
                          ("elsewhere.gpg", "elsewhere.gpg", 5, digest(b"other"))])
        self.assertTrue(all(record.made.endswith("+00:00") for record in made))


class ChecksumFileTests(LedgerCase):
    def test_writes_what_sha256sum_reads(self):
        text = records.checksum_file([(digest(b"a"), "Taxes/a.pdf.gpg"), (digest(b"b"), "b.gpg")])
        self.assertEqual(text, f"{digest(b'a')}  Taxes/a.pdf.gpg\n{digest(b'b')}  b.gpg\n")

    def test_reads_its_own_files_and_other_tools(self):
        upper = digest(b"c").upper()
        text = ("﻿# made elsewhere\n"
                f"{digest(b'a')}  Taxes/a.pdf.gpg\n"
                f"{digest(b'b')} *b.gpg\n"
                f"{upper}  Windows\\style\\c.gpg\n"
                "not a checksum\n"
                f"{digest(b'd')[:-1]}  too-short.gpg\n")
        found, unreadable = records.read_checksum_file(text, "SHA256SUMS.txt")
        self.assertEqual([(r.sha256, r.name, r.path) for r in found], [
            (digest(b"a"), "a.pdf.gpg", "Taxes/a.pdf.gpg"),
            (digest(b"b"), "b.gpg", "b.gpg"),
            (digest(b"c"), "c.gpg", "Windows/style/c.gpg"),
        ])
        self.assertEqual(unreadable, 2)
        self.assertTrue(all(record.source == "SHA256SUMS.txt" and not record.made for record in found))

    def test_imported_checksums_are_checked_against_like_any_other(self):
        found, _ = records.read_checksum_file(f"{digest(b'v1')}  Taxes/report.pdf.gpg\n", "SHA256SUMS.txt")
        self.ledger.add(found)
        match = self.check("report.pdf.gpg", b"v1")
        self.assertEqual(match.verdict, "match")
        self.assertIn("checksum from SHA256SUMS.txt", match.message)
        changed = self.check("report.pdf.gpg", b"v2")
        self.assertEqual(changed.verdict, "changed")
        self.assertIn("from SHA256SUMS.txt", changed.message)


if __name__ == "__main__":
    unittest.main()
