"""Fuzzing: random and mangled input for the parsers that read things this app didn't write.

Each target gets inputs from a seeded generator, so any failure can be reproduced exactly from the
seed and iteration that the failure message names. A normal test run uses a fixed seed and a few
hundred inputs per target. The weekly fuzzing workflow runs many more, from a random seed:

    MYOB_FUZZ_ITERATIONS=20000 MYOB_FUZZ_SEED=12345 python -m unittest tests.test_fuzz

No dependency is needed, and nothing here touches GnuPG, the network, or anything outside a
temporary folder.
"""

from __future__ import annotations

import io
import json
import os
import random
import re
import string
import tempfile
import typing
import unittest
import zipfile
from pathlib import Path, PurePosixPath

from mindyourownbytes import archive, records, signatures, strength
from mindyourownbytes.core import GpgFailure, describe_failure

ITERATIONS = int(os.environ.get("MYOB_FUZZ_ITERATIONS", "300"))
SEED = int(os.environ.get("MYOB_FUZZ_SEED", "20261119"))

#: Pieces that attackers, other tools, and accidents put into names.
NAME_PIECES = ["..", ".", "/", "\\", "C:", "c:\\", "//server/share", "CON", "nul", "LPT1", "aux.txt", " ", "\t", "\n",
               "\x00", "\u202e", "\u200b", "\ufeff", "ﬁ", "Ⅸ", "Έγγραφα", "résumé", "日本", "😀", "a" * 300, "~",
               "$", "%2e%2e", ":", "*", "?", "<", ">", "|", '"', "\x7f", "x.", "y ", ".hidden", "-", "#"]
STATUS_WORDS = ["NEWSIG", "GOODSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "BADSIG", "ERRSIG", "VALIDSIG",
                "TRUST_UNDEFINED", "TRUST_NEVER", "TRUST_MARGINAL", "TRUST_FULLY", "TRUST_ULTIMATE",
                "DECRYPTION_OKAY", "DECRYPTION_FAILED", "DECRYPTION_KEY", "NO_PUBKEY", "NO_SECKEY", "BADMDC",
                "GOODMDC", "PLAINTEXT", "BEGIN_DECRYPTION", "END_DECRYPTION", "FAILURE", "ERROR", "BAD_PASSPHRASE",
                "NEED_PASSPHRASE_SYM", "INV_RECP", "INV_SGNR", "KEYREVOKED", "KEYEXPIRED", "NODATA"]


def generator(target: str, iteration: int) -> random.Random:
    """One generator per input, so a failure names exactly what to rerun."""
    return random.Random(f"{SEED}:{target}:{iteration}")


def random_text(chance: random.Random, length: int = 40) -> str:
    alphabet = string.printable + "Έγγραφαрésumé日本😀\u202e\x00\x7f\ufeff"
    return "".join(chance.choice(alphabet) for _ in range(chance.randrange(length)))


def random_name(chance: random.Random) -> str:
    pieces = [chance.choice(NAME_PIECES) if chance.random() < 0.4 else random_text(chance, 12)
              for _ in range(chance.randrange(1, 6))]
    return chance.choice(["", "/", "\\"]).join(pieces)


def random_fingerprint(chance: random.Random) -> str:
    length = chance.choice([40, 40, 64, 16, 39, 0])
    return "".join(chance.choice("0123456789ABCDEFabcdefXYZ" if chance.random() < 0.1 else "0123456789ABCDEF")
                   for _ in range(length))


def random_status_line(chance: random.Random) -> str:
    word = chance.choice(STATUS_WORDS)
    fields = [random_fingerprint(chance) if chance.random() < 0.6 else random_text(chance, 10).replace("\n", " ")
              for _ in range(chance.randrange(0, 12))]
    return " ".join(["[GNUPG:]", word, *fields])


def random_status_report(chance: random.Random) -> str:
    lines = []
    for _ in range(chance.randrange(0, 14)):
        if chance.random() < 0.15:
            lines.append(random_text(chance, 60).replace("\r", ""))  # GnuPG's own words, in between
        else:
            lines.append(random_status_line(chance))
    return "\n".join(lines)


class ArchiveNameFuzz(unittest.TestCase):
    def test_a_name_inside_an_archive_is_refused_or_stays_inside(self):
        for iteration in range(ITERATIONS):
            name = random_name(generator("member", iteration))
            with self.subTest(seed=SEED, iteration=iteration, name=name):
                try:
                    parts = archive._member_parts(name)
                except archive.ArchiveError:
                    continue
                self.assertTrue(parts)
                for part in parts:
                    self.assertTrue(archive.is_safe_name_part(part), part)
                    self.assertNotIn(part, ("", ".", ".."))
                    self.assertFalse(set(part) & set("/\\:"), part)
                base = PurePosixPath("/restore")
                self.assertTrue(str(base.joinpath(*parts)).startswith("/restore/"))

    def test_names_made_when_packing_always_unpack_side_by_side(self):
        for iteration in range(ITERATIONS):
            chance = generator("pack", iteration)
            relatives = []
            for _ in range(chance.randrange(1, 8)):
                parts = [random_name(chance).replace("/", "").replace("\\", "") or "x"
                         for _ in range(chance.randrange(1, 4))]
                relatives.append("/".join(parts))
            with self.subTest(seed=SEED, iteration=iteration, relatives=relatives):
                names = archive.member_names(relatives)
                self.assertEqual(len(names), len(relatives))
                for name in names:
                    archive._member_parts(name)  # Raises if unpacking would refuse it.
                folded = [tuple(part.casefold() for part in name.split("/")) for name in names]
                self.assertEqual(len(set(folded)), len(folded), "two files would land on one name")
                folders = {parts[:depth] for parts in folded for depth in range(1, len(parts))}
                self.assertFalse(folders & set(folded), "a file and a folder would share a name")

    def test_a_mangled_zip_is_refused_or_unpacks_only_inside_its_folder(self):
        good = io.BytesIO()
        with zipfile.ZipFile(good, "w", compression=zipfile.ZIP_DEFLATED) as made:
            made.writestr("Taxes/return.pdf", b"%PDF " + bytes(range(256)) * 20)
            made.writestr("notes.txt", "Τεστ résumé\r\n" * 30)
            made.writestr("empty/", b"")
            made.comment = archive.MARKER
        original = good.getvalue()
        with tempfile.TemporaryDirectory(prefix="myobfuzz") as temporary:
            root = Path(temporary)
            for iteration in range(max(ITERATIONS // 6, 20)):
                chance = generator("zip", iteration)
                data = bytearray(original)
                for _ in range(chance.randrange(1, 6)):
                    data[chance.randrange(len(data))] = chance.randrange(256)
                path = root / f"{iteration}.zip"
                path.write_bytes(bytes(data))
                folder = root / f"out-{iteration}"
                folder.mkdir()
                with self.subTest(seed=SEED, iteration=iteration):
                    try:
                        archive.extract(path, folder, lambda: None)
                    except archive.ArchiveError:
                        pass
                    # Every zip, and every out-N folder, is this test's own. Anything else escaped.
                    outside = [p for p in root.iterdir() if p.suffix != ".zip" and not p.name.startswith("out-")]
                    self.assertEqual(outside, [])
                    for written in folder.rglob("*"):
                        self.assertTrue(written.resolve().is_relative_to(folder.resolve()), written)


class RecordFuzz(unittest.TestCase):
    def test_a_checksum_file_from_anywhere_never_breaks_reading(self):
        for iteration in range(ITERATIONS):
            chance = generator("sums", iteration)
            lines = []
            for _ in range(chance.randrange(0, 10)):
                digest = "".join(chance.choice("0123456789abcdefABCDEFg") for _ in range(chance.choice([64, 63, 65])))
                lines.append(chance.choice([f"{digest}  {random_name(chance)}", f"{digest} *{random_name(chance)}",
                                            random_text(chance, 80), f"# {random_text(chance)}", ""]))
            text = chance.choice(["\n", "\r\n", "\r"]).join(lines)
            with self.subTest(seed=SEED, iteration=iteration):
                found, unreadable = records.read_checksum_file(text, "fuzz")
                self.assertGreaterEqual(unreadable, 0)
                for record in found:
                    self.assertRegex(record.sha256, r"^[0-9a-f]{64}$")
                    self.assertNotIn("\\", record.path)

    def test_a_damaged_record_file_never_stops_a_restore(self):
        with tempfile.TemporaryDirectory(prefix="myobfuzz") as temporary:
            path = Path(temporary) / "records.jsonl"
            for iteration in range(ITERATIONS):
                chance = generator("ledger", iteration)
                good = {"sha256": "a" * 64, "name": "a.gpg", "path": "a.gpg", "size": 1}
                lines = []
                for _ in range(chance.randrange(0, 6)):
                    kind = chance.randrange(6)
                    if kind == 0:
                        lines.append(json.dumps(good))
                    elif kind == 1:
                        mangled = dict(good)
                        mangled[chance.choice(list(good))] = chance.choice([None, [], {}, 1.5, -1, "x", 10**40, True])
                        lines.append(json.dumps(mangled))
                    elif kind == 2:
                        depth = chance.choice([10, 1000, 100000])
                        lines.append("[" * depth + "]" * depth)
                    elif kind == 3:
                        lines.append(json.dumps(chance.choice([[], 7, "text", None, [good]])))
                    elif kind == 4:
                        lines.append(random_text(chance, 120))
                    else:
                        lines.append(json.dumps(good)[: chance.randrange(1, 40)])
                path.write_text("\n".join(lines), encoding="utf-8", errors="surrogatepass")
                with self.subTest(seed=SEED, iteration=iteration):
                    ledger = records.Ledger(path).load()
                    for record in ledger.records:
                        self.assertRegex(record.sha256, r"^[0-9a-f]{64}$")


class StatusFuzz(unittest.TestCase):
    def test_a_signature_report_is_never_called_verified_without_proof(self):
        for iteration in range(ITERATIONS * 3):
            chance = generator("signatures", iteration)
            stderr = random_status_report(chance)
            expected = [random_fingerprint(chance) for _ in range(chance.choice([0, 0, 1]))]
            with self.subTest(seed=SEED, iteration=iteration):
                try:
                    verification = signatures.read(stderr, expected)
                except ValueError:
                    continue  # An expected fingerprint that isn't one: refused before anything is read.
                status = verification.status
                refused = signatures.refusal(verification)
                self.assertEqual(refused is None, status in ("unsigned", "verified", "unverified", "revoked",
                                                             "expired"), status)
                if status == "verified":
                    signer = verification.signer
                    self.assertTrue(signer.valid and signer.usable and not signer.problems)
                    self.assertRegex(signer.fingerprint, r"^[0-9A-F]+$")
                    self.assertTrue(signer.key_verified or signer.matches(verification.expected))
                if "[GNUPG:] BADSIG" in stderr:
                    # Wherever a bad signature appears, the file is refused, whatever the heading says.
                    self.assertIsNotNone(refused, status)
                signatures.headline(verification)
                signatures.explanation(verification)

    def test_any_status_report_gets_an_explanation_never_a_crash(self):
        for iteration in range(ITERATIONS * 3):
            stderr = random_status_report(generator("failure", iteration))
            for operation in ("encrypt", "restore"):
                with self.subTest(seed=SEED, iteration=iteration, operation=operation):
                    failure = describe_failure(stderr, operation)
                    self.assertIsInstance(failure, GpgFailure)
                    self.assertTrue(str(failure))


class StrengthFuzz(unittest.TestCase):
    def test_any_passphrase_gets_a_verdict_that_never_repeats_it(self):
        for iteration in range(ITERATIONS * 3):
            chance = generator("strength", iteration)
            passphrase = random_text(chance, 60) if chance.random() < 0.7 else " ".join(
                chance.choice(["password", "summer", "Έγγραφα", "qwerty", "2026", "!", "dragon", "x" * 30])
                for _ in range(chance.randrange(1, 5)))
            with self.subTest(seed=SEED, iteration=iteration):
                assessment = strength.assess(passphrase)
                self.assertIn(assessment.level, typing.get_args(strength.Level))
                if len(passphrase) >= 6 and not re.fullmatch(r"\W*", passphrase):
                    self.assertNotIn(passphrase, assessment.message)


if __name__ == "__main__":
    unittest.main()
