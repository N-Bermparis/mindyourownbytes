"""What a decrypted file's signatures prove, read from GnuPG's machine-readable status lines.

Four different things can be true of a restored file, and this module keeps them apart:

1. **It was encrypted** (confidentiality): GnuPG said DECRYPTION_OKAY. That's checked in ``core``.
2. **It wasn't changed after it was made** (integrity): the integrity check passed, or a signature verified.
3. **It was made by the holder of a particular key** (authenticity): a signature verified, and GnuPG
   reported VALIDSIG with that key's fingerprint.
4. **That key belongs to who you think** (trust): GnuPG considers the key valid, because it's yours or
   you certified it in Kleopatra (TRUST_ULTIMATE or TRUST_FULLY), or you named its fingerprint yourself.

Decrypting proves only the first two. A file encrypted to your public key can have been made by anyone
who has that public key, which is public. Only the third and fourth say who made it. A name or email
address in a key proves nothing by itself, because anyone can make a key with any name, so identity is
always shown together with the fingerprint, and a key counts as verified only on GnuPG's say-so or yours.

Decisions use status tokens rather than GnuPG's human-readable text, which is translated. GOODSIG alone is
never enough: a signature counts as valid only with a matching VALIDSIG, and anything duplicated,
missing, or contradictory within one signature's report makes the whole result "incomplete", which is
refused. GnuPG 2.2.8 and later escape the text they print around status lines (CVE-2018-12020).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

Status = Literal["unsigned", "verified", "unverified", "revoked", "expired", "unexpected", "bad", "unverifiable",
                 "incomplete"]

#: Results that mean the signature itself is mathematically correct.
_VALID_RESULTS = ("GOODSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG")
_RESULTS = (*_VALID_RESULTS, "BADSIG", "ERRSIG")
_TRUST = {
    "TRUST_ULTIMATE": "ultimate", "TRUST_FULLY": "full", "TRUST_MARGINAL": "marginal",
    "TRUST_NEVER": "never", "TRUST_UNDEFINED": "undefined",
}
#: The validity GnuPG gives your own keys, and keys you've certified.
VERIFIED_VALIDITY = frozenset({"ultimate", "full"})
#: libgpg-error's "No public key", as ERRSIG reports it.
_NO_PUBKEY = 9
_HEX = re.compile(r"[0-9A-F]+")


def normalize_fingerprint(fingerprint: str) -> str:
    """Uppercase hex, without spaces. Raises ValueError for anything that isn't a full fingerprint."""
    cleaned = re.sub(r"\s+", "", fingerprint).upper()
    if not re.fullmatch(r"[0-9A-F]{40}|[0-9A-F]{64}", cleaned):
        raise ValueError(f"Not a full OpenPGP fingerprint: {fingerprint!r}")
    return cleaned


def spaced(fingerprint: str) -> str:
    """A fingerprint in groups of four, the way people compare them."""
    return " ".join(fingerprint[index:index + 4] for index in range(0, len(fingerprint), 4))


def _unescape(text: str) -> str:
    """Undo the %XX escaping GnuPG uses for user IDs in status lines."""
    raw = re.sub(rb"%([0-9A-Fa-f]{2})", lambda match: bytes([int(match.group(1), 16)]), text.encode("utf-8"))
    return raw.decode("utf-8", errors="replace")


@dataclass
class _Block:
    """What GnuPG reported about one signature, between its NEWSIG and the next."""

    result: str = ""
    key_id: str = ""
    user_id: str = ""
    fingerprint: str = ""
    primary_fingerprint: str = ""
    validity: str = "unknown"
    error_code: int | None = None
    missing_key: bool = False
    problems: list[str] = field(default_factory=list)

    def set_once(self, name: str, value) -> None:
        if getattr(self, name) not in ("", "unknown", None):
            self.problems.append(f"{name} reported twice")
        setattr(self, name, value)


@dataclass(frozen=True)
class Signature:
    """One signature on a decrypted file, as GnuPG reported it."""

    #: GOODSIG, EXPSIG, EXPKEYSIG, REVKEYSIG, BADSIG, ERRSIG, or "" if GnuPG reported no result.
    result: str
    key_id: str
    #: The name the key gives itself. Unverified: anyone can make a key with any name.
    user_id: str
    #: The key that made the signature, which may be a subkey, from VALIDSIG.
    fingerprint: str
    #: The key it belongs to. This is what's compared with expected signers, and shown to people.
    primary_fingerprint: str
    #: ultimate, full, marginal, never, undefined, or unknown if GnuPG didn't say.
    validity: str
    error_code: int | None
    missing_key: bool
    #: Why GnuPG's report about this signature can't be relied on. Empty when it can.
    problems: tuple[str, ...]

    @property
    def valid(self) -> bool:
        """The signature is mathematically correct for the data, by the key in ``fingerprint``."""
        return self.result in _VALID_RESULTS and bool(self.fingerprint) and not self.problems

    @property
    def revoked(self) -> bool:
        return self.result == "REVKEYSIG"

    @property
    def usable(self) -> bool:
        """Valid, and neither made with a revoked key nor past the signature's own expiry date."""
        return self.valid and self.result not in ("REVKEYSIG", "EXPSIG")

    @property
    def key_verified(self) -> bool:
        """GnuPG says the key really belongs to its owner: it's yours, or you certified it."""
        return self.usable and self.validity in VERIFIED_VALIDITY

    def matches(self, fingerprints: frozenset[str]) -> bool:
        """Made by one of these keys, compared by fingerprint, never by name."""
        return self.usable and bool({self.fingerprint, self.primary_fingerprint} & fingerprints)

    def authenticates(self, expected: frozenset[str]) -> bool:
        """Says who made the file: made by an expected key if any were named, or else by a verified one."""
        return self.matches(expected) if expected else self.key_verified


@dataclass(frozen=True)
class Verification:
    """Everything a restore learned about who made a file."""

    #: True when a public key opened the file, so anyone who has that public key could have made it.
    encrypted_to_key: bool
    signatures: tuple[Signature, ...]
    #: Fingerprints a signature had to come from, if the caller named any.
    expected: frozenset[str] = frozenset()

    @property
    def status(self) -> Status:
        if not self.signatures:
            return "unsigned"
        if any(signature.result == "BADSIG" for signature in self.signatures):
            return "bad"
        if any(signature.result == "ERRSIG" for signature in self.signatures):
            return "unverifiable"
        if not all(signature.valid for signature in self.signatures):
            return "incomplete"
        if any(signature.authenticates(self.expected) for signature in self.signatures):
            return "verified"
        if self.expected:
            return "unexpected"
        if all(signature.revoked for signature in self.signatures):
            return "revoked"
        if all(signature.result == "EXPKEYSIG" for signature in self.signatures):
            # GnuPG gives no trust verdict for a key that has expired, so it can't say who made the file.
            return "expired"
        return "unverified"

    @property
    def signer(self) -> Signature | None:
        """The signature the status is about: one that says who made the file, or else the first."""
        for signature in self.signatures:
            if signature.authenticates(self.expected):
                return signature
        return self.signatures[0] if self.signatures else None

    @property
    def authenticated(self) -> bool:
        """A valid signature by a key you've verified, or by one you named."""
        return self.status == "verified"


def read(stderr: str, expected: Iterable[str] = ()) -> Verification:
    """Collect the signatures GnuPG reported while decrypting, from its status lines."""
    blocks: list[_Block] = []
    encrypted_to_key = False

    def current() -> _Block:
        if not blocks:
            blocks.append(_Block())
            blocks[-1].problems.append("result without NEWSIG")
        return blocks[-1]

    for line in stderr.splitlines():
        if not line.startswith("[GNUPG:] "):
            continue
        keyword, _, rest = line[len("[GNUPG:] "):].partition(" ")
        fields = rest.split()
        if keyword == "DECRYPTION_KEY":
            encrypted_to_key = True
        elif keyword == "NEWSIG":
            blocks.append(_Block())
        elif keyword in _RESULTS:
            block = current()
            if block.result:
                block.problems.append("two results for one signature")
            block.result = keyword
            block.key_id = fields[0].upper() if fields else ""
            if keyword == "ERRSIG":
                block.error_code = int(fields[5]) if len(fields) > 5 and fields[5].isdigit() else None
                if len(fields) > 6 and _HEX.fullmatch(fields[6].upper()):
                    block.primary_fingerprint = fields[6].upper()
            else:
                block.user_id = _unescape(rest.partition(" ")[2])
        elif keyword == "NO_PUBKEY" and blocks:
            blocks[-1].missing_key = True
        elif keyword == "VALIDSIG":
            block = current()
            fingerprint = fields[0].upper() if fields else ""
            primary = fields[9].upper() if len(fields) > 9 else fingerprint
            if not (_HEX.fullmatch(fingerprint) and _HEX.fullmatch(primary)):
                block.problems.append("VALIDSIG without a fingerprint")
            block.set_once("fingerprint", fingerprint)
            block.primary_fingerprint = primary
        elif keyword in _TRUST:
            current().set_once("validity", _TRUST[keyword])
    signatures = tuple(_finish(block) for block in blocks)
    return Verification(encrypted_to_key, signatures, frozenset(normalize_fingerprint(f) for f in expected))


def _finish(block: _Block) -> Signature:
    problems = list(block.problems)
    if not block.result:
        problems.append("no result")
    if block.result in _VALID_RESULTS:
        if not block.fingerprint:
            problems.append("no VALIDSIG")
        elif block.key_id and not any(
            fingerprint.endswith(block.key_id) or fingerprint.startswith(block.key_id) or fingerprint == block.key_id
            for fingerprint in (block.fingerprint, block.primary_fingerprint)
        ):
            problems.append("VALIDSIG names a different key")
    if block.result in ("BADSIG", "ERRSIG") and block.fingerprint:
        problems.append("VALIDSIG for a failed signature")
    return Signature(block.result, block.key_id, block.user_id, block.fingerprint,
                     block.primary_fingerprint or block.fingerprint, block.validity, block.error_code,
                     block.missing_key or block.error_code == _NO_PUBKEY, tuple(problems))


def refusal(verification: Verification, *, require_verified: bool = False) -> str | None:
    """Why this file mustn't be restored, in words people can read, or None if it may be.

    A bad signature, one that can't be checked, a report that can't be relied on, and a signer other than
    the ones expected are always refused. ``require_verified`` also refuses a file opened with a key that
    isn't signed by a verified key, because anyone with the public key could have made it. Files opened
    with a passphrase don't need a signature: only someone who knew the passphrase could have made them.
    """
    status = verification.status
    signer = verification.signer
    who = spaced(signer.primary_fingerprint) if signer is not None and signer.primary_fingerprint else "unknown"
    if status == "bad":
        return ("This file's signature is invalid, so it was altered or forged after it was signed. "
                "Nothing was restored.")
    if status == "unverifiable":
        if signer is not None and signer.missing_key:
            return ("This file decrypted, but it is signed by a key you don't have, so the signature can't be "
                    "checked. Import the signer's public key and try again.")
        code = signer.error_code if signer is not None else None
        return (f"This file decrypted, but GnuPG couldn't check its signature (error {code}), so it wasn't "
                "trusted. Nothing was restored.")
    if status == "incomplete":
        return ("GnuPG's report on this file's signature was incomplete or contradictory, so it wasn't trusted. "
                "Nothing was restored.")
    if status == "unexpected":
        return (f"This file is signed, but not by a key you expected: it was signed with {who}. Nothing was "
                "restored.")
    if require_verified and verification.encrypted_to_key and status != "verified":
        if status == "unsigned":
            return ("This file isn't signed, so anyone with your public key could have made it, and your settings "
                    "ask for a signature from a key you've verified. Nothing was restored.")
        if status == "revoked":
            return (f"This file is signed with a key that has been revoked ({who}), and your settings ask for a "
                    "signature from a key you've verified. Nothing was restored.")
        if status == "expired":
            return (f"This file is signed with a key that has expired ({who}), so GnuPG no longer vouches for it, "
                    "and your settings ask for a signature from a key you've verified. If it's your key, extend "
                    "its expiry date in Kleopatra, then try again. Nothing was restored.")
        return (f"This file is signed with a key you haven't verified ({who}), and your settings ask for a "
                "signature from a key you've verified. Nothing was restored.")
    return None


def headline(verification: Verification) -> str:
    """A few words for a restored file's status, such as "signed by Alex". Empty when there's nothing to add.

    A name is only shown for a key that's verified, and the fingerprint is always in ``explanation``.
    """
    status = verification.status
    signer = verification.signer
    if status == "unsigned":
        return "not signed" if verification.encrypted_to_key else ""
    if status == "verified" and signer is not None:
        name = signer.user_id.split("<")[0].strip() or f"key …{signer.primary_fingerprint[-8:]}"
        return f"signed by {name}"
    if status == "revoked":
        return "signed with a revoked key"
    if status == "expired":
        return "signed with a key that has expired"
    if status == "unverified":
        return "signed with a key you haven't verified"
    return ""


def explanation(verification: Verification) -> str:
    """What the signature does and doesn't prove, for a tooltip, in plain words."""
    status = verification.status
    signer = verification.signer
    if status == "unsigned":
        if verification.encrypted_to_key:
            return ("Not signed. It decrypted with your key, but anyone who has your public key could have made "
                    "it, so nothing shows who did.")
        return "Not signed. It decrypted with the passphrase, so whoever made it knew the passphrase."
    if signer is None or status not in ("verified", "unverified", "revoked", "expired"):
        return refusal(verification) or ""
    key = spaced(signer.primary_fingerprint)
    claimed = f"“{signer.user_id}”" if signer.user_id else "no name"
    if status == "verified":
        why = ("you named it as a signer you expect" if verification.expected
               else "GnuPG trusts it ultimately, as it does your own keys" if signer.validity == "ultimate"
               else "you've certified it")
        expiry = (" The key has expired since, which doesn't change what it signed before then."
                  if signer.result == "EXPKEYSIG" else "")
        return (f"Signed with the key {key}, which says it belongs to {claimed}. GnuPG checked the signature, so "
                f"the file hasn't changed since it was signed, and the key is one you can rely on, because {why}."
                f"{expiry}")
    if status == "revoked":
        return (f"Signed with the key {key}, which says it belongs to {claimed}, but its owner has revoked it. "
                "The signature is correct, but a revoked key may have been stolen, so it doesn't show who made "
                "the file.")
    if status == "expired":
        return (f"Signed with the key {key}, which says it belongs to {claimed}. The signature is correct, so the "
                "file hasn't changed since it was signed, but the key has expired since, and GnuPG no longer "
                "vouches for an expired key, so this can't show who made the file. If it's your key, extend its "
                "expiry date in Kleopatra, and restore the file again.")
    return (f"Signed with the key {key}, which says it belongs to {claimed}. The signature is correct, so the "
            "file hasn't changed since it was signed. But you haven't verified this key, and anyone can make a "
            "key with any name. Compare the fingerprint with its owner, then certify it in Kleopatra.")
