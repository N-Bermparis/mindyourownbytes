"""An encrypted, opt-in store of named passphrases.

The vault is one ordinary GnuPG file holding JSON, encrypted under a master
passphrase. This module implements no cryptography, and because the file is
plain OpenPGP there is no lock-in: ``gpg --decrypt vault.gpg`` prints every
saved passphrase, so losing this application never means losing access.

The plaintext only ever exists in pipes and in this process's memory, never on
disk. Python cannot reliably wipe strings from memory, and that limit is
documented in docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from mindyourownbytes.core import SYMMETRIC_ARGS, describe_failure, encode_passphrase, run_gpg_pipe

VAULT_FORMAT = "mindyourownbytes-vault"
VAULT_VERSION = 1
MIN_MASTER_LENGTH = 12

#: No 0/O or 1/I/L, so a generated passphrase survives being copied by hand.
_GENERATED_ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"


class VaultError(Exception):
    """The vault could not be used. The message is safe to show the user."""


class WrongMasterPassphrase(VaultError):
    pass


@dataclass
class VaultEntry:
    label: str
    passphrase: str
    note: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    created: str = field(default_factory=lambda: datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def __repr__(self) -> str:
        # Keeps the secret out of tracebacks and any accidental logging.
        return f"VaultEntry(label={self.label!r}, id={self.id!r})"


def default_vault_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "mindyourownbytes" / "vault.gpg"


def generate_passphrase(groups: int = 6, group_size: int = 5) -> str:
    """Random passphrase. The default holds about 147 bits, far beyond guessing."""
    return "-".join(
        "".join(secrets.choice(_GENERATED_ALPHABET) for _ in range(group_size))
        for _ in range(groups)
    )


def check_new_master(passphrase: str) -> None:
    """Every saved passphrase is only as strong as this one, so it has a floor."""
    encode_passphrase(passphrase)
    if len(passphrase) < MIN_MASTER_LENGTH:
        raise VaultError(f"The master passphrase must be at least {MIN_MASTER_LENGTH} characters.")


class Vault:
    """A locked or unlocked view of one vault file."""

    def __init__(self, gpg: str, path: Path) -> None:
        self.gpg = gpg
        self.path = path
        self._entries: list[VaultEntry] | None = None
        self._master: str | None = None
        self._loaded_mtime: int | None = None

    def __repr__(self) -> str:
        state = "unlocked" if self.unlocked else "locked"
        return f"Vault({self.path}, {state})"

    @property
    def backup_path(self) -> Path:
        return self.path.with_name(self.path.stem + ".bak" + self.path.suffix)

    @property
    def exists(self) -> bool:
        return self.path.is_file()

    @property
    def unlocked(self) -> bool:
        return self._entries is not None

    @property
    def entries(self) -> list[VaultEntry]:
        if self._entries is None:
            raise VaultError("The vault is locked.")
        return list(self._entries)

    def create(self, master: str) -> None:
        check_new_master(master)
        if self.exists:
            raise VaultError(f"A vault already exists at {self.path}. It was not changed.")
        self._master = master
        self._entries = []
        try:
            self._save()
        except Exception:
            self.lock()
            raise

    def unlock(self, master: str) -> None:
        if not self.exists:
            raise VaultError(f"No vault was found at {self.path}.")
        secret = encode_passphrase(master)
        mtime = self.path.stat().st_mtime_ns
        self._entries = self._parse(self._decrypt(self.path, secret))
        self._master = master
        self._loaded_mtime = mtime

    def lock(self) -> None:
        """Drop references to all secrets. Python may keep copies until they're reused."""
        self._entries = None
        self._master = None
        self._loaded_mtime = None

    def add(self, label: str, passphrase: str, note: str = "") -> VaultEntry:
        entries = self.entries
        encode_passphrase(passphrase)
        cleaned = label.strip()
        if not cleaned:
            raise VaultError("Give this passphrase a name, so you can recognise it later.")
        if any(entry.label.casefold() == cleaned.casefold() for entry in entries):
            raise VaultError(f"A saved passphrase named “{cleaned}” already exists.")
        entry = VaultEntry(cleaned, passphrase, note.strip())
        self._commit([*entries, entry])
        return entry

    def remove(self, entry_id: str) -> None:
        self._commit([entry for entry in self.entries if entry.id != entry_id])

    def rename(self, entry_id: str, label: str) -> None:
        cleaned = label.strip()
        if not cleaned:
            raise VaultError("The name cannot be empty.")
        entries = self.entries
        if any(entry.label.casefold() == cleaned.casefold() and entry.id != entry_id for entry in entries):
            raise VaultError(f"A saved passphrase named “{cleaned}” already exists.")
        renamed = [
            VaultEntry(cleaned, entry.passphrase, entry.note, entry.id, entry.created)
            if entry.id == entry_id else entry
            for entry in entries
        ]
        self._commit(renamed)

    def change_master(self, current: str, new: str) -> None:
        if self._master is None:
            raise VaultError("The vault is locked.")
        if not hmac.compare_digest(current.encode(), self._master.encode()):
            raise WrongMasterPassphrase("The current master passphrase is not correct.")
        check_new_master(new)
        previous = self._master
        self._master = new
        try:
            self._save(keep_backup=False)
        except Exception:
            self._master = previous
            raise
        # A backup under the old master would stay readable by anyone who learned
        # it, which is usually why a master gets changed. The new vault is already
        # committed by now, so a failure here must not look like the change failed.
        try:
            self.backup_path.unlink(missing_ok=True)
        except OSError as exc:
            raise VaultError(
                "The master passphrase was changed, but the old backup could not be deleted. It still "
                f"opens with the old passphrase, so please delete it yourself: {self.backup_path}"
            ) from exc

    def _commit(self, entries: list[VaultEntry]) -> None:
        """Change the file first, so memory never claims what the disk doesn't hold."""
        previous = self._entries
        self._entries = entries
        try:
            self._save()
        except Exception:
            self._entries = previous
            raise

    def _decrypt(self, path: Path, secret: bytes) -> bytes:
        try:
            code, output, stderr = run_gpg_pipe(self.gpg, ["--output", "-", "--decrypt", "--", str(path)], secret)
        except (OSError, subprocess.SubprocessError) as exc:
            raise VaultError(f"Could not run GnuPG: {exc}") from exc
        if code != 0:
            if describe_failure(stderr).wrong_secret:
                raise WrongMasterPassphrase("That master passphrase did not open the vault.")
            raise VaultError(f"The vault file is damaged or could not be read. Try restoring {self.backup_path.name}.")
        if "[GNUPG:] DECRYPTION_OKAY" not in stderr:
            # Same forgery check as restoring a file: gpg exits 0 on unencrypted
            # OpenPGP data, which would let anyone able to write this file plant
            # passphrases of their choosing with no master passphrase at all.
            raise VaultError("The vault file is not encrypted, so it cannot be trusted. It was not loaded.")
        return output

    @staticmethod
    def _serialize(entries: list[VaultEntry]) -> bytes:
        document = {"format": VAULT_FORMAT, "version": VAULT_VERSION, "entries": [asdict(e) for e in entries]}
        return json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")

    @staticmethod
    def _parse(data: bytes) -> list[VaultEntry]:
        try:
            document = json.loads(data.decode("utf-8"))
            if document["format"] != VAULT_FORMAT:
                raise ValueError("unexpected format")
            if document["version"] > VAULT_VERSION:
                raise VaultError("This vault was created by a newer version. Please update the application.")
            entries = []
            for raw in document["entries"]:
                if not isinstance(raw["label"], str) or not isinstance(raw["passphrase"], str):
                    raise ValueError("label and passphrase must be text")
                encode_passphrase(raw["passphrase"])
                entries.append(VaultEntry(
                    raw["label"], raw["passphrase"], str(raw.get("note", "")),
                    str(raw.get("id") or uuid.uuid4().hex), str(raw.get("created", "")),
                ))
            return entries
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            # Only the error type, as the data could hold secrets.
            raise VaultError(f"The vault contents are not valid ({type(exc).__name__}).") from exc

    def _save(self, keep_backup: bool = True) -> None:
        """Write, prove the new file is readable, and only then replace the old one.

        A corrupt vault could lock someone out of everything it protects, so the
        previous version is never touched until the new one has been decrypted
        and compared byte for byte.
        """
        assert self._master is not None and self._entries is not None
        if self.exists and self._loaded_mtime is not None and self.path.stat().st_mtime_ns != self._loaded_mtime:
            raise VaultError("The vault changed on disk, perhaps in another window. Lock it, "
                             "unlock it again, then repeat your change.")
        secret = encode_passphrase(self._master)
        plaintext = self._serialize(self._entries)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        pending = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex[:12]}.tmp")
        previous = pending.with_suffix(".prev")
        try:
            code, _, stderr = run_gpg_pipe(self.gpg, [*SYMMETRIC_ARGS, "--output", str(pending)], secret, plaintext)
            if code != 0 or not pending.is_file():
                lines = [line for line in stderr.splitlines() if not line.startswith("[GNUPG:] ")]
                raise VaultError(f"GnuPG could not write the vault: {lines[-1] if lines else 'no details'}")
            if os.name != "nt":
                os.chmod(pending, 0o600)
            if self._decrypt(pending, secret) != plaintext:
                raise VaultError("The vault could not be verified after writing. Your saved copy was not changed.")
            if self.exists and keep_backup:
                # Copy then replace, so a real vault exists at every moment.
                shutil.copy2(self.path, previous)
                os.replace(previous, self.backup_path)
            os.replace(pending, self.path)
            self._loaded_mtime = self.path.stat().st_mtime_ns
        except (OSError, subprocess.SubprocessError) as exc:
            raise VaultError(f"The vault could not be saved: {exc}") from exc
        finally:
            for leftover in (pending, previous):
                leftover.unlink(missing_ok=True)
