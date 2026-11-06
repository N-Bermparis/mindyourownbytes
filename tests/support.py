"""Shared test helpers. Every real gpg call runs against a throwaway home directory."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from mindyourownbytes.core import find_gpg, is_valid_gpg


def require_gpg() -> str:
    """Return a usable gpg, or skip.

    CI sets MYOB_REQUIRE_GPG so that a missing GnuPG fails the build rather than
    silently skipping every test that exercises real cryptography.
    """
    binary = find_gpg()
    if binary and is_valid_gpg(binary):
        return binary
    if os.environ.get("MYOB_REQUIRE_GPG"):
        raise RuntimeError("MYOB_REQUIRE_GPG is set but no usable GnuPG was found")
    raise unittest.SkipTest("GnuPG is not installed")


class GpgTestCase(unittest.TestCase):
    """Isolates GNUPGHOME and stops the agent it started, so nothing leaks."""

    def setUp(self) -> None:
        self.gpg = require_gpg()
        self._temp = tempfile.TemporaryDirectory(prefix="myobtest", ignore_cleanup_errors=True)
        self.addCleanup(self._temp.cleanup)
        self.root = Path(self._temp.name).resolve()
        self.home = self.root / "gnupg"
        self.home.mkdir(mode=0o700)
        patcher = patch.dict(os.environ, {"GNUPGHOME": str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._stop_agent)

    def _stop_agent(self) -> None:
        gpgconf = Path(self.gpg).with_name("gpgconf.exe" if os.name == "nt" else "gpgconf")
        if gpgconf.is_file():
            subprocess.run([str(gpgconf), "--homedir", str(self.home), "--kill", "all"],
                           capture_output=True, check=False)
            time.sleep(0.05)

    def run_gpg(self, *args: str, **kwargs) -> subprocess.CompletedProcess:
        return subprocess.run([self.gpg, "--batch", "--no-tty", *args], capture_output=True,
                              check=False, timeout=60, **kwargs)

    def generate_key(self, uid: str = "Test <test@example.invalid>", expire: str = "1y", passphrase: str = "",
                     algorithm: str = "default") -> str:
        """Create a key in the isolated home, with no passphrase by default. Returns its fingerprint."""
        result = self.run_gpg("--passphrase", passphrase, "--pinentry-mode", "loopback",
                              "--quick-generate-key", uid, algorithm, "default", expire)
        if result.returncode != 0:
            self.skipTest(f"gpg-agent could not create a key here: {result.stderr[-200:]!r}")
        listing = self.run_gpg("--with-colons", "--fingerprint", "--list-keys", uid).stdout.decode()
        return next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))

    def packets(self, path: Path, passphrase: str = "") -> str:
        """Decode a file's OpenPGP packet structure, as anyone holding it could."""
        args = ["--list-packets", "--pinentry-mode", "loopback", "--passphrase", passphrase, str(path)]
        return self.run_gpg(*args).stdout.decode(errors="replace")


def stderr_with_statuses(*statuses: str) -> str:
    """Build fake gpg stderr for tests that mock the subprocess."""
    return "\n".join(f"[GNUPG:] {status}" for status in statuses) + "\n"

