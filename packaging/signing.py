"""Optional code signing for the downloads. Without the settings below, the downloads are built unsigned,
say so, and nothing pretends otherwise.

Nothing here holds, prints, or passes on a private key. Each system's own tool signs, with a key it
reaches by itself:

* **Windows**: ``signtool`` signs with a certificate in the Windows certificate store, chosen by its
  SHA-1 thumbprint. Code-signing keys now have to live in hardware: a USB token, or a cloud service whose
  key storage provider puts the certificate in the store. Setting that up is the CA's or service's
  own step, in the workflow, before the build. Then set:

      MYOB_SIGN_CERT_SHA1      the certificate's thumbprint, 40 hex digits (not a secret)
      MYOB_SIGN_TIMESTAMP_URL  the RFC 3161 timestamp server your CA names

  The app's own executable is signed before it goes into the zip and the installer, then the installer
  itself. The included GnuPG files already carry g10 Code's signature, so they're left alone.

* **macOS**: ``codesign`` signs every executable part of the app, inside out, then the app, with the
  hardened runtime and a secure timestamp, using a Developer ID Application identity from a keychain
  the workflow unlocked. ``notarytool`` sends the disk image to Apple and ``stapler`` attaches the result.

      MYOB_MAC_SIGN_IDENTITY   such as "Developer ID Application: Name (TEAMID)" (not a secret)
      MYOB_NOTARY_KEY_PATH     path to an App Store Connect API key (.p8), written by the workflow
      MYOB_NOTARY_KEY_ID, MYOB_NOTARY_ISSUER   that key's ID and issuer (not secrets)

After signing, every signature is checked with the system's own verifier, and the build fails if any
check does. Half the settings is an error, never a quietly unsigned build.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class SigningError(RuntimeError):
    pass


@dataclass(frozen=True)
class WindowsSigning:
    thumbprint: str
    timestamp_url: str


@dataclass(frozen=True)
class MacSigning:
    identity: str
    #: (key path, key ID, issuer), or None to sign without notarizing, which Gatekeeper still warns about.
    notary: tuple[Path, str, str] | None


def _settings(names: tuple[str, ...]) -> dict[str, str] | None:
    values = {name: os.environ.get(name, "").strip() for name in names}
    if not any(values.values()):
        return None
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise SigningError(f"Signing is half set up: {', '.join(missing)} missing. Set all of them, or none.")
    return values


def windows_signing() -> WindowsSigning | None:
    values = _settings(("MYOB_SIGN_CERT_SHA1", "MYOB_SIGN_TIMESTAMP_URL"))
    if values is None:
        return None
    thumbprint = values["MYOB_SIGN_CERT_SHA1"].replace(" ", "").upper()
    if not re.fullmatch(r"[0-9A-F]{40}", thumbprint):
        raise SigningError("MYOB_SIGN_CERT_SHA1 must be a certificate's SHA-1 thumbprint: 40 hex digits.")
    url = values["MYOB_SIGN_TIMESTAMP_URL"]
    if not re.fullmatch(r"https?://[^\s\"']+", url):
        raise SigningError("MYOB_SIGN_TIMESTAMP_URL must be the http(s) address of a timestamp server.")
    return WindowsSigning(thumbprint, url)


def mac_signing() -> MacSigning | None:
    identity = os.environ.get("MYOB_MAC_SIGN_IDENTITY", "").strip()
    notary = _settings(("MYOB_NOTARY_KEY_PATH", "MYOB_NOTARY_KEY_ID", "MYOB_NOTARY_ISSUER"))
    if not identity:
        if notary is not None:
            raise SigningError("Notarizing needs a signed app: set MYOB_MAC_SIGN_IDENTITY too.")
        return None
    if not identity.startswith("Developer ID Application:"):
        raise SigningError("MYOB_MAC_SIGN_IDENTITY must be a Developer ID Application identity.")
    if notary is None:
        return MacSigning(identity, None)
    key = Path(notary["MYOB_NOTARY_KEY_PATH"])
    if not key.is_file():
        raise SigningError("MYOB_NOTARY_KEY_PATH doesn't name a file.")
    return MacSigning(identity, (key, notary["MYOB_NOTARY_KEY_ID"], notary["MYOB_NOTARY_ISSUER"]))


def _run(command: list[str], what: str) -> subprocess.CompletedProcess:
    """Run a signing tool. Its output never includes a secret: there's none on its command line."""
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise SigningError(f"{what} failed ({result.returncode}): {(result.stderr or result.stdout)[-2000:]}")
    return result


def find_signtool() -> Path:
    kits = Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Windows Kits" / "10" / "bin"
    found = sorted(kits.glob("10.*/x64/signtool.exe"))
    if not found:
        raise SigningError("signtool.exe wasn't found. It comes with the Windows SDK.")
    return found[-1]


def sign_windows(files: list[Path], signing: WindowsSigning) -> None:
    """Sign with SHA-256 and an RFC 3161 timestamp, so signatures outlast the certificate, then verify each."""
    _run([str(find_signtool()), "sign", "/sha1", signing.thumbprint, "/fd", "SHA256", "/tr", signing.timestamp_url,
          "/td", "SHA256", "/d", "mindyourownbytes", *map(str, files)], "Signing")
    for file in files:
        verify_windows(file, signing.thumbprint)


def verify_windows(file: Path, thumbprint: str) -> None:
    """Windows' own check, which the app's users get: a valid chain, and the certificate that was meant."""
    script = ("$s = Get-AuthenticodeSignature -LiteralPath $env:MYOB_FILE; "
              "Write-Output \"$($s.Status)|$($s.SignerCertificate.Thumbprint)|$($s.TimeStamperCertificate -ne $null)\"")
    result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True,
                            text=True, check=False, env={**os.environ, "MYOB_FILE": str(file)})
    status, _, rest = result.stdout.strip().partition("|")
    signer, _, timestamped = rest.partition("|")
    if result.returncode != 0 or status != "Valid" or signer.upper() != thumbprint or timestamped != "True":
        raise SigningError(f"{file.name} isn't validly signed and timestamped by the expected certificate: "
                           f"{result.stdout.strip() or result.stderr.strip()}")


def _is_mach_o(path: Path) -> bool:
    try:
        with path.open("rb") as file:
            magic = file.read(4)
    except OSError:
        return False
    return magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf",
                     b"\xfe\xed\xfa\xce", b"\xbe\xba\xfe\xca")


def _codesign(path: Path, identity: str) -> None:
    _run(["codesign", "--force", "--timestamp", "--options", "runtime", "--sign", identity, str(path)],
         f"Signing {path.name}")


def sign_mac_app(app: Path, signing: MacSigning) -> None:
    """Sign every executable part, deepest first, then the app itself, then check it as Gatekeeper would."""
    parts = [path for path in app.rglob("*") if path.is_file() and not path.is_symlink() and _is_mach_o(path)]
    main = app / "Contents" / "MacOS" / app.stem
    for path in sorted(parts, key=lambda p: len(p.parts), reverse=True):
        if path != main:
            _codesign(path, signing.identity)
    _codesign(app, signing.identity)
    _run(["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app)], "Checking the app's signature")


def sign_mac_image(image: Path, signing: MacSigning) -> None:
    """Sign the disk image, notarize and staple it if Apple credentials are set, and check the result."""
    _run(["codesign", "--force", "--timestamp", "--sign", signing.identity, str(image)], "Signing the disk image")
    if signing.notary is None:
        print("The disk image is signed but not notarized, so Gatekeeper will still warn about it.", flush=True)
        return
    key, key_id, issuer = signing.notary
    submitted = _run(["xcrun", "notarytool", "submit", str(image), "--key", str(key), "--key-id", key_id,
                      "--issuer", issuer, "--wait", "--output-format", "json"], "Notarizing")
    if '"status":"Accepted"' not in submitted.stdout.replace(" ", ""):
        raise SigningError(f"Apple didn't accept the disk image: {submitted.stdout[-2000:]}")
    _run(["xcrun", "stapler", "staple", str(image)], "Stapling")
    _run(["xcrun", "stapler", "validate", str(image)], "Checking the stapled ticket")
    _run(["spctl", "--assess", "--type", "open", "--context", "context:primary-signature", "--verbose=2", str(image)],
         "Gatekeeper's check")


def describe(windows: WindowsSigning | None = None, mac: MacSigning | None = None) -> str:
    """One line for the build log. Says plainly when a download is unsigned."""
    if sys.platform == "win32":
        return (f"Signing with the certificate {windows.thumbprint}." if windows
                else "UNSIGNED: no signing certificate is configured, so Windows will warn about this download.")
    if sys.platform == "darwin":
        if mac is None:
            return "UNSIGNED: no Developer ID is configured, so macOS will refuse to open this download at first."
        return f"Signing as {mac.identity}" + (", and notarizing." if mac.notary else ", without notarizing.")
    return "Linux downloads aren't code-signed. The release's SHA256SUMS.txt can carry an OpenPGP signature."
