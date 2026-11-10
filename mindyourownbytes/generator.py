"""Random passphrases: words that are easy to type, or characters that pack in more strength.

Everything random here comes from Python's ``secrets`` module, which uses the operating system's
cryptographic random numbers. Because each passphrase is picked at random from a known set, its
strength can be stated exactly, which is never true of a passphrase someone makes up.

The words are EFF's Long Wordlist, by the Electronic Frontier Foundation: 7,776 common English
words, chosen to be easy to type and tell apart, with no word the start of another.
https://www.eff.org/dice. It's shipped exactly as EFF publishes it, and checked against this
file's SHA-256 before it's used, so a changed or shortened list can't quietly weaken anything.
"""

from __future__ import annotations

import functools
import hashlib
import math
import secrets
from pathlib import Path
from typing import Literal

Kind = Literal["words", "characters"]

WORD_LIST = Path(__file__).resolve().with_name("eff_large_wordlist.txt")
WORD_LIST_SHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
WORD_COUNT = 7776
DEFAULT_WORDS = 7
SEPARATOR = "-"

#: No 0/O or 1/I/L, so a generated passphrase survives being copied by hand.
ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
DEFAULT_GROUPS = 6
GROUP_SIZE = 5


@functools.cache
def words() -> tuple[str, ...]:
    """The word list, after checking that it's exactly the one this app was released with."""
    data = WORD_LIST.read_bytes()
    if hashlib.sha256(data).hexdigest() != WORD_LIST_SHA256:
        raise RuntimeError("The word list in this app's folder isn't the one it came with, so it wasn't used. "
                           "Reinstall the app to fix this.")
    found = tuple(line.split("\t", 1)[1] for line in data.decode("ascii").splitlines() if line)
    if len(found) != WORD_COUNT or len(set(found)) != WORD_COUNT:
        raise RuntimeError("The word list isn't complete, so it wasn't used.")
    return found


def word_passphrase(count: int = DEFAULT_WORDS) -> str:
    if count < 1:
        raise ValueError("A passphrase needs at least one word.")
    chosen = words()
    return SEPARATOR.join(secrets.choice(chosen) for _ in range(count))


def character_passphrase(groups: int = DEFAULT_GROUPS) -> str:
    if groups < 1:
        raise ValueError("A passphrase needs at least one group.")
    return "-".join("".join(secrets.choice(ALPHABET) for _ in range(GROUP_SIZE)) for _ in range(groups))


def generate(kind: Kind) -> str:
    return word_passphrase() if kind == "words" else character_passphrase()


def bits(kind: Kind, count: int | None = None) -> float:
    """How many bits of randomness a generated passphrase holds: log2 of how many there could be."""
    if kind == "words":
        return (count or DEFAULT_WORDS) * math.log2(WORD_COUNT)
    return (count or DEFAULT_GROUPS) * GROUP_SIZE * math.log2(len(ALPHABET))


def describe(kind: Kind, count: int | None = None) -> str:
    """What a generated passphrase's strength means, in plain words."""
    strength = bits(kind, count)
    if kind == "words":
        what = f"{count or DEFAULT_WORDS} random words"
        why = "Easy to type and to read out."
    else:
        what = f"{(count or DEFAULT_GROUPS) * GROUP_SIZE} random letters and digits"
        why = "Hard to type, but even stronger."
    return (f"{what}, picked by your computer: about {strength:.0f} bits, or {_power_of_ten(strength)} possible "
            f"passphrases. Far beyond what anyone can guess, however fast their computers. {why}")


def _power_of_ten(strength: float) -> str:
    """Such as 10²⁷, which is how many passphrases 90 bits allows, give or take."""
    exponent = str(math.floor(strength * math.log10(2)))
    return "10" + exponent.translate(str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹"))
