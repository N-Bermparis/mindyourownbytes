"""How guessable a new passphrase is, judged on this computer and nowhere else.

Nothing typed is sent anywhere, logged, or written down: this module only looks at a string in memory
and returns a level and a sentence, never the passphrase or any part of it.

* **Weak** means common or easily guessed: one of the passphrases people use most, one ordinary word
  with digits or symbols added, two ordinary words, a run of keys such as "qwerty" or "12345678", the
  same few characters repeated, or only digits, such as a date or a phone number. Anyone guessing starts
  with exactly these, and no setting can make up for that, so a weak passphrase isn't accepted for new
  files or a new vault.
* **Better** means none of that was found, but a person chose it. People's choices are easier to guess
  than they look, and no check can measure how much easier, so no number is claimed for them.
* **Strong** is only for a passphrase the computer picked at random. Only then is its strength known
  exactly: see ``generator``.

Only new passphrases are judged. A passphrase typed to open something is never refused for being weak,
so everything protected before this check existed still opens.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import cache
from typing import Literal

Level = Literal["weak", "fair", "strong"]

#: The shortest new passphrase for files. The vault's master has its own, longer minimum.
MIN_LENGTH = 8
#: Below this, a passphrase that passes every check still gets a warning that it's short.
RECOMMENDED_LENGTH = 14

#: Passphrases that top every published list of leaked passwords, and phrases made famous as examples.
#: Compared after folding case and width, and without spaces. Short on purpose: the patterns below catch
#: most of what a longer list would.
# A block of words is easier to review than hundreds of quoted strings.
_COMMON = frozenset("""
123456 1234567 12345678 123456789 1234567890 0123456789 987654321 0987654321 111111 1111111 11111111
000000 00000000 121212 123123 123321 654321 666666 696969 777777 7777777 112233 159753 147258369
password password1 password12 password123 password1234 passw0rd p@ssw0rd p@ssword passwort motdepasse
contraseña contrasena senha parola wachtwoord haslo qwerty qwerty1 qwerty12 qwerty123 qwertyuiop
qwertyui qwertz qwertzuiop azerty azertyuiop asdfgh asdfghjkl asdf1234 zxcvbn zxcvbnm 1q2w3e4r
1q2w3e4r5t 1q2w3e4r5t6y q1w2e3r4 q1w2e3r4t5 1qaz2wsx 1qaz2wsx3edc zaq12wsx qazwsx qazwsxedc qwe123
abc123 abcd1234 abc12345 a1b2c3d4 aa123456 iloveyou iloveyou1 iloveu loveyou letmein letmein1 welcome
welcome1 welcome123 admin admin123 administrator root toor login guest default changeme secret
secret123 trustno1 whatever starwars superman batman spiderman pokemon minecraft fortnite naruto
dragon monkey shadow master sunshine princess football baseball soccer hockey basketball michael
jordan jordan23 jennifer hunter buster harley tigger charlie robert thomas daniel andrew joshua
matthew ashley jessica michelle nicole amanda summer winter freedom ginger pepper cheese cookie
chocolate banana orange apple flower butterfly purple angel blessed jesus jesus1 hello hello123
computer internet samsung google facebook microsoft windows linkedin twitter youtube liverpool
chelsea arsenal barcelona realmadrid juventus manchester yankees dallas austin thunder taylor matrix
killer mustang ranger klaster maggie biteme access lovely loveme hottie zaq1zaq1 mypassword passpass
mindyourownbytes correcthorsebatterystaple tr0ub4dor&3 troubador iloveyou123 qwerty1234 asdfasdf
asdasdasd zxczxczxc 11223344 12344321 aaaaaa abcdef abcdefg abcdefgh 123abc 1234abcd
""".split())  # noqa: SIM905

#: Ordinary words beyond EFF's list, which people build passphrases from.
_WORDS = frozenset("""
love life home family friend friends money happy lucky secret private personal backup files docs
documents photos music work office school house garden summer winter spring autumn baby mother father
sister brother daughter son wife husband name birthday welcome hello goodbye please thanks sorry
the and for you your my me mine our this that what with from have just like time year day night
horse dog cat bird fish lion tiger bear wolf fox eagle dragon monkey rabbit mouse snake cow pig sheep goat
red blue green yellow black white pink gray grey gold silver brown purple orange sun moon star sky sea
water fire earth wind rain snow storm river lake mountain forest tree flower rose beach island city
car bike train plane boat road street king queen prince princess god angel devil hero magic dream
heart soul mind body hand eye blood light dark power coffee pizza beer wine chocolate cookie
apple banana orange cherry lemon game player football soccer tennis golf guitar piano phone computer
""".split())  # noqa: SIM905

_LINE_BREAKS = "\n\r\0"
#: Digits, spaces, and punctuation, which people add around a word to meet a password rule.
_SYMBOLS = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~€£¥§°"
_DECORATION = "0123456789" + _SYMBOLS
_SEPARATORS = re.compile(r"[\s\-_.,;:+/\\|·•]+")
_LEET_I = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
                         "@": "a", "$": "s", "!": "i", "|": "l", "+": "t", "€": "e"})
_LEET_L = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
                         "@": "a", "$": "s", "!": "l", "|": "l", "+": "t", "€": "e"})
#: Rows of letters and keys that people type in order, forwards or backwards.
_SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm",
              "qwertzuiop", "yxcvbnm", "azertyuiop", "qsdfghjklm", "wxcvbn")


@dataclass(frozen=True)
class Assessment:
    level: Level
    #: One plain sentence saying why. Never contains the passphrase.
    message: str

    @property
    def acceptable(self) -> bool:
        """Whether it may protect new files or a new vault."""
        return self.level != "weak"


class WeakPassphrase(ValueError):
    """A new passphrase that's too easy to guess. The message is safe to show the user."""


@cache
def _words() -> frozenset[str]:
    from mindyourownbytes import generator
    try:
        eff = frozenset(generator.words())
    except (OSError, RuntimeError):
        eff = frozenset()  # The generator reports a damaged list itself. The checks still work without it.
    return eff | _COMMON | _WORDS


def _fold(text: str) -> str:
    """Compare like a guesser would: case, accents' encoding, and full-width forms don't matter."""
    return unicodedata.normalize("NFKC", text).casefold().strip()


def _variants(folded: str) -> set[str]:
    """The passphrase without separators, without decoration at either end, and with leetspeak undone.

    Symbols are stripped from the ends both with and without digits, since a digit at the end may be
    leetspeak ("3l3phant!" is "elephant") or decoration ("elephant3").
    """
    compact = _SEPARATORS.sub("", folded)
    bases = {folded, compact, compact.strip(_DECORATION), compact.strip(_SYMBOLS)}
    found = set(bases)
    for value in bases:
        for table in (_LEET_I, _LEET_L):
            undone = value.translate(table)
            found |= {undone, undone.strip(_DECORATION)}
    return {value for value in found if value}


def _adjacent(first: str, second: str, step: int) -> bool:
    for sequence in _SEQUENCES:
        index = sequence.find(first)
        if index >= 0 and 0 <= index + step < len(sequence) and sequence[index + step] == second:
            return True
    return False


def _run_coverage(text: str) -> float:
    """How much of ``text`` is in runs of three or more keys or characters in order, such as "abc" or "4321"."""
    if len(text) < 3:
        return 0.0
    covered = [False] * len(text)
    for step in (1, -1):
        start = 0
        for index in range(1, len(text) + 1):
            if index < len(text) and _adjacent(text[index - 1], text[index], step):
                continue
            if index - start >= 3:
                covered[start:index] = [True] * (index - start)
            start = index
    return sum(covered) / len(text)


def _period(text: str) -> int:
    """The length of the shortest part that ``text`` repeats, or its whole length if it doesn't."""
    for length in range(1, len(text) // 2 + 1):
        if (text[:length] * (len(text) // length + 1))[:len(text)] == text:
            return length
    return len(text)


def _weakness(passphrase: str, min_length: int) -> str | None:
    """Why a passphrase someone chose is easily guessed, or None if nothing obvious was found."""
    if len(passphrase) < min_length:
        return f"Use at least {min_length} characters."
    folded = _fold(passphrase)
    compact = _SEPARATORS.sub("", folded)
    variants = _variants(folded)
    if folded in _COMMON or compact in _COMMON:
        return "Weak: this is one of the passphrases people use most, so it's among the first anyone tries."
    if variants & _COMMON:
        return ("Weak: this is a common password with a few characters changed or added, which is among the "
                "first things anyone tries.")
    if variants & _words():
        return "Weak: one ordinary word, even with numbers or symbols added, is among the first things anyone tries."
    if len(set(compact)) < 4:
        return "Weak: it uses only a few different characters, so it's easy to guess."
    period = _period(compact)
    if period < len(compact) and _weakness(compact[:period], min_length) is not None:
        return "Weak: it repeats a short part, so it's only as strong as that part."
    digits = sum(character.isdigit() for character in compact)
    if digits == len(compact) and digits < 16:
        return "Weak: only digits, such as a date or a phone number, are easy to guess."
    if _run_coverage(compact) >= 0.8:
        return "Weak: it's mostly keys or characters in order, such as qwerty or 1234, which are easy to guess."
    core = compact.strip(_DECORATION)
    if core != compact and core.isalpha() and len(core) < MIN_LENGTH:
        # Such as a name and a year. No list holds every name, but guessers try short words dressed up.
        return ("Weak: one short word or name, with numbers or symbols added, is among the first things anyone "
                "tries.")
    tokens = [token.strip(_DECORATION) for token in _SEPARATORS.split(folded)]
    tokens = [token for token in tokens if token]
    # Two words are guessed by pairing words from lists. Known words for certain, and any two short ones,
    # since no list here holds every word in every language.
    if 1 < len(tokens) <= 2 and (all(token in _words() for token in tokens)
                                 or (all(token.isalpha() for token in tokens) and len(compact) < RECOMMENDED_LENGTH)):
        return "Weak: two ordinary words are easy to guess. Use five or more, picked at random."
    return None


def assess(passphrase: str, *, min_length: int = MIN_LENGTH, generated: bool = False) -> Assessment:
    """How guessable a new passphrase is. ``generated`` means the app picked it and it hasn't been changed."""
    if not passphrase:
        return Assessment("weak", "")
    if any(character in _LINE_BREAKS for character in passphrase):
        return Assessment("weak", "Passphrases cannot contain line breaks or NUL characters.")
    if any(unicodedata.category(character) == "Cc" for character in passphrase):
        return Assessment("weak", "This contains a control character, which can't be typed reliably on "
                                  "another computer.")
    if generated:
        return Assessment("strong", "Strong: picked at random by your computer.")
    problem = _weakness(passphrase, min_length)
    if problem is not None:
        return Assessment("weak", problem)
    if len(passphrase) < RECOMMENDED_LENGTH:
        message = ("Better, but short enough to be guessed. Five or more random words, or one your computer "
                   "picks, is far stronger.")
    else:
        message = ("Better: nothing common was found, but you chose it, and people's choices are easier to guess "
                   "than they look. One your computer picks is stronger.")
    if unicodedata.normalize("NFC", passphrase) != passphrase:
        message += (" Some of its letters can be typed in more than one way, so on another computer it might "
                    "not match.")
    return Assessment("fair", message)


def check_new(passphrase: str, *, min_length: int, generated: bool = False) -> None:
    """Refuse a new passphrase that's easily guessed, with a message that says why."""
    result = assess(passphrase, min_length=min_length, generated=generated)
    if not result.acceptable:
        raise WeakPassphrase(result.message or "Type a passphrase.")
