"""Text normalization that undoes common evasion tricks before detection.

Author: Chandu Komme

Attackers hide instructions with zero-width characters, look-alike letters,
leetspeak, letter spacing and encodings. ``views`` returns every readable
form of a text so that the rule engine can scan each one:

* ``original``  the text as received
* ``folded``    NFKC, invisible characters removed, look-alikes mapped to
                Latin, lowercased, whitespace collapsed
* ``unleet``    folded text with leetspeak digits and symbols mapped back
* ``despaced``  letter-by-letter spacing ("i g n o r e") joined up
* ``decoded``   base64, hex and rot13 payloads found in the text, decoded
"""

from __future__ import annotations

import base64
import binascii
import codecs
from dataclasses import dataclass
import re
import unicodedata

__author__ = "Chandu Komme"

INVISIBLE = dict.fromkeys(map(ord, "​‌‍‎‏⁠⁡⁢⁣⁤﻿­"), None)

# Cyrillic and Greek letters that render like Latin ones.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ս": "u", "ν": "v", "ο": "o",
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "ρ": "p", "χ": "x",
    "А": "a", "Е": "e", "О": "o", "Р": "p", "С": "c", "Х": "x", "І": "i", "Ѕ": "s",
})

LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})

_SPACE = re.compile(r"\s+")
_SPACED_LETTERS = re.compile(r"\b(?:[a-z][ .\-_*]){3,}[a-z]\b")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_ROT13_HINT = re.compile(r"rot-?13", re.I)


@dataclass(frozen=True)
class View:
    name: str
    text: str


def fold(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(INVISIBLE).translate(CONFUSABLES)
    return _SPACE.sub(" ", text.lower()).strip()


def _printable(data: bytes) -> str | None:
    try:
        decoded = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded or sum(ch.isprintable() or ch.isspace() for ch in decoded) / len(decoded) < 0.95:
        return None
    letters = sum(ch.isalpha() for ch in decoded)
    return decoded if letters >= 6 else None


def decode_payloads(text: str) -> list[str]:
    """Decode base64, hex and rot13 segments that turn into readable text."""
    found: list[str] = []
    for token in _BASE64.findall(text):
        padded = token + "=" * (-len(token) % 4)
        try:
            readable = _printable(base64.b64decode(padded, validate=True))
        except (binascii.Error, ValueError):
            readable = None
        if readable:
            found.append(readable)
    for token in _HEX.findall(text):
        readable = _printable(bytes.fromhex(token))
        if readable:
            found.append(readable)
    if _ROT13_HINT.search(text):
        found.append(codecs.decode(text, "rot13"))
    return found


def views(text: str) -> list[View]:
    folded = fold(text)
    result = [View("original", text), View("folded", folded)]
    unleet = folded.translate(LEET)
    if unleet != folded:
        result.append(View("unleet", unleet))
    despaced = _SPACED_LETTERS.sub(lambda m: re.sub(r"[ .\-_*]", "", m.group(0)), folded)
    if despaced != folded:
        result.append(View("despaced", despaced))
    for index, payload in enumerate(decode_payloads(text)):
        result.append(View(f"decoded[{index}]", fold(payload)))
    return result
