"""Homoglyph (look-alike letter) folding for DETECTION only.

Attackers swap Latin letters for identical-looking Cyrillic/Greek ones
("Іgnоrе" = Latin I-g-n-r + Cyrillic о, е) so regexes and n-gram features see
different characters. NFKC does not fold these: they are different letters,
not compatibility variants.

We fold only *mixed-script* words - a word that contains both Latin and
Cyrillic/Greek letters. Real Russian or Greek text is all one script per word
and is left untouched, and the folded text is never shown to the LLM: it is
used for matching only. The map covers the common look-alikes; Unicode TR39's
confusables.txt is the complete source if more coverage is needed.
"""
from __future__ import annotations

import re

_TO_LATIN = {
    # Cyrillic lower
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "к": "k", "т": "t", "м": "m",
    "н": "h", "в": "b",
    # Cyrillic upper
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    # Greek lower
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i",
    "κ": "k", "υ": "u", "τ": "t",
    # Greek upper
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}
_FOLD = str.maketrans(_TO_LATIN)

_WORD = re.compile(r"[^\W\d_]+")
_LATIN = re.compile(r"[A-Za-zÀ-ɏ]")
_CYR_GREEK = re.compile(r"[Ͱ-ϿЀ-ԯ]")


def _is_mixed(word: str) -> bool:
    return bool(_LATIN.search(word)) and bool(_CYR_GREEK.search(word))


def fold_mixed_script(text: str) -> tuple[str, int]:
    """Return (text with mixed-script words folded to Latin, number of such words)."""
    count = 0

    def sub(m: re.Match) -> str:
        nonlocal count
        w = m.group(0)
        if _is_mixed(w):
            count += 1
            return w.translate(_FOLD)
        return w

    return _WORD.sub(sub, text), count